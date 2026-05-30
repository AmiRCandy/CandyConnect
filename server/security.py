"""
CandyConnect - Security helpers (validation, safe execution, rate limiting).
"""
from __future__ import annotations

import asyncio
import re
import shlex
import subprocess
import time
from collections import defaultdict
from typing import Optional

from fastapi import HTTPException, Request

# VPN usernames are used in shell-adjacent tooling — strict charset only.
VPN_USERNAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,31}$")

# Linux interface names (for bind_interface validation).
IFACE_RE = re.compile(r"^[a-zA-Z0-9_.-]{1,15}$")

# Allowed iptables fragments for WireGuard PostUp/PostDown (no shell metacharacters).
IPTABLES_SAFE_RE = re.compile(
    r"^(iptables|ip6tables)(\s+-[a-zA-Z0-9=/_%.]+|\s+%i|\s+--[a-z-]+|\s+\d+|\s+[a-zA-Z0-9_.:/-]+)*"
    r"(;\s*(iptables|ip6tables)(\s+-[a-zA-Z0-9=/_%.]+|\s+%i|\s+--[a-z-]+|\s+\d+|\s+[a-zA-Z0-9_.:/-]+)*)*$"
)

SHELL_METACHAR_RE = re.compile(r"[;|&`$<>\\'\n\r]")


def validate_vpn_username(username: str) -> str:
    username = (username or "").strip()
    if not VPN_USERNAME_RE.match(username):
        raise HTTPException(
            status_code=400,
            detail=(
                "Invalid username: use 1-32 chars, start with letter/digit, "
                "only letters, digits, underscore and hyphen"
            ),
        )
    return username


def validate_bind_interface(name: str) -> str:
    name = (name or "").strip()
    if name and not IFACE_RE.match(name):
        raise HTTPException(status_code=400, detail="Invalid network interface name")
    return name


def assert_safe_wireguard_hook(command: str, field_name: str) -> str:
    command = (command or "").strip()
    if not command:
        return ""
    if SHELL_METACHAR_RE.search(command):
        raise ValueError(f"{field_name} contains disallowed shell characters")
    if not IPTABLES_SAFE_RE.match(command):
        raise ValueError(f"{field_name} must be iptables/ip6tables rules only")
    return command


def validate_wireguard_hook(command: str, field_name: str) -> str:
    try:
        return assert_safe_wireguard_hook(command, field_name)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def sanitize_wireguard_config(data: dict) -> dict:
    out = dict(data)
    if "bind_interface" in out:
        out["bind_interface"] = validate_bind_interface(str(out.get("bind_interface", "")))
    if "post_up" in out:
        out["post_up"] = validate_wireguard_hook(str(out.get("post_up", "")), "post_up")
    if "post_down" in out:
        out["post_down"] = validate_wireguard_hook(str(out.get("post_down", "")), "post_down")
    return out


def validate_traffic_bytes(value: float, field_name: str = "bytes") -> float:
    if value is None:
        return 0.0
    try:
        num = float(value)
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail=f"Invalid {field_name}")
    if num < 0:
        raise HTTPException(status_code=400, detail=f"{field_name} cannot be negative")
    # Cap single report to 1 TiB to prevent abuse / overflow tricks.
    if num > 1024 ** 4:
        raise HTTPException(status_code=400, detail=f"{field_name} exceeds maximum allowed value")
    return num


async def run_cmd(
    cmd: list[str] | str,
    *,
    shell: bool = False,
    check: bool = True,
    timeout: int = 30,
    cwd: Optional[str] = None,
    input_text: Optional[str] = None,
) -> tuple[int, str, str]:
    """Run a subprocess without shell unless explicitly requested."""
    try:
        if shell:
            proc = await asyncio.create_subprocess_shell(
                cmd if isinstance(cmd, str) else " ".join(shlex.quote(c) for c in cmd),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
            )
        else:
            if isinstance(cmd, str):
                raise ValueError("Pass argv list when shell=False")
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
                stdin=asyncio.subprocess.PIPE if input_text is not None else None,
            )
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(input_text.encode("utf-8") if input_text is not None else None),
            timeout=timeout,
        )
        out = stdout.decode("utf-8", errors="replace").strip()
        err = stderr.decode("utf-8", errors="replace").strip()
        if check and proc.returncode != 0:
            return proc.returncode or 1, out, err
        return proc.returncode or 0, out, err
    except asyncio.TimeoutError:
        return -1, "", f"Command timed out after {timeout}s"


def chpasswd_entry(username: str, password: str) -> tuple[int, str, str]:
    """Set password via chpasswd stdin (no shell interpolation)."""
    base = username[6:] if username.startswith("dnstt_") else username
    validate_vpn_username(base)
    proc = subprocess.run(
        ["sudo", "chpasswd"],
        input=f"{username}:{password}\n",
        capture_output=True,
        text=True,
        timeout=15,
    )
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()


async def append_line_to_root_file(path: str, line: str) -> bool:
    """Append a single line to a root-owned file without shell-interpolating content."""
    import os
    import tempfile

    tmp_path = ""
    try:
        with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as tmp:
            tmp.write(line if line.endswith("\n") else f"{line}\n")
            tmp_path = tmp.name
        rc, _, _ = await run_cmd(
            f"sudo tee -a {shlex.quote(path)} < {shlex.quote(tmp_path)} > /dev/null",
            shell=True,
            check=False,
        )
        return rc == 0
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


class LoginRateLimiter:
    """Simple in-memory login rate limiter (per client IP)."""

    def __init__(self, max_attempts: int = 10, window_seconds: int = 300):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._attempts: dict[str, list[float]] = defaultdict(list)

    def _client_ip(self, request: Request) -> str:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
        if request.client:
            return request.client.host
        return "unknown"

    def check(self, request: Request, bucket: str) -> None:
        key = f"{bucket}:{self._client_ip(request)}"
        now = time.time()
        window_start = now - self.window_seconds
        self._attempts[key] = [t for t in self._attempts[key] if t >= window_start]
        if len(self._attempts[key]) >= self.max_attempts:
            raise HTTPException(
                status_code=429,
                detail="Too many login attempts. Try again later.",
            )

    def record_failure(self, request: Request, bucket: str) -> None:
        key = f"{bucket}:{self._client_ip(request)}"
        self._attempts[key].append(time.time())

    def reset(self, request: Request, bucket: str) -> None:
        key = f"{bucket}:{self._client_ip(request)}"
        self._attempts.pop(key, None)


login_rate_limiter = LoginRateLimiter()
