#!/usr/bin/env python3
"""Basic security regression checks for CandyConnect server modules."""
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SERVER = ROOT / "server"
sys.path.insert(0, str(SERVER))


def load(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, SERVER / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main() -> int:
    security = load("security", "security.py")

    try:
        security.validate_vpn_username("valid_user-1")
    except Exception as exc:
        print(f"FAIL valid username rejected: {exc}")
        return 1

    rejected = False
    try:
        security.validate_vpn_username("bad;id")
        rejected = True
    except Exception:
        pass
    if rejected:
        print("FAIL shell username accepted")
        return 1

    try:
        security.assert_safe_wireguard_hook(
            "iptables -A FORWARD -i %i -j ACCEPT; rm -rf /",
            "post_up",
        )
        print("FAIL malicious post_up accepted")
        return 1
    except ValueError:
        pass

    security.validate_traffic_bytes(100)
    try:
        security.validate_traffic_bytes(-1)
        print("FAIL negative traffic accepted")
        return 1
    except Exception:
        pass

    print("OK security regression checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
