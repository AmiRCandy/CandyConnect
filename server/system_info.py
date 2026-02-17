"""
CandyConnect Server - System Information Collector
"""
import platform, socket, asyncio
import psutil
import time


async def get_public_ip() -> str:
    """Get the public IP of the server with multiple fallbacks."""
    # Attempt to get public IP via external services
    services = [
        "curl -4 -s --connect-timeout 2 ifconfig.me",
        "curl -4 -s --connect-timeout 2 api.ipify.org",
        "curl -4 -s --connect-timeout 2 icanhazip.com",
    ]
    
    for cmd in services:
        try:
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=3)
            ip = stdout.decode().strip()
            if ip and len(ip.split('.')) == 4:
                return ip
        except Exception:
            continue
            
    # Fallback to local interface IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


async def get_server_info() -> dict:
    """Collect real server information using psutil."""
    # CPU
    cpu_model = "Unknown"
    try:
        with open("/proc/cpuinfo", "r") as f:
            for line in f:
                if line.startswith("model name"):
                    cpu_model = line.split(":")[1].strip()
                    break
    except Exception:
        cpu_model = platform.processor() or "Unknown"

    cpu_count = psutil.cpu_count(logical=True) or 1
    cpu_usage = psutil.cpu_percent(interval=0.5)

    # Memory
    mem = psutil.virtual_memory()
    ram_total = mem.total // (1024 * 1024)  # MB
    ram_used = mem.used // (1024 * 1024)

    # Disk
    disk = psutil.disk_usage("/")
    disk_total = disk.total // (1024 ** 3)  # GB
    disk_used = disk.used // (1024 ** 3)

    # Network
    net = psutil.net_io_counters()
    total_in = net.bytes_recv / (1024 ** 3)   # GB
    total_out = net.bytes_sent / (1024 ** 3)

    # Speed estimation (delta over small interval)
    net1 = psutil.net_io_counters()
    await asyncio.sleep(0.5)
    net2 = psutil.net_io_counters()
    speed_in = ((net2.bytes_recv - net1.bytes_recv) * 2 * 8) / (1024 * 1024)  # Mbps
    speed_out = ((net2.bytes_sent - net1.bytes_sent) * 2 * 8) / (1024 * 1024)

    # Hostname & IP
    hostname = socket.gethostname()
    ip = await get_public_ip()

    # OS / Kernel
    os_name = "Unknown"
    try:
        with open("/etc/os-release", "r") as f:
            for line in f:
                if line.startswith("PRETTY_NAME="):
                    os_name = line.split("=", 1)[1].strip().strip('"')
                    break
    except Exception:
        os_name = f"{platform.system()} {platform.release()}"

    kernel = platform.release()

    # Uptime
    boot_time = int(psutil.boot_time())
    uptime_secs = int(time.time() - boot_time)

    return {
        "hostname": hostname,
        "ip": ip,
        "os": os_name,
        "kernel": kernel,
        "uptime": uptime_secs,
        "cpu": {
            "model": cpu_model,
            "cores": cpu_count,
            "usage": round(cpu_usage, 1),
        },
        "ram": {
            "total": ram_total,
            "used": ram_used,
        },
        "disk": {
            "total": disk_total,
            "used": disk_used,
        },
        "network": {
            "total_in": round(total_in, 1),
            "total_out": round(total_out, 1),
            "speed_in": round(speed_in, 1),
            "speed_out": round(speed_out, 1),
        },
    }
