"""Utility functions for the LAN Packet Cracker tool."""

import os
import sys
import platform
import subprocess


# Terminal colors
class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


def print_banner():
    """Print the tool banner."""
    banner = f"""{Colors.CYAN}{Colors.BOLD}
  _     _   _  _   ___         _           ___             _
 | |   /_\\ | \\| | | _ \\__ _ __| |_____ ___/ __|_ _ __ _ __| |_____ _ _
 | |__/ _ \\| .` | |  _/ _` / _| / / -_)___|  _| '_/ _` / _| / / -_) '_|
 |____/_/ \\_\\_|\\_| |_| \\__,_\\__|_\\_\\_____|  |___|_| \\__,_\\__|_\\_\\___|_|
{Colors.RESET}
{Colors.YELLOW}  WPA/WPA2 Handshake Capture & Cracking Tool{Colors.RESET}
{Colors.RED}  For educational and authorized testing purposes only.{Colors.RESET}
"""
    print(banner)


def print_disclaimer():
    """Print legal disclaimer."""
    print(f"{Colors.RED}{Colors.BOLD}")
    print("=" * 60)
    print(" DISCLAIMER")
    print("=" * 60)
    print(f"{Colors.RESET}{Colors.RED}")
    print(" This tool is intended for educational purposes and")
    print(" authorized security testing ONLY.")
    print()
    print(" Unauthorized access to computer networks is illegal.")
    print(" Use this tool only on networks you own or have")
    print(" explicit written permission to test.")
    print()
    print(" The author assumes no liability for misuse.")
    print(f"{'=' * 60}{Colors.RESET}")
    print()


def check_root():
    """Check if the script is running with root/admin privileges."""
    if platform.system() == "Windows":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    else:
        return os.geteuid() == 0


def require_root():
    """Exit if not running as root."""
    if not check_root():
        print(f"{Colors.RED}[!] This tool requires root/administrator privileges.{Colors.RESET}")
        print(f"{Colors.YELLOW}[*] Run with: sudo python main.py{Colors.RESET}")
        sys.exit(1)


def get_platform():
    """Return the current platform."""
    return platform.system().lower()


def get_wireless_interfaces():
    """List available wireless interfaces."""
    interfaces = []
    plat = get_platform()

    if plat == "linux":
        try:
            result = subprocess.run(
                ["iw", "dev"],
                capture_output=True, text=True, timeout=10
            )
            current_iface = None
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.startswith("Interface"):
                    current_iface = line.split()[-1]
                    interfaces.append(current_iface)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            # Fallback: read /proc/net/wireless
            try:
                with open("/proc/net/wireless", "r") as f:
                    for line in f.readlines()[2:]:
                        iface = line.split(":")[0].strip()
                        if iface:
                            interfaces.append(iface)
            except FileNotFoundError:
                pass

    elif plat == "darwin":
        try:
            result = subprocess.run(
                ["networksetup", "-listallhardwareports"],
                capture_output=True, text=True, timeout=10
            )
            lines = result.stdout.splitlines()
            for i, line in enumerate(lines):
                if "Wi-Fi" in line or "AirPort" in line:
                    for j in range(i + 1, min(i + 3, len(lines))):
                        if lines[j].startswith("Device:"):
                            interfaces.append(lines[j].split()[-1])
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    return interfaces


def set_channel(interface, channel):
    """Set the wireless interface to a specific channel."""
    plat = get_platform()
    if plat == "linux":
        subprocess.run(
            ["iwconfig", interface, "channel", str(channel)],
            capture_output=True, timeout=5
        )
    elif plat == "darwin":
        subprocess.run(
            ["airport", "-c", str(channel)],
            capture_output=True, timeout=5
        )


def print_status(msg):
    print(f"{Colors.BLUE}[*]{Colors.RESET} {msg}")


def print_success(msg):
    print(f"{Colors.GREEN}[+]{Colors.RESET} {msg}")


def print_error(msg):
    print(f"{Colors.RED}[-]{Colors.RESET} {msg}")


def print_warning(msg):
    print(f"{Colors.YELLOW}[!]{Colors.RESET} {msg}")


def print_info(msg):
    print(f"{Colors.CYAN}[i]{Colors.RESET} {msg}")
