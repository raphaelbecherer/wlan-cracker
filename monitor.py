"""Monitor mode management for wireless interfaces."""

import subprocess
import time
import threading

from config import AIRMON_BIN, CHANNELS_24GHZ, CHANNELS_5GHZ, CHANNELS_ALL, CHANNEL_HOP_INTERVAL
from utils import (
    get_platform, get_wireless_interfaces, set_channel,
    print_status, print_success, print_error, print_warning
)


class MonitorMode:
    """Manages enabling/disabling monitor mode on wireless interfaces."""

    def __init__(self, interface=None):
        self.interface = interface
        self.original_interface = interface
        self.monitor_interface = None
        self._channel_hopper = None
        self._hop_stop = threading.Event()

    def find_interface(self):
        """Auto-detect a wireless interface if none specified."""
        if self.interface:
            return self.interface

        interfaces = get_wireless_interfaces()
        if not interfaces:
            print_error("No wireless interfaces found.")
            return None

        print_status(f"Found wireless interfaces: {', '.join(interfaces)}")
        self.interface = interfaces[0]
        self.original_interface = self.interface
        print_status(f"Using interface: {self.interface}")
        return self.interface

    def enable(self):
        """Enable monitor mode on the interface."""
        if not self.find_interface():
            return None

        plat = get_platform()

        if plat == "linux":
            return self._enable_linux()
        elif plat == "darwin":
            print_warning("macOS has limited monitor mode support.")
            print_warning("Consider using a Linux system for full functionality.")
            return self._enable_macos()
        else:
            print_error(f"Monitor mode not supported on {plat}.")
            return None

    def _enable_linux(self):
        """Enable monitor mode on Linux."""
        # Kill interfering processes
        if AIRMON_BIN:
            print_status("Killing interfering processes...")
            subprocess.run(
                [AIRMON_BIN, "check", "kill"],
                capture_output=True, timeout=10
            )

        # Try airmon-ng first
        if AIRMON_BIN:
            print_status(f"Enabling monitor mode on {self.interface} via airmon-ng...")
            result = subprocess.run(
                [AIRMON_BIN, "start", self.interface],
                capture_output=True, text=True, timeout=15
            )

            # airmon-ng may rename the interface (e.g., wlan0 -> wlan0mon)
            for suffix in ["mon", ""]:
                candidate = f"{self.interface}{suffix}"
                check = subprocess.run(
                    ["iwconfig", candidate],
                    capture_output=True, text=True, timeout=5
                )
                if "Mode:Monitor" in check.stdout:
                    self.monitor_interface = candidate
                    # Allow kernel to fully initialize the new interface
                    time.sleep(2)
                    print_success(f"Monitor mode enabled: {self.monitor_interface}")
                    return self.monitor_interface

        # Fallback: manual method with ip/iwconfig
        print_status("Trying manual monitor mode setup...")
        try:
            subprocess.run(
                ["ip", "link", "set", self.interface, "down"],
                capture_output=True, timeout=5
            )
            subprocess.run(
                ["iwconfig", self.interface, "mode", "monitor"],
                capture_output=True, timeout=5
            )
            subprocess.run(
                ["ip", "link", "set", self.interface, "up"],
                capture_output=True, timeout=5
            )

            # Verify
            check = subprocess.run(
                ["iwconfig", self.interface],
                capture_output=True, text=True, timeout=5
            )
            if "Mode:Monitor" in check.stdout:
                self.monitor_interface = self.interface
                time.sleep(2)
                print_success(f"Monitor mode enabled: {self.monitor_interface}")
                return self.monitor_interface
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        print_error("Failed to enable monitor mode.")
        return None

    def _enable_macos(self):
        """Enable monitor mode on macOS (limited support)."""
        try:
            # macOS uses the airport utility
            subprocess.run(
                ["sudo", "airport", self.interface, "sniff"],
                capture_output=True, timeout=5
            )
            self.monitor_interface = self.interface
            return self.monitor_interface
        except (subprocess.TimeoutExpired, FileNotFoundError):
            print_error("Failed to enable monitor mode on macOS.")
            return None

    def disable(self):
        """Disable monitor mode and restore managed mode."""
        self.stop_channel_hop()

        if not self.monitor_interface:
            return

        plat = get_platform()
        print_status(f"Restoring managed mode on {self.monitor_interface}...")

        if plat == "linux":
            if AIRMON_BIN:
                subprocess.run(
                    [AIRMON_BIN, "stop", self.monitor_interface],
                    capture_output=True, timeout=10
                )
            else:
                subprocess.run(
                    ["ip", "link", "set", self.monitor_interface, "down"],
                    capture_output=True, timeout=5
                )
                subprocess.run(
                    ["iwconfig", self.monitor_interface, "mode", "managed"],
                    capture_output=True, timeout=5
                )
                subprocess.run(
                    ["ip", "link", "set", self.monitor_interface, "up"],
                    capture_output=True, timeout=5
                )

            # Restart NetworkManager if available
            subprocess.run(
                ["systemctl", "start", "NetworkManager"],
                capture_output=True, timeout=10
            )

        print_success("Managed mode restored.")
        self.monitor_interface = None

    def start_channel_hop(self, channels=None, band="all"):
        """Start channel hopping in a background thread.

        Args:
            channels: Explicit list of channels. Overrides band if provided.
            band: Channel band - "2.4", "5", or "all" (default).
        """
        if not self.monitor_interface:
            print_error("Monitor mode not enabled.")
            return

        if channels is None:
            if band == "5":
                channels = CHANNELS_5GHZ
            elif band == "2.4":
                channels = CHANNELS_24GHZ
            else:
                channels = CHANNELS_ALL

        self._hop_stop.clear()

        def _hop():
            idx = 0
            while not self._hop_stop.is_set():
                ch = channels[idx % len(channels)]
                set_channel(self.monitor_interface, ch)
                idx += 1
                self._hop_stop.wait(CHANNEL_HOP_INTERVAL)

        self._channel_hopper = threading.Thread(target=_hop, daemon=True)
        self._channel_hopper.start()
        band_label = {"2.4": "2.4 GHz", "5": "5 GHz", "all": "2.4 + 5 GHz"}.get(band, "custom")
        print_status(f"Channel hopping started ({band_label}, {len(channels)} channels).")

    def stop_channel_hop(self):
        """Stop channel hopping."""
        self._hop_stop.set()
        if self._channel_hopper and self._channel_hopper.is_alive():
            self._channel_hopper.join(timeout=2)
        self._channel_hopper = None

    def set_channel(self, channel):
        """Set a specific channel on the monitor interface."""
        if self.monitor_interface:
            set_channel(self.monitor_interface, channel)
            time.sleep(0.5)
            print_status(f"Set channel to {channel}")
