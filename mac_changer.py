"""MAC address randomization module - spoofs MAC to avoid detection.

Changing the MAC address of the wireless interface before an attack helps
avoid fingerprinting by IDS/WIDS systems that log MAC addresses. This module
supports full randomization, vendor-preserving randomization (keeps the first
3 bytes/OUI to look like a legitimate device), and restoring the original MAC.

Requirements:
- Linux: uses `ip link` or `macchanger` if available
- Must be done while interface is DOWN (handled automatically)
"""

import os
import re
import random
import subprocess

from utils import print_status, print_success, print_error, print_warning, print_info, Colors


# Common wireless adapter OUIs (vendor prefixes) for realistic spoofing
COMMON_WIFI_OUIS = [
    "00:1A:2B",  # Ayecom Technology
    "00:1C:BF",  # Intel
    "00:21:6A",  # Intel
    "00:24:D7",  # Intel
    "00:26:C6",  # Intel
    "3C:A9:F4",  # Intel
    "48:45:20",  # Intel
    "8C:88:2B",  # Samsung
    "AC:BC:32",  # Apple
    "D0:C5:F3",  # Apple
    "F4:F5:D8",  # Google
    "DC:A6:32",  # Raspberry Pi
    "B8:27:EB",  # Raspberry Pi
    "00:E0:4C",  # Realtek
    "48:5D:60",  # AzureWave (common USB adapters)
    "00:C0:CA",  # Alfa (popular pentesting adapters)
    "00:0F:00",  # Atheros
    "00:1B:B1",  # Qualcomm Atheros
    "EC:08:6B",  # TP-Link
    "50:C7:BF",  # TP-Link
]


def _random_mac_bytes(count=3):
    """Generate random MAC address bytes."""
    return ":".join(f"{random.randint(0x00, 0xFF):02x}" for _ in range(count))


def generate_random_mac(preserve_vendor=False, original_mac=None):
    """Generate a random MAC address.

    Args:
        preserve_vendor: Keep the OUI (first 3 bytes) from original_mac
                         or use a common WiFi OUI.
        original_mac: Original MAC address (used if preserve_vendor=True).

    Returns:
        str: New MAC address.
    """
    if preserve_vendor:
        if original_mac:
            oui = ":".join(original_mac.split(":")[:3])
        else:
            oui = random.choice(COMMON_WIFI_OUIS)
        suffix = _random_mac_bytes(3)
        mac = f"{oui}:{suffix}"
    else:
        # Use a common WiFi OUI to blend in, but randomize suffix
        oui = random.choice(COMMON_WIFI_OUIS)
        suffix = _random_mac_bytes(3)
        mac = f"{oui}:{suffix}"

    # Ensure unicast (clear multicast bit) and locally administered
    # Set bit 1 of first byte to 0 (unicast), bit 0 to 1 (locally administered)
    first_byte = int(mac.split(":")[0], 16)
    first_byte = (first_byte & 0xFC) | 0x02  # Clear multicast, set local bit
    mac = f"{first_byte:02x}:{':'.join(mac.split(':')[1:])}"

    return mac.lower()


def get_current_mac(interface):
    """Get the current MAC address of an interface.

    Args:
        interface: Network interface name.

    Returns:
        str: Current MAC address, or None.
    """
    try:
        result = subprocess.run(
            ["ip", "link", "show", interface],
            capture_output=True, text=True, timeout=5
        )
        match = re.search(r"link/ether\s+([0-9a-f:]{17})", result.stdout)
        if match:
            return match.group(1)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # Fallback: read from sysfs
    try:
        with open(f"/sys/class/net/{interface}/address", "r") as f:
            return f.read().strip()
    except (FileNotFoundError, PermissionError):
        pass

    return None


def change_mac(interface, new_mac=None, preserve_vendor=False):
    """Change the MAC address of a wireless interface.

    Args:
        interface: Network interface name.
        new_mac: Specific MAC to set. If None, generates a random one.
        preserve_vendor: Keep OUI prefix (only if new_mac is None).

    Returns:
        tuple: (original_mac, new_mac) on success, (None, None) on failure.
    """
    original_mac = get_current_mac(interface)
    if not original_mac:
        print_error(f"Could not read MAC address of {interface}")
        return None, None

    if not new_mac:
        new_mac = generate_random_mac(
            preserve_vendor=preserve_vendor,
            original_mac=original_mac
        )

    print_status(f"Changing MAC address of {interface}...")
    print_info(f"  Original: {original_mac}")
    print_info(f"  New:      {new_mac}")

    try:
        # Bring interface down
        subprocess.run(
            ["ip", "link", "set", interface, "down"],
            capture_output=True, timeout=5, check=True
        )

        # Try macchanger first (more reliable)
        macchanger = _find_macchanger()
        if macchanger:
            result = subprocess.run(
                [macchanger, "-m", new_mac, interface],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode != 0:
                # Fall back to ip link
                subprocess.run(
                    ["ip", "link", "set", interface, "address", new_mac],
                    capture_output=True, timeout=5, check=True
                )
        else:
            subprocess.run(
                ["ip", "link", "set", interface, "address", new_mac],
                capture_output=True, timeout=5, check=True
            )

        # Bring interface back up
        subprocess.run(
            ["ip", "link", "set", interface, "up"],
            capture_output=True, timeout=5, check=True
        )

        # Verify
        current = get_current_mac(interface)
        if current and current.lower() == new_mac.lower():
            print_success(f"MAC changed successfully: {new_mac}")
            return original_mac, new_mac
        else:
            print_warning(f"MAC change may not have applied. Current: {current}")
            return original_mac, current

    except subprocess.CalledProcessError as e:
        print_error(f"Failed to change MAC: {e}")
        # Try to restore
        subprocess.run(
            ["ip", "link", "set", interface, "up"],
            capture_output=True, timeout=5
        )
        return None, None
    except subprocess.TimeoutExpired:
        print_error("MAC change timed out.")
        return None, None


def restore_mac(interface, original_mac):
    """Restore the original MAC address.

    Args:
        interface: Network interface name.
        original_mac: MAC address to restore.

    Returns:
        bool: True if restored successfully.
    """
    if not original_mac:
        print_warning("No original MAC to restore.")
        return False

    print_status(f"Restoring original MAC on {interface}...")

    try:
        subprocess.run(
            ["ip", "link", "set", interface, "down"],
            capture_output=True, timeout=5
        )

        macchanger = _find_macchanger()
        if macchanger:
            subprocess.run(
                [macchanger, "-m", original_mac, interface],
                capture_output=True, timeout=10
            )
        else:
            subprocess.run(
                ["ip", "link", "set", interface, "address", original_mac],
                capture_output=True, timeout=5
            )

        subprocess.run(
            ["ip", "link", "set", interface, "up"],
            capture_output=True, timeout=5
        )

        current = get_current_mac(interface)
        if current and current.lower() == original_mac.lower():
            print_success(f"MAC restored: {original_mac}")
            return True
        else:
            print_warning(f"MAC restore may have failed. Current: {current}")
            return False

    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        print_error("Failed to restore MAC.")
        return False


def _find_macchanger():
    """Find macchanger binary."""
    import shutil
    return shutil.which("macchanger")


def print_mac_info(interface):
    """Print current MAC address info for an interface."""
    mac = get_current_mac(interface)
    if mac:
        oui = ":".join(mac.split(":")[:3]).upper()
        print_info(f"Interface: {interface}")
        print_info(f"MAC:       {mac}")
        print_info(f"OUI:       {oui}")
    else:
        print_warning(f"Could not read MAC for {interface}")
