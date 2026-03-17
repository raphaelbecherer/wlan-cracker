"""Configuration constants and defaults for the LAN Packet Cracker tool."""

import os
import shutil

# Directories
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CAPTURES_DIR = os.path.join(BASE_DIR, "captures")

# Ensure captures directory exists
os.makedirs(CAPTURES_DIR, exist_ok=True)

# Deauth settings
DEAUTH_COUNT = 50          # Number of deauth packets to send per burst
DEAUTH_INTERVAL = 0.05     # Seconds between deauth packets
DEAUTH_BURSTS = 5          # Number of deauth bursts

# Capture settings
HANDSHAKE_TIMEOUT = 60     # Seconds to wait for a handshake
SCAN_TIMEOUT = 30          # Seconds to scan for networks

# Channel hopping
CHANNEL_HOP_INTERVAL = 0.5  # Seconds between channel hops
CHANNELS_24GHZ = list(range(1, 14))  # 2.4 GHz channels 1-13

# 5 GHz channels (UNII-1, UNII-2, UNII-2 Extended, UNII-3)
CHANNELS_5GHZ = [
    # UNII-1 (indoor, no DFS)
    36, 40, 44, 48,
    # UNII-2 (DFS required in most countries)
    52, 56, 60, 64,
    # UNII-2 Extended (DFS required)
    100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
    # UNII-3 (no DFS)
    149, 153, 157, 161, 165,
]

# All channels combined (2.4 + 5 GHz)
CHANNELS_ALL = CHANNELS_24GHZ + CHANNELS_5GHZ

# Deauth evasion settings
DEAUTH_JITTER_MIN = 0.02   # Minimum random delay (seconds)
DEAUTH_JITTER_MAX = 0.15   # Maximum random delay (seconds)
DEAUTH_BURST_JITTER_MIN = 0.3   # Minimum delay between bursts
DEAUTH_BURST_JITTER_MAX = 2.0   # Maximum delay between bursts

# aircrack-ng binary detection
def find_aircrack_binary(name):
    """Find an aircrack-ng suite binary on the system."""
    path = shutil.which(name)
    if path:
        return path
    # Common install locations
    for prefix in ["/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin"]:
        candidate = os.path.join(prefix, name)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None

AIRCRACK_BIN = find_aircrack_binary("aircrack-ng")
AIRMON_BIN = find_aircrack_binary("airmon-ng")
AIREPLAY_BIN = find_aircrack_binary("aireplay-ng")
AIRODUMP_BIN = find_aircrack_binary("airodump-ng")

# Hashcat binary detection
def find_binary(name):
    """Find a binary on the system."""
    path = shutil.which(name)
    if path:
        return path
    for prefix in ["/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin"]:
        candidate = os.path.join(prefix, name)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None

HASHCAT_BIN = find_binary("hashcat")
HCXPCAPTOOL_BIN = find_binary("hcxpcapngtool") or find_binary("hcxpcaptool")
HCXDUMPTOOL_BIN = find_binary("hcxdumptool")

# WPS attack tools
REAVER_BIN = find_binary("reaver")
BULLY_BIN = find_binary("bully")
WASH_BIN = find_binary("wash")

# PMK precomputation tools
AIROLIB_BIN = find_binary("airolib-ng")
GENPMK_BIN = find_binary("genpmk")

# Evil Twin tools
HOSTAPD_BIN = find_binary("hostapd")
DNSMASQ_BIN = find_binary("dnsmasq")

# Hashcat mode for WPA/WPA2
HASHCAT_WPA_MODE = 22000  # hashcat mode for WPA-PBKDF2-PMKID+EAPOL (hc22000)

# PMKID settings
PMKID_TIMEOUT = 30  # Seconds to wait for PMKID capture

# Mutation rules
MUTATIONS_DIR = os.path.join(BASE_DIR, "rules")
os.makedirs(MUTATIONS_DIR, exist_ok=True)
