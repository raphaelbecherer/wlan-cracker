"""Handshake validation module - verifies capture files before cracking.

Performs thorough checks on pcap files to determine if they contain
a valid, crackable WPA/WPA2 handshake. Catches issues early before
wasting time on a doomed cracking attempt.
"""

import os
import subprocess

from scapy.all import rdpcap, Dot11, EAPOL, Dot11Beacon

from config import AIRCRACK_BIN
from utils import print_status, print_success, print_error, print_warning, print_info, Colors


class HandshakeValidator:
    """Validates WPA/WPA2 handshake capture files."""

    def __init__(self, pcap_path, bssid=None):
        self.pcap_path = pcap_path
        self.bssid = bssid
        self.issues = []
        self.info = {}

    def validate(self):
        """Run all validation checks.

        Returns:
            dict: Validation result with keys:
                - valid (bool): Whether the capture is crackable
                - score (int): Quality score 0-100
                - issues (list): List of issue strings
                - info (dict): Extracted information
        """
        print_status(f"Validating capture: {self.pcap_path}")
        print()

        self.issues.clear()
        self.info.clear()

        # Check file exists and is readable
        if not self._check_file():
            return self._result(False, 0)

        # Load and analyze packets
        packets = self._load_packets()
        if packets is None:
            return self._result(False, 0)

        score = 0

        # Check for EAPOL frames
        eapol_score = self._check_eapol(packets)
        score += eapol_score

        # Check EAPOL message completeness
        msg_score = self._check_message_completeness(packets)
        score += msg_score

        # Check for beacon frames (helps aircrack-ng identify the network)
        beacon_score = self._check_beacons(packets)
        score += beacon_score

        # Validate with aircrack-ng if available
        aircrack_score = self._check_aircrack()
        score += aircrack_score

        # Print results
        self._print_report(score)

        valid = score >= 40 and eapol_score > 0
        return self._result(valid, score)

    def _check_file(self):
        """Check if file exists and is valid."""
        if not os.path.isfile(self.pcap_path):
            self.issues.append("File not found")
            print_error(f"File not found: {self.pcap_path}")
            return False

        size = os.path.getsize(self.pcap_path)
        self.info["file_size"] = size

        if size == 0:
            self.issues.append("File is empty")
            print_error("Capture file is empty (0 bytes)")
            return False

        if size < 100:
            self.issues.append("File suspiciously small")
            print_warning(f"File is very small ({size} bytes)")

        print_info(f"  File size: {size:,} bytes")
        return True

    def _load_packets(self):
        """Load packets from pcap."""
        try:
            packets = rdpcap(self.pcap_path)
            self.info["total_packets"] = len(packets)
            print_info(f"  Total packets: {len(packets)}")
            return packets
        except Exception as e:
            self.issues.append(f"Failed to read pcap: {e}")
            print_error(f"Failed to read pcap: {e}")
            return None

    def _check_eapol(self, packets):
        """Check for EAPOL frames and their quality."""
        eapol_packets = [p for p in packets if p.haslayer(EAPOL)]
        count = len(eapol_packets)
        self.info["eapol_count"] = count

        if count == 0:
            self.issues.append("No EAPOL frames found")
            print(f"  {Colors.RED}EAPOL frames: 0 (FAIL){Colors.RESET}")
            return 0

        print(f"  {Colors.GREEN}EAPOL frames: {count}{Colors.RESET}")

        # Check if EAPOL frames match our BSSID
        if self.bssid:
            matching = 0
            for p in eapol_packets:
                if p.haslayer(Dot11):
                    addrs = [
                        (p[Dot11].addr1 or "").lower(),
                        (p[Dot11].addr2 or "").lower(),
                        (p[Dot11].addr3 or "").lower(),
                    ]
                    if self.bssid.lower() in addrs:
                        matching += 1

            self.info["eapol_matching_bssid"] = matching
            if matching == 0:
                self.issues.append(f"No EAPOL frames match BSSID {self.bssid}")
                print(f"  {Colors.RED}Matching BSSID: 0/{count} (FAIL){Colors.RESET}")
                return 5
            else:
                print(f"  {Colors.GREEN}Matching BSSID: {matching}/{count}{Colors.RESET}")

        return min(30, count * 10)

    def _check_message_completeness(self, packets):
        """Check which 4-way handshake messages are present."""
        messages = set()

        for packet in packets:
            if not packet.haslayer(EAPOL):
                continue

            raw = bytes(packet[EAPOL])
            if len(raw) < 7:
                continue

            try:
                key_info = (raw[5] << 8) | raw[6]
            except IndexError:
                continue

            install = bool(key_info & (1 << 6))
            ack = bool(key_info & (1 << 7))
            mic = bool(key_info & (1 << 8))
            secure = bool(key_info & (1 << 9))

            if ack and not mic:
                messages.add(1)
            elif not ack and mic and not secure:
                messages.add(2)
            elif ack and mic and install:
                messages.add(3)
            elif not ack and mic and secure:
                messages.add(4)

        self.info["handshake_messages"] = sorted(messages)
        msg_str = ", ".join(f"M{m}" for m in sorted(messages)) or "none"
        print(f"  Handshake messages: {msg_str}")

        # Scoring based on completeness
        if {1, 2, 3, 4}.issubset(messages):
            print(f"  {Colors.GREEN}Complete 4-way handshake (EXCELLENT){Colors.RESET}")
            return 40
        elif {1, 2}.issubset(messages):
            print(f"  {Colors.GREEN}Messages 1+2 present (GOOD - sufficient for cracking){Colors.RESET}")
            return 30
        elif {2, 3}.issubset(messages):
            print(f"  {Colors.YELLOW}Messages 2+3 present (OK - may work){Colors.RESET}")
            return 20
        elif 2 in messages:
            self.issues.append("Only Message 2 captured - need at least M1+M2 or M2+M3")
            print(f"  {Colors.YELLOW}Only M2 present (WEAK - may fail){Colors.RESET}")
            return 10
        else:
            self.issues.append("Insufficient handshake messages")
            print(f"  {Colors.RED}Insufficient messages (FAIL){Colors.RESET}")
            return 0

    def _check_beacons(self, packets):
        """Check for Beacon frames (help identify the AP)."""
        beacons = [p for p in packets if p.haslayer(Dot11Beacon)]
        self.info["beacon_count"] = len(beacons)

        if beacons:
            print(f"  {Colors.GREEN}Beacon frames: {len(beacons)}{Colors.RESET}")
            return 10
        else:
            print(f"  {Colors.YELLOW}Beacon frames: 0 (not critical, but helps){Colors.RESET}")
            return 5

    def _check_aircrack(self):
        """Verify with aircrack-ng if available."""
        if not AIRCRACK_BIN:
            print(f"  {Colors.YELLOW}aircrack-ng: not available for verification{Colors.RESET}")
            return 0

        try:
            cmd = [AIRCRACK_BIN]
            if self.bssid:
                cmd.extend(["-b", self.bssid])
            cmd.append(self.pcap_path)

            result = subprocess.run(
                cmd,
                capture_output=True, text=True, timeout=10,
                input="\n"
            )

            if "1 handshake" in result.stdout:
                print(f"  {Colors.GREEN}aircrack-ng: Valid handshake confirmed{Colors.RESET}")
                return 20
            elif "0 handshake" in result.stdout:
                self.issues.append("aircrack-ng found no valid handshake")
                print(f"  {Colors.RED}aircrack-ng: No valid handshake{Colors.RESET}")
                return 0
            else:
                print(f"  {Colors.YELLOW}aircrack-ng: Inconclusive{Colors.RESET}")
                return 5

        except (subprocess.TimeoutExpired, FileNotFoundError):
            return 0

    def _print_report(self, score):
        """Print the validation summary."""
        print()
        print(f"{Colors.BOLD}{'=' * 50}")
        print(f" Validation Report")
        print(f"{'=' * 50}{Colors.RESET}")

        # Score bar
        bar_len = 30
        filled = int(bar_len * score / 100)
        bar = "█" * filled + "░" * (bar_len - filled)

        if score >= 70:
            color = Colors.GREEN
            verdict = "EXCELLENT - Ready for cracking"
        elif score >= 40:
            color = Colors.YELLOW
            verdict = "ACCEPTABLE - Cracking may succeed"
        else:
            color = Colors.RED
            verdict = "POOR - Likely insufficient for cracking"

        print(f"  Score: {color}{bar} {score}/100{Colors.RESET}")
        print(f"  Verdict: {color}{verdict}{Colors.RESET}")

        if self.issues:
            print(f"\n  {Colors.RED}Issues:{Colors.RESET}")
            for issue in self.issues:
                print(f"    • {issue}")

        print()

    def _result(self, valid, score):
        return {
            "valid": valid,
            "score": score,
            "issues": self.issues.copy(),
            "info": self.info.copy(),
        }
