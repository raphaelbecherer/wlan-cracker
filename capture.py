"""Handshake capture module - captures WPA/WPA2 4-way handshake EAPOL frames."""

import os
import time
import subprocess
import threading
from datetime import datetime

from scapy.all import Dot11, Dot11Beacon, EAPOL, sniff, wrpcap

from config import CAPTURES_DIR, HANDSHAKE_TIMEOUT
from utils import print_status, print_success, print_error, print_warning, print_info, Colors


def _check_interface_exists(interface):
    """Check if a monitor mode interface still exists and is usable."""
    try:
        result = subprocess.run(
            ["iwconfig", interface],
            capture_output=True, text=True, timeout=5
        )
        return result.returncode == 0 and "No such device" not in result.stderr
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


class HandshakeCapture:
    """Captures WPA/WPA2 4-way handshake packets."""

    def __init__(self, interface, bssid, ssid="unknown"):
        """
        Args:
            interface: Monitor mode interface to sniff on.
            bssid: Target AP's BSSID.
            ssid: Target SSID (used for filename).
        """
        self.interface = interface
        self.bssid = bssid.lower()
        self.ssid = ssid
        self.eapol_packets = []
        self.handshake_messages = set()  # Track which EAPOL messages we've captured
        self.handshake_complete = False
        self._stop_event = threading.Event()
        self._thread = None
        self.pcap_path = None

    def _identify_eapol_message(self, packet):
        """Identify which message in the 4-way handshake this EAPOL frame is.

        Returns message number (1-4) or 0 if undetermined.
        """
        if not packet.haslayer(EAPOL):
            return 0

        eapol = packet[EAPOL]

        # Raw key info bytes for WPA key frames
        raw = bytes(eapol)
        if len(raw) < 6:
            return 0

        # Key info is at offset 1-2 in the EAPOL-Key frame body
        # After the EAPOL header (4 bytes): type(1) + key_info(2)
        try:
            key_info = (raw[5] << 8) | raw[6]
        except IndexError:
            return 0

        # Bit flags in key info
        install = bool(key_info & (1 << 6))
        ack = bool(key_info & (1 << 7))
        mic = bool(key_info & (1 << 8))
        secure = bool(key_info & (1 << 9))

        # Message identification based on key info bits:
        # Msg 1: ACK=1, MIC=0
        # Msg 2: ACK=0, MIC=1, secure=0
        # Msg 3: ACK=1, MIC=1, install=1
        # Msg 4: ACK=0, MIC=1, secure=1 (or simply the last one)
        if ack and not mic:
            return 1
        elif not ack and mic and not secure:
            return 2
        elif ack and mic and install:
            return 3
        elif not ack and mic and secure:
            return 4

        return 0

    def _packet_handler(self, packet):
        """Process each captured packet looking for EAPOL frames."""
        if not packet.haslayer(EAPOL):
            return

        # Check if this EAPOL frame involves our target AP
        if packet.haslayer(Dot11):
            addr1 = (packet[Dot11].addr1 or "").lower()
            addr2 = (packet[Dot11].addr2 or "").lower()
            addr3 = (packet[Dot11].addr3 or "").lower()

            if self.bssid not in (addr1, addr2, addr3):
                return

        msg_num = self._identify_eapol_message(packet)
        if msg_num == 0:
            # Still capture it even if we can't identify the exact message
            self.eapol_packets.append(packet)
            print_info("Captured EAPOL frame (unidentified)")
            return

        self.eapol_packets.append(packet)
        self.handshake_messages.add(msg_num)

        print(
            f"  {Colors.GREEN}Captured EAPOL Message {msg_num}/4 "
            f"[{''.join(str(m) for m in sorted(self.handshake_messages))}/1234]{Colors.RESET}"
        )

        # Check if we have a usable handshake (need at least messages 1-2 or 2-3)
        if {1, 2}.issubset(self.handshake_messages) or \
           {2, 3}.issubset(self.handshake_messages):
            self.handshake_complete = True
            print_success("WPA handshake captured!")
            self._stop_event.set()

    def _generate_filename(self):
        """Generate a filename for the capture file."""
        safe_ssid = "".join(c if c.isalnum() or c in "-_" else "_" for c in self.ssid)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return os.path.join(CAPTURES_DIR, f"handshake_{safe_ssid}_{timestamp}.pcap")

    def capture(self, timeout=None):
        """Start capturing handshake packets (blocking).

        Args:
            timeout: Max seconds to capture (default: HANDSHAKE_TIMEOUT).

        Returns:
            str: Path to saved pcap file if handshake captured, None otherwise.
        """
        timeout = timeout or HANDSHAKE_TIMEOUT
        self._stop_event.clear()
        self.eapol_packets.clear()
        self.handshake_messages.clear()
        self.handshake_complete = False

        print_status(
            f"Waiting for WPA handshake from {self.bssid} "
            f"(timeout: {timeout}s)..."
        )

        for _attempt in range(3):
            try:
                sniff(
                    iface=self.interface,
                    prn=self._packet_handler,
                    lfilter=lambda p: p.haslayer(EAPOL),
                    timeout=timeout,
                    store=False,
                    stop_filter=lambda _: self._stop_event.is_set()
                )
                break
            except PermissionError:
                print_error("Permission denied. Run as root/sudo.")
                return None
            except OSError as e:
                if _attempt < 2 and not self._stop_event.is_set():
                    # Verify interface still exists before retrying
                    if not _check_interface_exists(self.interface):
                        print_error(f"Interface {self.interface} is no longer available.")
                        return None
                    print_warning(f"Interface error: {e} - retrying in 2s...")
                    time.sleep(2)
                else:
                    print_error(f"Interface error: {e}")
                    return None

        return self._save_capture()

    def capture_async(self, timeout=None):
        """Start capturing in a background thread.

        Args:
            timeout: Max seconds to capture.
        """
        self._thread = threading.Thread(
            target=self.capture,
            args=(timeout,),
            daemon=True
        )
        self._thread.start()

    def wait(self, timeout=None):
        """Wait for async capture to complete."""
        if self._thread:
            self._thread.join(timeout=timeout)
        return self._save_capture() if self.eapol_packets and not self.pcap_path else self.pcap_path

    def stop(self):
        """Stop capture."""
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)

    def _save_capture(self):
        """Save captured EAPOL packets to a pcap file."""
        if not self.eapol_packets:
            print_warning("No EAPOL packets captured.")
            return None

        if self.pcap_path:
            return self.pcap_path

        self.pcap_path = self._generate_filename()
        wrpcap(self.pcap_path, self.eapol_packets)
        print_success(f"Capture saved to: {self.pcap_path}")

        if self.handshake_complete:
            print_success("Handshake is COMPLETE - ready for cracking.")
        else:
            msgs = sorted(self.handshake_messages)
            print_warning(
                f"Partial handshake only (messages: {msgs}). "
                f"May not be sufficient for cracking."
            )

        return self.pcap_path


class PassiveCapture:
    """Passively captures WPA handshakes without sending any deauth frames.

    This is a stealthier approach that waits for clients to naturally
    reconnect (e.g., after sleep/wake, roaming, or connection drops).
    No traffic is injected, making this invisible to IDS/WIDS.

    Trade-offs:
    - Much stealthier (no deauth = no IDS alerts)
    - Can take minutes to hours (depends on client activity)
    - Also captures beacon frames for better pcap quality
    - Useful in environments where deauth would be detected
    """

    def __init__(self, interface, bssid=None, ssid=None):
        """
        Args:
            interface: Monitor mode interface.
            bssid: Target AP BSSID. If None, captures from ANY AP.
            ssid: Target SSID (for filename/display).
        """
        self.interface = interface
        self.bssid = bssid.lower() if bssid else None
        self.ssid = ssid or "passive"
        self.all_packets = []  # Beacons + EAPOL for better pcap quality
        self.eapol_packets = []
        self.handshake_messages = set()
        self.handshake_complete = False
        self.captured_aps = {}  # bssid -> set of handshake message numbers
        self._stop_event = threading.Event()
        self._thread = None
        self.pcap_path = None

    def _packet_handler(self, packet):
        """Process packets passively - capture beacons and EAPOL frames."""
        # Capture beacons from target AP (improves pcap quality for cracking)
        if packet.haslayer(Dot11Beacon):
            if self.bssid:
                pkt_bssid = (packet[Dot11].addr2 or "").lower()
                if pkt_bssid == self.bssid:
                    self.all_packets.append(packet)
            return

        # Capture EAPOL frames
        if not packet.haslayer(EAPOL):
            return

        # Filter by BSSID if specified
        if self.bssid and packet.haslayer(Dot11):
            addr1 = (packet[Dot11].addr1 or "").lower()
            addr2 = (packet[Dot11].addr2 or "").lower()
            addr3 = (packet[Dot11].addr3 or "").lower()
            if self.bssid not in (addr1, addr2, addr3):
                return

        # Determine which AP this EAPOL belongs to
        ap_bssid = None
        if packet.haslayer(Dot11):
            addr1 = (packet[Dot11].addr1 or "").lower()
            addr2 = (packet[Dot11].addr2 or "").lower()
            addr3 = (packet[Dot11].addr3 or "").lower()
            for addr in (addr3, addr1, addr2):
                if addr and addr != "ff:ff:ff:ff:ff:ff":
                    ap_bssid = addr
                    break

        self.eapol_packets.append(packet)
        self.all_packets.append(packet)

        # Identify message number
        msg_num = self._identify_eapol_message(packet)

        if ap_bssid:
            if ap_bssid not in self.captured_aps:
                self.captured_aps[ap_bssid] = set()
            if msg_num:
                self.captured_aps[ap_bssid].add(msg_num)

        if msg_num:
            self.handshake_messages.add(msg_num)
            ap_label = ap_bssid or "unknown"
            print(f"  {Colors.GREEN}[PASSIVE] EAPOL M{msg_num}/4 from {ap_label} "
                  f"[{''.join(str(m) for m in sorted(self.handshake_messages))}/1234]{Colors.RESET}")
        else:
            print_info("[PASSIVE] Captured EAPOL frame (unidentified)")

        # Check if any AP has a complete handshake
        if self.bssid:
            msgs = self.captured_aps.get(self.bssid, set())
        else:
            msgs = self.handshake_messages

        if {1, 2}.issubset(msgs) or {2, 3}.issubset(msgs):
            self.handshake_complete = True
            print_success("Passive handshake capture complete!")
            self._stop_event.set()

    def _identify_eapol_message(self, packet):
        """Identify EAPOL message number."""
        if not packet.haslayer(EAPOL):
            return 0
        eapol = packet[EAPOL]
        raw = bytes(eapol)
        if len(raw) < 7:
            return 0
        try:
            key_info = (raw[5] << 8) | raw[6]
        except IndexError:
            return 0

        install = bool(key_info & (1 << 6))
        ack = bool(key_info & (1 << 7))
        mic = bool(key_info & (1 << 8))
        secure = bool(key_info & (1 << 9))

        if ack and not mic:
            return 1
        elif not ack and mic and not secure:
            return 2
        elif ack and mic and install:
            return 3
        elif not ack and mic and secure:
            return 4
        return 0

    def capture(self, timeout=None):
        """Passively capture handshake (blocking).

        Args:
            timeout: Max seconds to wait. Default: 5 minutes (passive takes longer).

        Returns:
            str: Path to saved pcap, or None.
        """
        timeout = timeout or 300  # 5 minutes default for passive
        self._stop_event.clear()
        self.eapol_packets.clear()
        self.all_packets.clear()
        self.handshake_messages.clear()
        self.captured_aps.clear()
        self.handshake_complete = False

        target = self.bssid or "ALL networks"
        print_status("Passive capture mode - waiting for natural handshakes...")
        print_info(f"  Target: {target}")
        print_info(f"  Timeout: {timeout}s")
        print_info("  No deauth frames will be sent (stealth mode)")
        print_warning("  This may take several minutes. Wait for clients to reconnect naturally.")
        print()

        for _attempt in range(3):
            try:
                sniff(
                    iface=self.interface,
                    prn=self._packet_handler,
                    lfilter=lambda p: p.haslayer(EAPOL) or p.haslayer(Dot11Beacon),
                    timeout=timeout,
                    store=False,
                    stop_filter=lambda _: self._stop_event.is_set()
                )
                break
            except PermissionError:
                print_error("Permission denied. Run as root/sudo.")
                return None
            except OSError as e:
                if _attempt < 2 and not self._stop_event.is_set():
                    # Verify interface still exists before retrying
                    if not _check_interface_exists(self.interface):
                        print_error(f"Interface {self.interface} is no longer available.")
                        return None
                    print_warning(f"Interface error: {e} - retrying in 2s...")
                    time.sleep(2)
                else:
                    print_error(f"Interface error: {e}")
                    return None

        return self._save_capture()

    def capture_async(self, timeout=None):
        """Start passive capture in background thread."""
        self._thread = threading.Thread(
            target=self.capture, args=(timeout,), daemon=True
        )
        self._thread.start()

    def wait(self, timeout=None):
        """Wait for async capture to complete."""
        if self._thread:
            self._thread.join(timeout=timeout)
        return self.pcap_path

    def stop(self):
        """Stop passive capture."""
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)

    def _save_capture(self):
        """Save captured packets to pcap."""
        if not self.eapol_packets:
            print_warning("No EAPOL packets captured passively.")
            if self.captured_aps:
                print_info(f"  Saw activity from {len(self.captured_aps)} AP(s) "
                           "but no complete handshake.")
            return None

        if self.pcap_path:
            return self.pcap_path

        safe_ssid = "".join(c if c.isalnum() or c in "-_" else "_" for c in self.ssid)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.pcap_path = os.path.join(CAPTURES_DIR, f"passive_{safe_ssid}_{timestamp}.pcap")

        # Save all packets (beacons + EAPOL) for maximum pcap quality
        wrpcap(self.pcap_path, self.all_packets)
        print_success(f"Passive capture saved to: {self.pcap_path}")
        print_info(f"  Total packets: {len(self.all_packets)} "
                   f"({len(self.eapol_packets)} EAPOL)")

        if self.handshake_complete:
            print_success("Handshake is COMPLETE - ready for cracking.")
        else:
            msgs = sorted(self.handshake_messages)
            print_warning(f"Partial handshake (messages: {msgs}). May need more time.")

        # Show per-AP summary if capturing from multiple
        if len(self.captured_aps) > 1:
            print_info("  Per-AP breakdown:")
            for bssid, msgs in self.captured_aps.items():
                status = "COMPLETE" if {1, 2}.issubset(msgs) or {2, 3}.issubset(msgs) else "partial"
                print_info(f"    {bssid}: messages {sorted(msgs)} ({status})")

        return self.pcap_path
