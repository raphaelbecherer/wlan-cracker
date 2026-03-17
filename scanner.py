"""Network scanner - discovers access points and connected clients."""

import time
import threading
from collections import OrderedDict

from scapy.all import Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeResp, sniff, RadioTap

from config import SCAN_TIMEOUT
from utils import Colors, print_status, print_success, print_info, print_warning


class AccessPoint:
    """Represents a discovered access point."""

    def __init__(self, bssid, ssid, channel, encryption, signal):
        self.bssid = bssid
        self.ssid = ssid
        self.channel = channel
        self.encryption = encryption
        self.signal = signal
        self.clients = set()
        self.is_wpa3 = "WPA3" in encryption or "SAE" in encryption

    def __str__(self):
        clients_str = f"{len(self.clients)} clients" if self.clients else "no clients"
        wpa3_flag = " ⚠WPA3" if self.is_wpa3 else ""
        return (
            f"{self.bssid}  {self.ssid:<32s}  CH:{self.channel:<3d}  "
            f"{self.signal:>4d}dBm  {self.encryption:<16s}  [{clients_str}]{wpa3_flag}"
        )


class NetworkScanner:
    """Scans for wireless networks and connected clients."""

    def __init__(self, interface):
        self.interface = interface
        self.access_points = OrderedDict()  # bssid -> AccessPoint
        self._stop_event = threading.Event()

    def _get_encryption(self, packet):
        """Determine encryption type from beacon frame, including WPA3/SAE detection."""
        crypto = set()

        # Check for WPA2/WPA3 (RSN Information Element, ID=48)
        rsn = packet.getlayer(Dot11Elt, ID=48)
        if rsn and hasattr(rsn, 'info') and len(rsn.info) >= 8:
            rsn_data = bytes(rsn.info)
            crypto.add("WPA2")

            # Parse AKM suites to detect WPA3/SAE
            # RSN IE structure: Version(2) + Group Cipher(4) +
            # Pairwise Count(2) + Pairwise Suites(4*n) +
            # AKM Count(2) + AKM Suites(4*n)
            try:
                offset = 2 + 4  # Skip version + group cipher
                pairwise_count = rsn_data[offset] | (rsn_data[offset + 1] << 8)
                offset += 2 + (pairwise_count * 4)  # Skip pairwise suites

                akm_count = rsn_data[offset] | (rsn_data[offset + 1] << 8)
                offset += 2

                for i in range(akm_count):
                    if offset + 4 > len(rsn_data):
                        break
                    akm_suite = rsn_data[offset:offset + 4]

                    # AKM Suite OUI: 00-0F-AC
                    # Type 8 = SAE (WPA3-Personal)
                    # Type 18 = SAE with FT
                    # Type 12 = Suite B 192-bit (WPA3-Enterprise)
                    if akm_suite[:3] == b'\x00\x0f\xac':
                        akm_type = akm_suite[3]
                        if akm_type in (8, 18):
                            crypto.add("WPA3")
                            crypto.add("SAE")
                        elif akm_type == 12:
                            crypto.add("WPA3-Enterprise")
                        elif akm_type == 2:
                            pass  # Standard PSK (WPA2)
                        elif akm_type == 1:
                            crypto.add("802.1X")

                    offset += 4

                # Check RSN capabilities for MFP (Management Frame Protection)
                # Required MFP is a strong WPA3 indicator
                if offset + 2 <= len(rsn_data):
                    rsn_caps = rsn_data[offset] | (rsn_data[offset + 1] << 8)
                    mfp_required = bool(rsn_caps & (1 << 6))
                    mfp_capable = bool(rsn_caps & (1 << 7))
                    if mfp_required and "SAE" in crypto:
                        crypto.discard("WPA2")  # Pure WPA3, not transition mode

            except (IndexError, ValueError):
                pass  # Parsing failed, keep what we have

        # Check for WPA (vendor specific)
        wpa = packet.getlayer(Dot11Elt, ID=221)
        if wpa and hasattr(wpa, 'info'):
            if b'\x00\x50\xf2\x01' in bytes(wpa.info[:4]) if len(wpa.info) >= 4 else False:
                crypto.add("WPA")

        # Check capability for WEP
        cap = packet.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}"
                             "{Dot11ProbeResp:%Dot11ProbeResp.cap%}")
        if "privacy" in cap and not crypto:
            crypto.add("WEP")

        if not crypto:
            crypto.add("OPEN")

        return "/".join(sorted(crypto))

    def _get_channel(self, packet):
        """Extract channel from DS Parameter Set element."""
        ds = packet.getlayer(Dot11Elt, ID=3)
        if ds and hasattr(ds, 'info') and len(ds.info) >= 1:
            return ds.info[0]
        return 0

    def _get_signal(self, packet):
        """Extract signal strength from RadioTap header."""
        if packet.haslayer(RadioTap):
            try:
                return packet[RadioTap].dBm_AntSignal
            except AttributeError:
                pass
        return -100

    def _packet_handler(self, packet):
        """Process each sniffed packet."""
        # Beacon / Probe Response -> AP discovery
        if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
            bssid = packet[Dot11].addr2
            if not bssid:
                return

            # Extract SSID
            ssid_elt = packet.getlayer(Dot11Elt, ID=0)
            ssid = ""
            if ssid_elt and hasattr(ssid_elt, 'info'):
                try:
                    ssid = ssid_elt.info.decode('utf-8', errors='replace')
                except Exception:
                    ssid = "<hidden>"
            if not ssid:
                ssid = "<hidden>"

            channel = self._get_channel(packet)
            signal = self._get_signal(packet)
            encryption = self._get_encryption(packet)

            if bssid not in self.access_points:
                self.access_points[bssid] = AccessPoint(
                    bssid, ssid, channel, encryption, signal
                )
            else:
                # Update signal strength (keep strongest)
                ap = self.access_points[bssid]
                if signal > ap.signal:
                    ap.signal = signal

        # Data frames -> client discovery
        elif packet.haslayer(Dot11) and packet.type == 2:
            # DS status tells us direction of frame
            ds = packet.FCfield & 0x3
            src = None
            bssid = None

            if ds == 0x1:  # To DS: client -> AP
                bssid = packet.addr1
                src = packet.addr2
            elif ds == 0x2:  # From DS: AP -> client
                bssid = packet.addr2
                src = packet.addr3

            if bssid and src and bssid in self.access_points:
                # Don't add broadcast addresses as clients
                if src != "ff:ff:ff:ff:ff:ff" and src != bssid:
                    self.access_points[bssid].clients.add(src)

    def scan(self, timeout=None, channel=None):
        """Scan for networks.

        Args:
            timeout: Scan duration in seconds (default: SCAN_TIMEOUT).
            channel: If set, only scan this channel (no hopping needed).

        Returns:
            dict: BSSID -> AccessPoint mapping.
        """
        timeout = timeout or SCAN_TIMEOUT
        self.access_points.clear()
        self._stop_event.clear()

        print_status(f"Scanning for networks on {self.interface} ({timeout}s)...")
        print()

        try:
            sniff(
                iface=self.interface,
                prn=self._packet_handler,
                timeout=timeout,
                store=False,
                stop_filter=lambda _: self._stop_event.is_set()
            )
        except PermissionError:
            from utils import print_error
            print_error("Permission denied. Run as root/sudo.")
            return {}
        except OSError as e:
            from utils import print_error
            print_error(f"Interface error: {e}")
            return {}

        return self.access_points

    def stop(self):
        """Stop an ongoing scan."""
        self._stop_event.set()

    def get_sorted_by_signal(self):
        """Return access points sorted by signal strength (strongest first).

        Returns:
            list[AccessPoint]: APs sorted by RSSI descending.
        """
        return sorted(self.access_points.values(), key=lambda ap: ap.signal, reverse=True)

    def get_channel_for_bssid(self, bssid):
        """Auto-detect the channel for a given BSSID from scan results.

        Args:
            bssid: Target BSSID to look up.

        Returns:
            int: Channel number, or None if not found.
        """
        bssid = bssid.lower()
        for ap_bssid, ap in self.access_points.items():
            if ap_bssid.lower() == bssid:
                return ap.channel
        return None

    def quick_channel_detect(self, bssid, timeout=10):
        """Quick scan to detect what channel a specific BSSID is on.

        Args:
            bssid: Target BSSID.
            timeout: Max scan time in seconds.

        Returns:
            int: Channel number, or None.
        """
        bssid = bssid.lower()
        self._stop_event.clear()
        detected_channel = [None]  # Use list for closure mutation

        def _handler(packet):
            if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
                pkt_bssid = packet[Dot11].addr2
                if pkt_bssid and pkt_bssid.lower() == bssid:
                    ch = self._get_channel(packet)
                    if ch:
                        detected_channel[0] = ch
                        self._stop_event.set()

        try:
            sniff(
                iface=self.interface,
                prn=_handler,
                timeout=timeout,
                store=False,
                stop_filter=lambda _: self._stop_event.is_set()
            )
        except (PermissionError, OSError):
            pass

        return detected_channel[0]

    def print_results(self, sort_by_signal=True):
        """Print discovered networks in a formatted table.

        Args:
            sort_by_signal: Sort by signal strength descending (default True).
        """
        if not self.access_points:
            print_info("No networks found.")
            return

        if sort_by_signal:
            ap_list = self.get_sorted_by_signal()
        else:
            ap_list = list(self.access_points.values())

        # Determine band column
        print(f"\n{Colors.BOLD}{'#':<4s}{'BSSID':<20s}{'SSID':<34s}{'CH':<6s}"
              f"{'Signal':<10s}{'Band':<8s}{'Encryption':<18s}{'Clients'}{Colors.RESET}")
        print("-" * 120)

        wpa3_count = 0
        for idx, ap in enumerate(ap_list, 1):
            if ap.is_wpa3:
                color = Colors.RED
                wpa3_count += 1
            elif ap.encryption == "OPEN":
                color = Colors.GREEN
            elif "WPA2" in ap.encryption:
                color = Colors.CYAN
            else:
                color = Colors.YELLOW

            band = "5 GHz" if ap.channel >= 36 else "2.4G"
            clients_str = f"{len(ap.clients)} clients" if ap.clients else "no clients"
            wpa3_flag = " ⚠WPA3" if ap.is_wpa3 else ""
            print(f"{color}{idx:<4d}{ap.bssid:<20s}{ap.ssid:<34s}{ap.channel:<6d}"
                  f"{ap.signal:>4d}dBm   {band:<8s}{ap.encryption:<18s}"
                  f"[{clients_str}]{wpa3_flag}{Colors.RESET}")

        print(f"\n{Colors.BOLD}Total: {len(self.access_points)} networks found.{Colors.RESET}")

        # Band breakdown
        count_24 = sum(1 for ap in ap_list if ap.channel < 36)
        count_5 = sum(1 for ap in ap_list if ap.channel >= 36)
        if count_5 > 0:
            print(f"{Colors.CYAN}  2.4 GHz: {count_24}  |  5 GHz: {count_5}{Colors.RESET}")

        if wpa3_count > 0:
            print(f"\n{Colors.RED}{Colors.BOLD}⚠ {wpa3_count} WPA3/SAE network(s) detected.{Colors.RESET}")
            print(f"{Colors.RED}  WPA3 uses Simultaneous Authentication of Equals (SAE).{Colors.RESET}")
            print(f"{Colors.RED}  These networks are RESISTANT to offline dictionary attacks.{Colors.RESET}")
            print(f"{Colors.RED}  Traditional handshake capture + cracking will NOT work.{Colors.RESET}")

    def select_target(self):
        """Interactive target selection from scan results (sorted by signal)."""
        if not self.access_points:
            return None

        self.print_results(sort_by_signal=True)
        print()

        ap_list = self.get_sorted_by_signal()
        while True:
            try:
                choice = input(f"{Colors.BOLD}Select target [1-{len(ap_list)}]: {Colors.RESET}")
                idx = int(choice) - 1
                if 0 <= idx < len(ap_list):
                    target = ap_list[idx]

                    # WPA3 warning
                    if target.is_wpa3:
                        print()
                        print_warning(f"{'=' * 55}")
                        print_warning(f" WARNING: {target.ssid} uses WPA3/SAE!")
                        print_warning(f"{'=' * 55}")
                        print_warning("WPA3 is resistant to offline dictionary attacks.")
                        print_warning("The 4-way handshake capture approach will NOT work.")
                        print_warning("Deauth + crack pipeline will likely fail.")
                        print()
                        confirm = input(f"{Colors.YELLOW}Continue anyway? [y/N]: {Colors.RESET}")
                        if confirm.lower() != 'y':
                            continue

                    print_success(f"Target: {target.ssid} ({target.bssid}) on channel {target.channel}")
                    return target
                print("Invalid selection.")
            except (ValueError, EOFError, KeyboardInterrupt):
                print()
                return None
