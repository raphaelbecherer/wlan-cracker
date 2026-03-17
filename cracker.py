"""Aircrack-ng integration for WPA/WPA2 password cracking."""

import os
import re
import subprocess
import threading

from config import AIRCRACK_BIN
from utils import print_status, print_success, print_error, print_warning, print_info, Colors


class AircrackCracker:
    """Wraps aircrack-ng to crack WPA/WPA2 handshakes using a wordlist."""

    def __init__(self, pcap_path, bssid=None):
        """
        Args:
            pcap_path: Path to the .pcap file containing the handshake.
            bssid: Target BSSID to crack (optional if only one AP in capture).
        """
        self.pcap_path = pcap_path
        self.bssid = bssid
        self.process = None
        self.password = None
        self._stop_event = threading.Event()

    def _check_prerequisites(self):
        """Verify aircrack-ng is available and pcap exists."""
        if not AIRCRACK_BIN:
            print_error("aircrack-ng not found on this system.")
            print_info("Install it with: sudo apt install aircrack-ng")
            return False

        if not os.path.isfile(self.pcap_path):
            print_error(f"Capture file not found: {self.pcap_path}")
            return False

        return True

    def crack(self, wordlist):
        """Run aircrack-ng to crack the handshake.

        Args:
            wordlist: Path to a wordlist file, or a list of paths
                      (aircrack-ng supports multiple via comma separation).

        Returns:
            str: The cracked password, or None if not found.
        """
        if not self._check_prerequisites():
            return None

        # Handle multiple wordlists
        if isinstance(wordlist, (list, tuple)):
            # Validate all paths
            valid = [w for w in wordlist if os.path.isfile(w)]
            if not valid:
                print_error("No valid wordlist files found.")
                return None
            for w in wordlist:
                if not os.path.isfile(w):
                    print_warning(f"Wordlist not found, skipping: {w}")
            wordlist_arg = ",".join(valid)
            print_info(f"  Using {len(valid)} wordlists")
        else:
            if not os.path.isfile(wordlist):
                print_error(f"Wordlist not found: {wordlist}")
                return None
            wordlist_arg = wordlist

        # Build command
        cmd = [AIRCRACK_BIN, "-w", wordlist_arg, "-l", "-"]

        if self.bssid:
            cmd.extend(["-b", self.bssid])

        cmd.append(self.pcap_path)

        print_status(f"Starting aircrack-ng...")
        print_info(f"  Capture: {self.pcap_path}")
        print_info(f"  Wordlist: {wordlist}")
        if self.bssid:
            print_info(f"  BSSID: {self.bssid}")
        print()

        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )

            output_lines = []
            for line in self.process.stdout:
                if self._stop_event.is_set():
                    self.process.terminate()
                    return None

                line = line.rstrip()
                output_lines.append(line)

                # Show progress
                if "keys tested" in line.lower():
                    print(f"  {Colors.CYAN}{line}{Colors.RESET}", end="\r")
                elif "key found" in line.lower() or "found" in line.lower():
                    print(f"\n  {Colors.GREEN}{line}{Colors.RESET}")

            self.process.wait()

            # Parse the full output for the key
            full_output = "\n".join(output_lines)
            return self._parse_result(full_output)

        except FileNotFoundError:
            print_error("aircrack-ng binary not found.")
            return None
        except subprocess.SubprocessError as e:
            print_error(f"aircrack-ng error: {e}")
            return None

    def _parse_result(self, output):
        """Parse aircrack-ng output for the cracked password.

        Args:
            output: Full stdout from aircrack-ng.

        Returns:
            str: Password if found, None otherwise.
        """
        # Pattern: "KEY FOUND! [ password ]"
        match = re.search(r"KEY FOUND!\s*\[\s*(.+?)\s*\]", output)
        if match:
            self.password = match.group(1)
            print()
            print_success(f"Password found: {Colors.BOLD}{Colors.GREEN}{self.password}{Colors.RESET}")
            return self.password

        # Check for common failure messages
        if "No matching network found" in output:
            print_error("No matching network found in the capture file.")
            print_info("Make sure the capture contains a valid handshake for the target BSSID.")
        elif "Passphrase not in dictionary" in output or "exhausted" in output.lower():
            print_warning("Password not found in wordlist.")
            print_info("Try a larger wordlist or different attack approach.")
        elif "No valid WPA handshake" in output:
            print_error("No valid WPA handshake found in the capture file.")
            print_info("Re-capture the handshake and ensure all 4 EAPOL messages are present.")
        else:
            print_warning("Cracking finished without finding the password.")

        return None

    def stop(self):
        """Stop the cracking process."""
        self._stop_event.set()
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
        print_warning("Cracking stopped.")

    def verify_handshake(self):
        """Check if the pcap file contains a valid handshake using aircrack-ng.

        Returns:
            bool: True if a valid handshake is found.
        """
        if not AIRCRACK_BIN or not os.path.isfile(self.pcap_path):
            return False

        cmd = [AIRCRACK_BIN]
        if self.bssid:
            cmd.extend(["-b", self.bssid])
        cmd.append(self.pcap_path)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True, text=True, timeout=10,
                input="\n"  # Cancel the interactive prompt
            )
            # aircrack-ng shows "1 handshake" if it finds one
            if "1 handshake" in result.stdout:
                print_success("Valid WPA handshake confirmed in capture file.")
                return True
            else:
                print_warning("No valid WPA handshake found in capture file.")
                return False
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
