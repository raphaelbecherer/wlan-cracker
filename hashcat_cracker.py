"""Hashcat integration for GPU-accelerated WPA/WPA2 password cracking."""

import os
import re
import subprocess
import threading

from config import HASHCAT_BIN, HCXPCAPTOOL_BIN, HASHCAT_WPA_MODE, CAPTURES_DIR
from utils import print_status, print_success, print_error, print_warning, print_info, Colors


class HashcatCracker:
    """Wraps hashcat for GPU-accelerated WPA/WPA2 cracking.

    Hashcat is significantly faster than aircrack-ng because it leverages
    GPU parallelism. Typical speed comparison:
      - aircrack-ng (CPU): ~5,000-10,000 keys/sec
      - hashcat (GPU):     ~100,000-1,000,000+ keys/sec
    """

    def __init__(self, pcap_path, bssid=None):
        """
        Args:
            pcap_path: Path to .pcap or .hc22000 file.
            bssid: Target BSSID (optional filter).
        """
        self.pcap_path = pcap_path
        self.bssid = bssid
        self.hash_file = None
        self.process = None
        self.password = None
        self._stop_event = threading.Event()

    def _check_prerequisites(self):
        """Check if hashcat and conversion tools are available."""
        if not HASHCAT_BIN:
            print_error("hashcat not found on this system.")
            print_info("Install: sudo apt install hashcat")
            print_info("Or download from: https://hashcat.net/hashcat/")
            return False

        if not os.path.isfile(self.pcap_path):
            print_error(f"File not found: {self.pcap_path}")
            return False

        return True

    def convert_to_hc22000(self):
        """Convert .pcap to hashcat's .hc22000 format.

        Returns:
            str: Path to the .hc22000 file, or None on failure.
        """
        # If already in hc22000 format, skip conversion
        if self.pcap_path.endswith(".hc22000") or self.pcap_path.endswith(".22000"):
            self.hash_file = self.pcap_path
            return self.hash_file

        if not HCXPCAPTOOL_BIN:
            print_error("hcxpcapngtool not found. Cannot convert pcap to hashcat format.")
            print_info("Install: sudo apt install hcxtools")
            return None

        # Output path
        base = os.path.splitext(self.pcap_path)[0]
        self.hash_file = base + ".hc22000"

        print_status(f"Converting capture to hashcat format...")
        cmd = [HCXPCAPTOOL_BIN, "-o", self.hash_file]

        if self.bssid:
            # Filter by BSSID (remove colons for hcxpcapngtool)
            bssid_clean = self.bssid.replace(":", "").lower()
            cmd.extend(["--filtermac", bssid_clean])

        cmd.append(self.pcap_path)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True, text=True, timeout=30
            )

            if os.path.isfile(self.hash_file) and os.path.getsize(self.hash_file) > 0:
                print_success(f"Converted: {self.hash_file}")

                # Count hashes
                with open(self.hash_file, "r") as f:
                    hash_count = sum(1 for line in f if line.strip())
                print_info(f"  Found {hash_count} hash(es) (handshakes + PMKIDs)")
                return self.hash_file
            else:
                print_error("Conversion produced no output.")
                if result.stderr:
                    print_info(f"  {result.stderr.strip()}")
                return None

        except FileNotFoundError:
            print_error("hcxpcapngtool binary not found.")
            return None
        except subprocess.TimeoutExpired:
            print_error("Conversion timed out.")
            return None

    def crack(self, wordlist, rules_file=None, extra_args=None):
        """Run hashcat to crack the capture.

        Args:
            wordlist: Path to wordlist file.
            rules_file: Optional path to hashcat rules file for mutations.
            extra_args: Optional list of extra hashcat arguments.

        Returns:
            str: Cracked password or None.
        """
        if not self._check_prerequisites():
            return None

        if not os.path.isfile(wordlist):
            print_error(f"Wordlist not found: {wordlist}")
            return None

        # Convert if needed
        if not self.hash_file:
            if not self.convert_to_hc22000():
                return None

        # Build hashcat command
        cmd = [
            HASHCAT_BIN,
            "-m", str(HASHCAT_WPA_MODE),
            self.hash_file,
            wordlist,
            "--force",           # Ignore warnings (useful in VMs)
            "--status",          # Show periodic status
            "--status-timer", "10",
            "--potfile-disable",  # Don't use potfile cache
        ]

        if rules_file and os.path.isfile(rules_file):
            cmd.extend(["-r", rules_file])
            print_info(f"  Rules: {rules_file}")

        if extra_args:
            cmd.extend(extra_args)

        print_status("Starting hashcat (GPU-accelerated)...")
        print_info(f"  Hash file: {self.hash_file}")
        print_info(f"  Wordlist: {wordlist}")
        print_info(f"  Mode: {HASHCAT_WPA_MODE} (WPA-PBKDF2-PMKID+EAPOL)")
        print()

        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
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

                # Show progress lines
                if "Speed" in line or "Progress" in line or "Recovered" in line:
                    print(f"  {Colors.CYAN}{line}{Colors.RESET}")
                elif "Cracked" in line or ":" in line and len(line) < 200:
                    print(f"  {Colors.GREEN}{line}{Colors.RESET}")

            self.process.wait()

            full_output = "\n".join(output_lines)
            return self._parse_result(full_output)

        except FileNotFoundError:
            print_error("hashcat binary not found.")
            return None
        except subprocess.SubprocessError as e:
            print_error(f"hashcat error: {e}")
            return None

    def _parse_result(self, output):
        """Parse hashcat output for cracked password."""
        # Hashcat outputs cracked hashes as: hash:password
        # For WPA: <hash_line>:<password>
        # Also check "Recovered" line

        # Look for recovered passwords in show mode
        for line in output.splitlines():
            # hc22000 format: WPA*...:password
            if line.startswith("WPA*") and ":" in line:
                parts = line.rsplit(":", 1)
                if len(parts) == 2 and parts[1]:
                    self.password = parts[1]
                    break

        if not self.password:
            # Try running --show to get cracked passwords
            if self.hash_file:
                try:
                    show_result = subprocess.run(
                        [HASHCAT_BIN, "-m", str(HASHCAT_WPA_MODE),
                         self.hash_file, "--show", "--potfile-disable"],
                        capture_output=True, text=True, timeout=10
                    )
                    for line in show_result.stdout.splitlines():
                        if ":" in line and line.strip():
                            parts = line.rsplit(":", 1)
                            if len(parts) == 2 and parts[1]:
                                self.password = parts[1]
                                break
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    pass

        if self.password:
            print()
            print_success(f"Password found: {Colors.BOLD}{Colors.GREEN}{self.password}{Colors.RESET}")
            return self.password

        # Check failure reasons
        if "No hashes loaded" in output:
            print_error("No valid hashes found in the file.")
            print_info("The capture may not contain a valid handshake or PMKID.")
        elif "Exhausted" in output or "exhausted" in output:
            print_warning("Password not found in wordlist.")
            print_info("Try a larger wordlist or enable rule-based mutations.")
        elif "No devices found" in output:
            print_error("No compatible GPU devices found.")
            print_info("Make sure GPU drivers are installed (OpenCL/CUDA).")
            print_info("Use --force flag or fall back to aircrack-ng for CPU cracking.")
        else:
            print_warning("Cracking finished without finding the password.")

        return None

    def mask_attack(self, mask=None, min_length=8, max_length=8, extra_args=None):
        """Run hashcat mask (brute-force) attack.

        Mask attack tries all combinations matching a pattern. Useful for
        passwords like 8-digit PINs, phone numbers, or patterned passwords.

        Built-in charsets:
          ?d = digits (0-9)
          ?l = lowercase (a-z)
          ?u = uppercase (A-Z)
          ?a = all printable ASCII
          ?s = special characters

        Args:
            mask: Hashcat mask string. If None, uses ?d * min_length (all digits).
            min_length: Min password length for increment mode.
            max_length: Max password length for increment mode.
            extra_args: Additional hashcat arguments.

        Returns:
            str: Cracked password or None.

        Examples:
            mask="?d?d?d?d?d?d?d?d"       -> all 8-digit numbers
            mask="?u?l?l?l?l?d?d?d"        -> Pattern like "Hello123"
            mask="?a?a?a?a?a?a?a?a"        -> all 8-char printable (SLOW!)
        """
        if not self._check_prerequisites():
            return None

        if not self.hash_file:
            if not self.convert_to_hc22000():
                return None

        # Default mask: all digits
        if not mask:
            mask = "?d" * min_length

        cmd = [
            HASHCAT_BIN,
            "-m", str(HASHCAT_WPA_MODE),
            "-a", "3",              # Attack mode 3 = brute-force/mask
            self.hash_file,
            mask,
            "--force",
            "--status",
            "--status-timer", "10",
            "--potfile-disable",
        ]

        # Increment mode: try shorter passwords first
        if min_length != max_length:
            cmd.extend(["--increment",
                        "--increment-min", str(min_length),
                        "--increment-max", str(max_length)])

        if extra_args:
            cmd.extend(extra_args)

        print_status("Starting hashcat MASK attack (brute-force)...")
        print_info(f"  Hash file: {self.hash_file}")
        print_info(f"  Mask: {mask}")
        print_info(f"  Length range: {min_length}-{max_length}")

        # Estimate keyspace
        keyspace = self._estimate_keyspace(mask)
        if keyspace:
            print_info(f"  Keyspace: {keyspace:,} combinations")

        print()

        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
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
                if "Speed" in line or "Progress" in line or "Recovered" in line:
                    print(f"  {Colors.CYAN}{line}{Colors.RESET}")

            self.process.wait()
            return self._parse_result("\n".join(output_lines))

        except (FileNotFoundError, subprocess.SubprocessError) as e:
            print_error(f"hashcat error: {e}")
            return None

    def combo_attack(self, wordlist1, wordlist2, extra_args=None):
        """Run hashcat combinator attack (word1+word2).

        Tries every combination of words from two wordlists concatenated.
        Useful for compound passwords like "sunshine" + "123" = "sunshine123".

        Args:
            wordlist1: Path to first wordlist.
            wordlist2: Path to second wordlist.
            extra_args: Additional hashcat arguments.

        Returns:
            str: Cracked password or None.
        """
        if not self._check_prerequisites():
            return None

        for wl in [wordlist1, wordlist2]:
            if not os.path.isfile(wl):
                print_error(f"Wordlist not found: {wl}")
                return None

        if not self.hash_file:
            if not self.convert_to_hc22000():
                return None

        cmd = [
            HASHCAT_BIN,
            "-m", str(HASHCAT_WPA_MODE),
            "-a", "1",              # Attack mode 1 = combinator
            self.hash_file,
            wordlist1,
            wordlist2,
            "--force",
            "--status",
            "--status-timer", "10",
            "--potfile-disable",
        ]

        if extra_args:
            cmd.extend(extra_args)

        print_status("Starting hashcat COMBINATOR attack (word1+word2)...")
        print_info(f"  Hash file: {self.hash_file}")
        print_info(f"  Wordlist 1: {wordlist1}")
        print_info(f"  Wordlist 2: {wordlist2}")
        print()

        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
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
                if "Speed" in line or "Progress" in line or "Recovered" in line:
                    print(f"  {Colors.CYAN}{line}{Colors.RESET}")

            self.process.wait()
            return self._parse_result("\n".join(output_lines))

        except (FileNotFoundError, subprocess.SubprocessError) as e:
            print_error(f"hashcat error: {e}")
            return None

    def crack_with_session(self, wordlist, session_name="wpa_session",
                           rules_file=None, restore=False):
        """Run hashcat with session support for pause/resume.

        Args:
            wordlist: Path to wordlist file.
            session_name: Name for the hashcat session.
            rules_file: Optional rules file.
            restore: If True, resume a previous session instead of starting new.

        Returns:
            str: Cracked password or None.
        """
        if not self._check_prerequisites():
            return None

        if restore:
            # Resume a previous session
            cmd = [
                HASHCAT_BIN,
                "--session", session_name,
                "--restore",
                "--force",
                "--status",
                "--status-timer", "10",
            ]
            print_status(f"Resuming hashcat session: {session_name}")
        else:
            if not os.path.isfile(wordlist):
                print_error(f"Wordlist not found: {wordlist}")
                return None

            if not self.hash_file:
                if not self.convert_to_hc22000():
                    return None

            cmd = [
                HASHCAT_BIN,
                "-m", str(HASHCAT_WPA_MODE),
                self.hash_file,
                wordlist,
                "--session", session_name,
                "--force",
                "--status",
                "--status-timer", "10",
            ]

            if rules_file and os.path.isfile(rules_file):
                cmd.extend(["-r", rules_file])

            print_status(f"Starting hashcat with session: {session_name}")
            print_info("  Press Ctrl+C to pause. Resume with: --restore")

        print()

        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )

            output_lines = []
            for line in self.process.stdout:
                if self._stop_event.is_set():
                    # Checkpoint and quit gracefully
                    self.process.send_signal(2)  # SIGINT for checkpoint
                    print_info("\nSession checkpointed. Resume with --restore.")
                    self.process.wait(timeout=10)
                    return None
                line = line.rstrip()
                output_lines.append(line)
                if "Speed" in line or "Progress" in line or "Recovered" in line:
                    print(f"  {Colors.CYAN}{line}{Colors.RESET}")
                elif "Checkpoint" in line or "Session" in line:
                    print(f"  {Colors.YELLOW}{line}{Colors.RESET}")

            self.process.wait()
            return self._parse_result("\n".join(output_lines))

        except (FileNotFoundError, subprocess.SubprocessError) as e:
            print_error(f"hashcat error: {e}")
            return None

    def _estimate_keyspace(self, mask):
        """Estimate keyspace size for a mask."""
        charset_sizes = {
            "?d": 10,
            "?l": 26,
            "?u": 26,
            "?a": 95,
            "?s": 33,
            "?h": 16,  # hex lowercase
            "?H": 16,  # hex uppercase
        }
        total = 1
        i = 0
        while i < len(mask):
            if i + 1 < len(mask) and mask[i] == "?":
                key = mask[i:i + 2]
                total *= charset_sizes.get(key, 95)
                i += 2
            else:
                i += 1  # literal character
        return total if total > 1 else None

    def hybrid_attack(self, wordlist, mask, mode=6, extra_args=None):
        """Run hashcat hybrid attack (wordlist + mask or mask + wordlist).

        Mode 6: wordlist + mask -> each word gets the mask appended
          e.g., wordlist has "password", mask "?d?d?d" -> "password000" to "password999"

        Mode 7: mask + wordlist -> mask is prepended to each word
          e.g., mask "?d?d?d", wordlist has "password" -> "000password" to "999password"

        This is powerful for common patterns like:
          - "word" + year:     mode=6, mask="?d?d?d?d"  -> "word2024"
          - "word" + digits:   mode=6, mask="?d?d?d"    -> "word123"
          - digits + "word":   mode=7, mask="?d?d?d"    -> "123word"
          - "word" + specials: mode=6, mask="?s?d?d"    -> "word!23"

        Args:
            wordlist: Path to wordlist file.
            mask: Hashcat mask to append (mode 6) or prepend (mode 7).
            mode: 6 = wordlist+mask (default), 7 = mask+wordlist.
            extra_args: Additional hashcat arguments.

        Returns:
            str: Cracked password or None.
        """
        if mode not in (6, 7):
            print_error("Hybrid mode must be 6 (wordlist+mask) or 7 (mask+wordlist).")
            return None

        if not self._check_prerequisites():
            return None

        if not os.path.isfile(wordlist):
            print_error(f"Wordlist not found: {wordlist}")
            return None

        if not self.hash_file:
            if not self.convert_to_hc22000():
                return None

        cmd = [
            HASHCAT_BIN,
            "-m", str(HASHCAT_WPA_MODE),
            "-a", str(mode),
            self.hash_file,
        ]

        # Mode 6: wordlist then mask; Mode 7: mask then wordlist
        if mode == 6:
            cmd.extend([wordlist, mask])
        else:
            cmd.extend([mask, wordlist])

        cmd.extend([
            "--force",
            "--status",
            "--status-timer", "10",
            "--potfile-disable",
        ])

        if extra_args:
            cmd.extend(extra_args)

        mode_desc = "wordlist + mask (append)" if mode == 6 else "mask + wordlist (prepend)"
        print_status(f"Starting hashcat HYBRID attack ({mode_desc})...")
        print_info(f"  Hash file: {self.hash_file}")
        print_info(f"  Wordlist: {wordlist}")
        print_info(f"  Mask: {mask}")
        print_info(f"  Mode: {mode} ({mode_desc})")

        # Estimate keyspace contribution from mask
        mask_keyspace = self._estimate_keyspace(mask)
        if mask_keyspace:
            print_info(f"  Mask keyspace: {mask_keyspace:,} per word")

        print()

        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
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
                if "Speed" in line or "Progress" in line or "Recovered" in line:
                    print(f"  {Colors.CYAN}{line}{Colors.RESET}")

            self.process.wait()
            return self._parse_result("\n".join(output_lines))

        except (FileNotFoundError, subprocess.SubprocessError) as e:
            print_error(f"hashcat error: {e}")
            return None

    def prince_attack(self, wordlist, min_length=8, max_length=16,
                       min_elem=1, max_elem=4, extra_args=None):
        """Run PRINCE (PRobability INfinite Chained Elements) attack.

        PRINCE generates password candidates by combining words from a wordlist
        using statistical probability ordering. Unlike combinator (mode 1) which
        only joins exactly 2 words, PRINCE can chain 1-N elements and orders
        candidates by likelihood based on word frequency.

        Example: wordlist has ["pass", "word", "123", "!"]
          -> "password", "pass123", "word!", "password123!", etc.
          Ordered by probability (most common combinations first).

        PRINCE is more efficient than brute-force for human-created passwords
        because it mirrors how people actually construct passwords.

        Requirements:
            hashcat-utils package with `pp64.bin` (PRINCE preprocessor),
            OR hashcat >= 6.0 which has built-in PRINCE support via --prince flag.

        Args:
            wordlist: Path to wordlist (ideally frequency-sorted).
            min_length: Minimum candidate length (default: 8 for WPA).
            max_length: Maximum candidate length.
            min_elem: Minimum word chain elements (default: 1).
            max_elem: Maximum word chain elements (default: 4).
            extra_args: Additional arguments.

        Returns:
            str: Cracked password or None.
        """
        if not self._check_prerequisites():
            return None

        if not os.path.isfile(wordlist):
            print_error(f"Wordlist not found: {wordlist}")
            return None

        if not self.hash_file:
            if not self.convert_to_hc22000():
                return None

        # Check for pp64 (PRINCE preprocessor from hashcat-utils)
        from config import find_binary
        pp64_bin = find_binary("pp64.bin") or find_binary("pp64")

        if pp64_bin:
            return self._prince_with_pp64(
                wordlist, pp64_bin, min_length, max_length,
                min_elem, max_elem, extra_args
            )
        else:
            # Fallback: use hashcat's built-in PRINCE mode if available
            return self._prince_builtin(
                wordlist, min_length, max_length,
                min_elem, max_elem, extra_args
            )

    def _prince_with_pp64(self, wordlist, pp64_bin, min_length, max_length,
                           min_elem, max_elem, extra_args):
        """Run PRINCE attack using pp64 preprocessor piped into hashcat."""
        print_status("Starting PRINCE attack (pp64 preprocessor)...")
        print_info(f"  Hash file: {self.hash_file}")
        print_info(f"  Wordlist: {wordlist}")
        print_info(f"  Length range: {min_length}-{max_length}")
        print_info(f"  Elements: {min_elem}-{max_elem} words chained")
        print()

        # pp64 generates candidates, piped into hashcat via stdin
        pp64_cmd = [
            pp64_bin,
            f"--pw-min={min_length}",
            f"--pw-max={max_length}",
            f"--elem-cnt-min={min_elem}",
            f"--elem-cnt-max={max_elem}",
            wordlist,
        ]

        hashcat_cmd = [
            HASHCAT_BIN,
            "-m", str(HASHCAT_WPA_MODE),
            "-a", "0",  # Straight mode (reading from stdin)
            self.hash_file,
            "--force",
            "--status",
            "--status-timer", "10",
            "--potfile-disable",
        ]

        if extra_args:
            hashcat_cmd.extend(extra_args)

        try:
            # Pipe pp64 output into hashcat
            pp64_proc = subprocess.Popen(
                pp64_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )

            self.process = subprocess.Popen(
                hashcat_cmd,
                stdin=pp64_proc.stdout,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            pp64_proc.stdout.close()  # Allow pp64 to receive SIGPIPE

            output_lines = []
            for line in self.process.stdout:
                if self._stop_event.is_set():
                    self.process.terminate()
                    pp64_proc.terminate()
                    return None
                line = line.rstrip()
                output_lines.append(line)
                if "Speed" in line or "Progress" in line or "Recovered" in line:
                    print(f"  {Colors.CYAN}{line}{Colors.RESET}")

            self.process.wait()
            pp64_proc.wait()
            return self._parse_result("\n".join(output_lines))

        except (FileNotFoundError, subprocess.SubprocessError) as e:
            print_error(f"PRINCE attack error: {e}")
            return None

    def _prince_builtin(self, wordlist, min_length, max_length,
                         min_elem, max_elem, extra_args):
        """Run PRINCE attack using hashcat's built-in support.

        Hashcat 6.2+ supports PRINCE natively as attack mode 8 (experimental).
        Falls back to generating candidates with Python if not available.
        """
        # Try hashcat attack mode 8 (PRINCE) - may not be available in all versions
        cmd = [
            HASHCAT_BIN,
            "-m", str(HASHCAT_WPA_MODE),
            "-a", "0",  # Use dictionary mode with generated candidates
            self.hash_file,
            "--force",
            "--status",
            "--status-timer", "10",
            "--potfile-disable",
        ]

        if extra_args:
            cmd.extend(extra_args)

        print_status("Starting PRINCE attack (Python candidate generator)...")
        print_info(f"  Hash file: {self.hash_file}")
        print_info(f"  Wordlist: {wordlist}")
        print_info(f"  Length range: {min_length}-{max_length}")
        print_info(f"  Elements: {min_elem}-{max_elem} words chained")
        print_warning("  pp64 not found. Using Python PRINCE generator (slower).")
        print_info("  Install hashcat-utils for better performance: "
                   "github.com/hashcat/hashcat-utils")
        print()

        # Generate PRINCE candidates and pipe to hashcat
        try:
            self.process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )

            # Generate candidates in a thread
            def generate_candidates():
                try:
                    words = []
                    with open(wordlist, "r", errors="replace") as f:
                        for line in f:
                            w = line.strip()
                            if w:
                                words.append(w)
                            if len(words) >= 50000:  # Cap for memory
                                break

                    # Generate combinations of 1..max_elem words
                    import itertools
                    for num_elem in range(min_elem, max_elem + 1):
                        for combo in itertools.product(words[:5000], repeat=num_elem):
                            if self._stop_event.is_set():
                                return
                            candidate = "".join(combo)
                            if min_length <= len(candidate) <= max_length:
                                try:
                                    self.process.stdin.write(candidate + "\n")
                                    self.process.stdin.flush()
                                except (BrokenPipeError, OSError):
                                    return
                except Exception:
                    pass
                finally:
                    try:
                        self.process.stdin.close()
                    except (BrokenPipeError, OSError):
                        pass

            gen_thread = threading.Thread(target=generate_candidates, daemon=True)
            gen_thread.start()

            output_lines = []
            for line in self.process.stdout:
                if self._stop_event.is_set():
                    self.process.terminate()
                    return None
                line = line.rstrip()
                output_lines.append(line)
                if "Speed" in line or "Progress" in line or "Recovered" in line:
                    print(f"  {Colors.CYAN}{line}{Colors.RESET}")

            self.process.wait()
            gen_thread.join(timeout=5)
            return self._parse_result("\n".join(output_lines))

        except (FileNotFoundError, subprocess.SubprocessError) as e:
            print_error(f"PRINCE attack error: {e}")
            return None

    def benchmark(self):
        """Run hashcat benchmark for WPA mode to show expected speed."""
        if not HASHCAT_BIN:
            print_error("hashcat not found.")
            return

        print_status("Running hashcat benchmark for WPA2...")
        try:
            result = subprocess.run(
                [HASHCAT_BIN, "-b", "-m", str(HASHCAT_WPA_MODE), "--force"],
                capture_output=True, text=True, timeout=120
            )
            for line in result.stdout.splitlines():
                if "Speed" in line or "Hash" in line:
                    print(f"  {Colors.CYAN}{line.strip()}{Colors.RESET}")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            print_error("Benchmark failed.")

    def stop(self):
        """Stop hashcat."""
        self._stop_event.set()
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
        print_warning("Hashcat stopped.")
