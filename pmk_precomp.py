"""PMK Precomputation module - precomputes hash tables for faster cracking.

WPA/WPA2 key derivation uses PBKDF2-SHA1 with 4096 iterations, which is the
bottleneck in cracking. By precomputing PMK (Pairwise Master Key) values for
a specific SSID and wordlist, the expensive PBKDF2 step is done once and
stored in a database. Subsequent cracking attempts against the same SSID
use the precomputed values and are near-instant.

Tools used:
- airolib-ng: Manages an SQLite database of precomputed PMKs
- genpmk:     Standalone PMK generator (alternative)

Trade-offs:
- Precomputation takes significant time (same as cracking once)
- Database can be very large (16 bytes PMK per password per SSID)
- Massive speed advantage for common SSIDs (default router names)
- Only useful if you expect to crack multiple handshakes from the same SSID
"""

import os
import subprocess
import time

from config import find_binary, BASE_DIR
from utils import print_status, print_success, print_error, print_warning, print_info, Colors

AIROLIB_BIN = find_binary("airolib-ng")
GENPMK_BIN = find_binary("genpmk")
AIRCRACK_BIN = find_binary("aircrack-ng")

PMK_DB_DIR = os.path.join(BASE_DIR, "pmk_databases")
os.makedirs(PMK_DB_DIR, exist_ok=True)

# Common default SSIDs that benefit most from precomputation
COMMON_SSIDS = [
    "linksys", "NETGEAR", "default", "dlink", "ASUS",
    "TP-LINK", "Wireless", "Home", "FRITZ!Box",
    "SKY", "BTHub", "PLUSNET", "TalkTalk",
    "Vodafone", "o2-WLAN", "HITRON",
]


class PMKPrecomputer:
    """Precomputes PMK hash tables for a specific SSID."""

    def __init__(self, ssid, db_path=None):
        """
        Args:
            ssid: The target SSID to precompute PMKs for.
            db_path: Path to the airolib-ng database. Auto-generated if None.
        """
        self.ssid = ssid
        safe_ssid = "".join(c if c.isalnum() or c in "-_" else "_" for c in ssid)
        self.db_path = db_path or os.path.join(PMK_DB_DIR, f"pmk_{safe_ssid}.db")

    def _check_tools(self):
        """Check if required tools are available."""
        if AIROLIB_BIN:
            return "airolib"
        if GENPMK_BIN:
            return "genpmk"
        print_error("Neither airolib-ng nor genpmk found.")
        print_info("Install aircrack-ng suite: sudo apt install aircrack-ng")
        return None

    def precompute(self, wordlist):
        """Precompute PMK values for the given SSID and wordlist.

        Args:
            wordlist: Path to the wordlist file.

        Returns:
            str: Path to the database/output file, or None on failure.
        """
        tool = self._check_tools()
        if not tool:
            return None

        if not os.path.isfile(wordlist):
            print_error(f"Wordlist not found: {wordlist}")
            return None

        if tool == "airolib":
            return self._precompute_airolib(wordlist)
        else:
            return self._precompute_genpmk(wordlist)

    def _precompute_airolib(self, wordlist):
        """Precompute using airolib-ng (creates an SQLite database)."""
        print_status(f"Precomputing PMKs with airolib-ng...")
        print_info(f"  SSID: {self.ssid}")
        print_info(f"  Wordlist: {wordlist}")
        print_info(f"  Database: {self.db_path}")
        print()

        # Step 1: Import SSID into database
        print_status("Importing SSID...")
        ssid_file = self.db_path + ".ssid.tmp"
        try:
            with open(ssid_file, "w") as f:
                f.write(self.ssid + "\n")

            result = subprocess.run(
                [AIROLIB_BIN, self.db_path, "import", "essid", ssid_file],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode != 0 and "already" not in result.stderr.lower():
                print_error(f"Failed to import SSID: {result.stderr}")
        finally:
            if os.path.isfile(ssid_file):
                os.remove(ssid_file)

        # Step 2: Import wordlist
        print_status("Importing wordlist (this may take a while)...")
        result = subprocess.run(
            [AIROLIB_BIN, self.db_path, "import", "passwd", wordlist],
            capture_output=True, text=True, timeout=3600
        )

        # Step 3: Run batch computation
        print_status("Computing PMKs (PBKDF2-SHA1 x 4096 iterations per password)...")
        print_warning("This will take a long time. Progress is shown below.")
        print()

        start = time.time()
        try:
            proc = subprocess.Popen(
                [AIROLIB_BIN, self.db_path, "batch"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )

            for line in proc.stdout:
                line = line.rstrip()
                if line:
                    print(f"  {Colors.CYAN}{line}{Colors.RESET}", end="\r")

            proc.wait()
            elapsed = time.time() - start

        except subprocess.SubprocessError as e:
            print_error(f"Batch computation failed: {e}")
            return None

        print()
        minutes = int(elapsed // 60)
        seconds = int(elapsed % 60)
        print_success(f"Precomputation complete ({minutes}m {seconds}s)")

        # Show stats
        self.stats()
        return self.db_path

    def _precompute_genpmk(self, wordlist):
        """Precompute using genpmk (creates a flat PMK file)."""
        output_path = self.db_path.replace(".db", ".pmk")

        print_status(f"Precomputing PMKs with genpmk...")
        print_info(f"  SSID: {self.ssid}")
        print_info(f"  Wordlist: {wordlist}")
        print_info(f"  Output: {output_path}")
        print()

        try:
            proc = subprocess.Popen(
                [GENPMK_BIN, "-f", wordlist, "-d", output_path, "-s", self.ssid],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )

            for line in proc.stdout:
                line = line.rstrip()
                if line:
                    print(f"  {Colors.CYAN}{line}{Colors.RESET}", end="\r")

            proc.wait()
            print()

            if os.path.isfile(output_path):
                size_mb = os.path.getsize(output_path) / 1024 / 1024
                print_success(f"PMK file generated: {output_path} ({size_mb:.1f}MB)")
                return output_path
            else:
                print_error("genpmk produced no output.")
                return None

        except (FileNotFoundError, subprocess.SubprocessError) as e:
            print_error(f"genpmk error: {e}")
            return None

    def crack(self, pcap_path, bssid=None):
        """Crack a handshake using precomputed PMK database.

        Args:
            pcap_path: Path to .pcap file with handshake.
            bssid: Target BSSID (optional).

        Returns:
            str: Password if found, None otherwise.
        """
        if not AIRCRACK_BIN:
            print_error("aircrack-ng not found.")
            return None

        if not os.path.isfile(self.db_path):
            print_error(f"PMK database not found: {self.db_path}")
            print_info("Run precomputation first: python main.py precompute ...")
            return None

        print_status("Cracking with precomputed PMKs (should be near-instant)...")
        print_info(f"  Database: {self.db_path}")
        print_info(f"  Capture: {pcap_path}")

        cmd = [AIRCRACK_BIN, "-r", self.db_path]
        if bssid:
            cmd.extend(["-b", bssid])
        cmd.append(pcap_path)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True, text=True, timeout=60
            )

            import re
            match = re.search(r"KEY FOUND!\s*\[\s*(.+?)\s*\]", result.stdout)
            if match:
                password = match.group(1)
                print_success(f"Password found: {Colors.BOLD}{Colors.GREEN}{password}{Colors.RESET}")
                return password
            else:
                print_warning("Password not found in precomputed database.")
                return None

        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            print_error(f"Cracking failed: {e}")
            return None

    def stats(self):
        """Print database statistics."""
        if not AIROLIB_BIN or not os.path.isfile(self.db_path):
            return

        try:
            result = subprocess.run(
                [AIROLIB_BIN, self.db_path, "stats"],
                capture_output=True, text=True, timeout=10
            )
            if result.stdout:
                print_info("Database stats:")
                for line in result.stdout.splitlines():
                    if line.strip():
                        print(f"    {line.strip()}")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

    def check_existing(self):
        """Check if a precomputed database already exists for this SSID."""
        if os.path.isfile(self.db_path):
            size_mb = os.path.getsize(self.db_path) / 1024 / 1024
            print_info(f"Existing PMK database found: {self.db_path} ({size_mb:.1f}MB)")
            return True
        return False


def list_databases():
    """List all precomputed PMK databases."""
    dbs = [f for f in os.listdir(PMK_DB_DIR)
           if f.endswith(".db") or f.endswith(".pmk")]

    if not dbs:
        print_info("No precomputed PMK databases found.")
        return

    print(f"\n{Colors.BOLD}Precomputed PMK Databases:{Colors.RESET}\n")
    for db in sorted(dbs):
        path = os.path.join(PMK_DB_DIR, db)
        size_mb = os.path.getsize(path) / 1024 / 1024
        ssid = db.replace("pmk_", "").replace(".db", "").replace(".pmk", "")
        print(f"  {db:<40s} {size_mb:>8.1f}MB  (SSID: {ssid})")
    print()
