"""Wordlist management - download, merge, and manage wordlists.

Supports auto-downloading common wordlists and chaining multiple
wordlists into a single cracking run.
"""

import os
import gzip
import shutil
import subprocess
import urllib.request
import urllib.error

from config import BASE_DIR
from utils import print_status, print_success, print_error, print_warning, print_info, Colors


WORDLISTS_DIR = os.path.join(BASE_DIR, "wordlists")
os.makedirs(WORDLISTS_DIR, exist_ok=True)

# Common wordlists available for download
AVAILABLE_WORDLISTS = {
    "rockyou": {
        "url": "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt",
        "filename": "rockyou.txt",
        "description": "Classic 14M password leak (most popular wordlist)",
        "size_mb": 134,
    },
    "common-passwords": {
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt",
        "filename": "common-1M.txt",
        "description": "Top 1 million most common passwords",
        "size_mb": 8,
    },
    "wifi-passwords": {
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/WiFi-WPA/probable-v2-wpa-top4800.txt",
        "filename": "wifi-wpa-top4800.txt",
        "description": "Top 4800 most common WiFi passwords",
        "size_mb": 0.05,
    },
    "darkweb-top10k": {
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/darkweb2017-top10000.txt",
        "filename": "darkweb-top10k.txt",
        "description": "Top 10K dark web passwords (2017)",
        "size_mb": 0.1,
    },
    "numbers-8digit": {
        "url": None,  # Generated locally
        "filename": "numbers-8digit.txt",
        "description": "All 8-digit number combinations (00000000-99999999)",
        "size_mb": 86,
    },
}


def list_available():
    """Print available wordlists and their download status."""
    print(f"\n{Colors.BOLD}Available Wordlists:{Colors.RESET}\n")
    print(f"  {'Name':<20s} {'Size':<10s} {'Status':<14s} {'Description'}")
    print(f"  {'-' * 80}")

    for name, info in AVAILABLE_WORDLISTS.items():
        path = os.path.join(WORDLISTS_DIR, info["filename"])
        exists = os.path.isfile(path)
        status = f"{Colors.GREEN}downloaded{Colors.RESET}" if exists else f"{Colors.YELLOW}available{Colors.RESET}"
        size = f"{info['size_mb']}MB"
        print(f"  {name:<20s} {size:<10s} {status:<24s} {info['description']}")

    # Check for custom wordlists
    custom = [f for f in os.listdir(WORDLISTS_DIR)
              if f not in [info["filename"] for info in AVAILABLE_WORDLISTS.values()]]
    if custom:
        print(f"\n  {Colors.CYAN}Custom wordlists in {WORDLISTS_DIR}:{Colors.RESET}")
        for f in custom:
            size = os.path.getsize(os.path.join(WORDLISTS_DIR, f))
            print(f"    {f} ({size / 1024 / 1024:.1f}MB)")

    print()


def download_wordlist(name):
    """Download a wordlist by name.

    Args:
        name: Key from AVAILABLE_WORDLISTS.

    Returns:
        str: Path to downloaded file, or None on failure.
    """
    if name not in AVAILABLE_WORDLISTS:
        print_error(f"Unknown wordlist: {name}")
        print_info(f"Available: {', '.join(AVAILABLE_WORDLISTS.keys())}")
        return None

    info = AVAILABLE_WORDLISTS[name]
    output_path = os.path.join(WORDLISTS_DIR, info["filename"])

    # Already downloaded?
    if os.path.isfile(output_path):
        print_info(f"Already downloaded: {output_path}")
        return output_path

    # Special case: generated wordlists
    if info["url"] is None:
        return _generate_wordlist(name, output_path)

    print_status(f"Downloading {name} ({info['size_mb']}MB)...")
    print_info(f"  Source: {info['url']}")

    try:
        # Download with progress
        def _progress(block_num, block_size, total_size):
            downloaded = block_num * block_size
            if total_size > 0:
                pct = min(100, downloaded * 100 // total_size)
                bar_len = 30
                filled = int(bar_len * pct / 100)
                bar = "█" * filled + "░" * (bar_len - filled)
                print(f"  {bar} {pct}%", end="\r")

        temp_path = output_path + ".tmp"
        urllib.request.urlretrieve(info["url"], temp_path, reporthook=_progress)
        print()

        # Handle gzipped files
        if info["url"].endswith(".gz"):
            print_status("Extracting...")
            with gzip.open(temp_path, 'rb') as f_in, \
                 open(output_path, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
            os.remove(temp_path)
        else:
            os.rename(temp_path, output_path)

        size_mb = os.path.getsize(output_path) / 1024 / 1024
        line_count = _count_lines(output_path)
        print_success(f"Downloaded: {output_path} ({size_mb:.1f}MB, {line_count:,} passwords)")
        return output_path

    except urllib.error.URLError as e:
        print_error(f"Download failed: {e}")
        return None
    except Exception as e:
        print_error(f"Error: {e}")
        # Cleanup temp file
        temp_path = output_path + ".tmp"
        if os.path.isfile(temp_path):
            os.remove(temp_path)
        return None


def download_all():
    """Download all available wordlists."""
    paths = []
    for name in AVAILABLE_WORDLISTS:
        path = download_wordlist(name)
        if path:
            paths.append(path)
    return paths


def _generate_wordlist(name, output_path):
    """Generate a wordlist locally."""
    if name == "numbers-8digit":
        print_status("Generating 8-digit number wordlist (00000000-99999999)...")
        print_warning("This will take a moment and use ~86MB of disk space.")

        with open(output_path, "w") as f:
            for n in range(100_000_000):
                f.write(f"{n:08d}\n")
                if n % 10_000_000 == 0 and n > 0:
                    print(f"  Progress: {n // 1_000_000}M / 100M", end="\r")

        print()
        print_success(f"Generated: {output_path}")
        return output_path

    print_error(f"Don't know how to generate: {name}")
    return None


def _count_lines(filepath):
    """Count lines in a file efficiently."""
    count = 0
    with open(filepath, "rb") as f:
        for _ in f:
            count += 1
    return count


def merge_wordlists(wordlist_paths, output_path=None, deduplicate=True):
    """Merge multiple wordlists into one.

    Args:
        wordlist_paths: List of paths to wordlist files.
        output_path: Where to save merged list. Auto-generated if None.
        deduplicate: Remove duplicate entries.

    Returns:
        str: Path to merged wordlist.
    """
    if not wordlist_paths:
        print_error("No wordlists to merge.")
        return None

    # Filter to existing files
    valid_paths = []
    for p in wordlist_paths:
        if os.path.isfile(p):
            valid_paths.append(p)
        else:
            print_warning(f"Wordlist not found, skipping: {p}")

    if not valid_paths:
        print_error("No valid wordlist files found.")
        return None

    if len(valid_paths) == 1 and not deduplicate:
        return valid_paths[0]

    if not output_path:
        output_path = os.path.join(WORDLISTS_DIR, "merged_wordlist.txt")

    print_status(f"Merging {len(valid_paths)} wordlists...")
    for p in valid_paths:
        print_info(f"  + {p}")

    total = 0
    seen = set() if deduplicate else None

    with open(output_path, "w") as fout:
        for wl_path in valid_paths:
            try:
                with open(wl_path, "r", errors="ignore") as fin:
                    for line in fin:
                        word = line.strip()
                        if not word:
                            continue
                        if deduplicate:
                            if word in seen:
                                continue
                            seen.add(word)
                        fout.write(word + "\n")
                        total += 1
            except Exception as e:
                print_warning(f"Error reading {wl_path}: {e}")

    size_mb = os.path.getsize(output_path) / 1024 / 1024
    print_success(f"Merged: {output_path} ({total:,} passwords, {size_mb:.1f}MB)")
    return output_path


def get_wordlist_path(name_or_path):
    """Resolve a wordlist name or path.

    Accepts either a path to a file, or a name from AVAILABLE_WORDLISTS.
    Downloads if needed.

    Returns:
        str: Resolved file path, or None.
    """
    # Direct path
    if os.path.isfile(name_or_path):
        return name_or_path

    # Check in wordlists dir
    in_dir = os.path.join(WORDLISTS_DIR, name_or_path)
    if os.path.isfile(in_dir):
        return in_dir

    # Known wordlist name -> download
    if name_or_path in AVAILABLE_WORDLISTS:
        return download_wordlist(name_or_path)

    print_error(f"Wordlist not found: {name_or_path}")
    return None
