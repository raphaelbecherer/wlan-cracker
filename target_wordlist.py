"""Targeted wordlist generator - creates OSINT-based custom wordlists.

Generic wordlists miss passwords that are specific to a target, such as:
- Company/business name variations (e.g., "AcmeCorp2024!")
- Street address or location (e.g., "MainSt123")
- Phone numbers
- Owner/family names
- Router model-based defaults
- City or region names
- Common local patterns

This module generates targeted wordlists by combining user-provided
keywords with common password patterns, numbers, and symbols.
This drastically improves hit rates for non-random passwords.
"""

import os
import itertools
from datetime import datetime

from config import BASE_DIR
from utils import print_status, print_success, print_info, print_warning, Colors


WORDLISTS_DIR = os.path.join(BASE_DIR, "wordlists")
os.makedirs(WORDLISTS_DIR, exist_ok=True)

# Common suffixes appended to base words
COMMON_SUFFIXES = [
    "", "1", "12", "123", "1234", "12345",
    "!", "!!", "@", "#", "$",
    "01", "02", "69", "007", "99", "00",
]

# Year suffixes
YEAR_SUFFIXES = [str(y) for y in range(2015, 2027)]

# Common separators
SEPARATORS = ["", "_", "-", ".", "@", "#"]

# Common prefixes
COMMON_PREFIXES = [
    "", "the", "my", "our",
]

# Special number patterns (phone-like, PIN-like)
NUMBER_PATTERNS = [
    # 8-digit numeric patterns common as WiFi passwords
    "00000000", "12345678", "87654321", "11111111",
    "password", "qwerty12", "admin123",
]

# Common WiFi password patterns
WIFI_PATTERNS = [
    "{word}WiFi", "{word}wifi", "{word}WIFI",
    "{word}Net", "{word}net", "{word}Network",
    "WiFi{word}", "wifi{word}",
    "{word}Guest", "{word}guest",
    "{word}Home", "{word}home",
    "{word}Office", "{word}office",
    "{word}Secure", "{word}secure",
]


def generate_targeted_wordlist(keywords, output_path=None, include_wifi_patterns=True):
    """Generate a targeted wordlist from provided keywords.

    Args:
        keywords: List of keyword strings (names, places, numbers, etc.)
        output_path: Output file path. Auto-generated if None.
        include_wifi_patterns: Include WiFi-specific patterns.

    Returns:
        str: Path to generated wordlist.
    """
    if not keywords:
        print_warning("No keywords provided.")
        return None

    if not output_path:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = os.path.join(WORDLISTS_DIR, f"targeted_{timestamp}.txt")

    print_status("Generating targeted wordlist...")
    print_info(f"  Keywords: {', '.join(keywords)}")

    seen = set()
    passwords = []

    def add(pw):
        if pw and len(pw) >= 8 and pw not in seen:  # WPA min is 8 chars
            seen.add(pw)
            passwords.append(pw)

    # Process each keyword
    for keyword in keywords:
        keyword = keyword.strip()
        if not keyword:
            continue

        # Base variations of the keyword
        variants = _generate_variants(keyword)

        for variant in variants:
            # Keyword alone (if >= 8 chars)
            add(variant)

            # Keyword + common suffixes
            for suffix in COMMON_SUFFIXES:
                add(variant + suffix)

            # Keyword + year
            for year in YEAR_SUFFIXES:
                add(variant + year)
                add(variant + "!" + year)
                add(variant + "@" + year)
                add(year + variant)

            # Keyword + separator + numbers
            for sep in SEPARATORS:
                for num in ["1", "12", "123", "1234", "!", "!!"]:
                    add(variant + sep + num)

            # WiFi-specific patterns
            if include_wifi_patterns:
                for pattern in WIFI_PATTERNS:
                    add(pattern.format(word=variant))

    # Keyword combinations (for 2+ keywords)
    if len(keywords) >= 2:
        for k1, k2 in itertools.permutations(keywords[:5], 2):
            k1, k2 = k1.strip(), k2.strip()
            for sep in ["", "_", "-", ".", " "]:
                combo = k1 + sep + k2
                add(combo)
                add(combo.capitalize())
                add(combo.title())
                for suffix in ["1", "123", "!", "2024", "2025"]:
                    add(combo + suffix)

    # Add number patterns
    for np in NUMBER_PATTERNS:
        add(np)

    # Write output
    with open(output_path, "w") as f:
        for pw in passwords:
            f.write(pw + "\n")

    print_success(f"Generated {len(passwords):,} targeted passwords")
    print_info(f"  Output: {output_path}")
    return output_path


def _generate_variants(word):
    """Generate case and leet-speak variants of a word."""
    variants = set()

    # Case variants
    variants.add(word)
    variants.add(word.lower())
    variants.add(word.upper())
    variants.add(word.capitalize())
    variants.add(word.title())
    variants.add(word.swapcase())

    # First letter uppercase, rest lower
    if len(word) > 1:
        variants.add(word[0].upper() + word[1:].lower())

    # Leet speak
    leet_map = {"a": "@", "e": "3", "i": "1", "o": "0", "s": "$", "t": "7"}
    leet = word.lower()
    for orig, repl in leet_map.items():
        leet = leet.replace(orig, repl)
    if leet != word.lower():
        variants.add(leet)

    # Partial leet (just a->@)
    variants.add(word.lower().replace("a", "@"))
    variants.add(word.lower().replace("e", "3"))
    variants.add(word.lower().replace("o", "0"))

    return list(variants)


def interactive_generate():
    """Interactive targeted wordlist generator - prompts for OSINT info."""
    print(f"\n{Colors.BOLD}Targeted Wordlist Generator{Colors.RESET}")
    print(f"{Colors.CYAN}Enter information about the target (leave blank to skip){Colors.RESET}\n")

    keywords = []

    prompts = [
        ("Company/Business name", "e.g., AcmeCorp"),
        ("Owner/Family name(s)", "e.g., Smith, Johnson"),
        ("Street address", "e.g., MainStreet, 42Oak"),
        ("City/Region", "e.g., Springfield"),
        ("Phone number(s)", "e.g., 5551234, 5559876"),
        ("Pet name(s)", "e.g., Buddy, Max"),
        ("Router brand/model", "e.g., Netgear, TP-Link"),
        ("SSID name", "e.g., HomeNetwork"),
        ("Other keywords", "e.g., favorite team, hobby"),
    ]

    for prompt, example in prompts:
        try:
            answer = input(f"  {Colors.CYAN}{prompt}{Colors.RESET} ({example}): ").strip()
            if answer:
                # Split comma-separated values
                for part in answer.split(","):
                    part = part.strip()
                    if part:
                        keywords.append(part)
        except (EOFError, KeyboardInterrupt):
            print()
            break

    if not keywords:
        print_warning("No keywords entered.")
        return None

    print()
    return generate_targeted_wordlist(keywords)
