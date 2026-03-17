"""Rule-based wordlist mutations for improved cracking success rate.

Generates mutated wordlists and hashcat rule files that apply common
password patterns (appending numbers, capitalization, leet speak, etc.)
to increase the effective size of a wordlist without needing a larger file.
"""

import os
import itertools
import tempfile
from datetime import datetime

from config import MUTATIONS_DIR
from utils import print_status, print_success, print_info, print_warning, Colors


# Common hashcat rule operations:
# c = capitalize first letter
# u = uppercase all
# l = lowercase all
# t = toggle case of all chars
# $X = append character X
# ^X = prepend character X
# r = reverse
# d = duplicate
# sa@ = substitute 'a' with '@'
# se3 = substitute 'e' with '3'
# etc.

# Built-in rule sets
BASIC_RULES = [
    "",             # Original word
    "c",            # Capitalize first
    "u",            # All uppercase
    "$1",           # Append 1
    "$!",           # Append !
    "c$1",          # Capitalize + append 1
    "$1$2$3",       # Append 123
    "r",            # Reverse
]

COMMON_APPEND_RULES = [
    f"${d}" for d in "0123456789"
] + [
    f"${d1}${d2}" for d1 in "0123456789" for d2 in "0123456789"
] + [
    "$!",
    "$@",
    "$#",
    "$$",
    "$.",
    "$!$!",
]

LEET_SPEAK_RULES = [
    "sa@",          # a -> @
    "se3",          # e -> 3
    "si1",          # i -> 1
    "so0",          # o -> 0
    "ss$",          # s -> $
    "st7",          # t -> 7
    "sa@se3",       # a -> @, e -> 3
    "sa@se3si1so0", # Full leet
]

CAPITALIZATION_RULES = [
    "c",            # First letter uppercase
    "C",            # First letter lowercase, rest uppercase
    "t",            # Toggle all
    "T0",           # Toggle position 0
    "T1",           # Toggle position 1
    "T0T1",         # Toggle positions 0 and 1
]

YEAR_SUFFIX_RULES = [
    f"${y[0]}${y[1]}${y[2]}${y[3]}"
    for y in [str(yr) for yr in range(2015, 2027)]
]

# Preset rule combinations
PRESETS = {
    "light": {
        "description": "Basic mutations (capitalize, append digits, common symbols)",
        "rules": BASIC_RULES + COMMON_APPEND_RULES[:12],
    },
    "moderate": {
        "description": "Moderate mutations (light + leet speak, years, more symbols)",
        "rules": (BASIC_RULES + COMMON_APPEND_RULES +
                  LEET_SPEAK_RULES + YEAR_SUFFIX_RULES[:6]),
    },
    "aggressive": {
        "description": "Aggressive mutations (all rules combined, ~500+ rules)",
        "rules": (BASIC_RULES + COMMON_APPEND_RULES +
                  LEET_SPEAK_RULES + CAPITALIZATION_RULES +
                  YEAR_SUFFIX_RULES),
    },
}


def generate_hashcat_rules(preset="moderate", output_path=None):
    """Generate a hashcat-compatible rules file.

    Args:
        preset: One of 'light', 'moderate', 'aggressive'.
        output_path: Where to save the rules file. Auto-generated if None.

    Returns:
        str: Path to the generated rules file.
    """
    if preset not in PRESETS:
        print_warning(f"Unknown preset '{preset}'. Using 'moderate'.")
        preset = "moderate"

    config = PRESETS[preset]
    rules = config["rules"]

    if not output_path:
        output_path = os.path.join(MUTATIONS_DIR, f"rules_{preset}.rule")

    with open(output_path, "w") as f:
        for rule in rules:
            f.write(rule + "\n")

    print_success(f"Generated {len(rules)} hashcat rules ({preset})")
    print_info(f"  File: {output_path}")
    print_info(f"  Description: {config['description']}")
    return output_path


def generate_mutated_wordlist(wordlist_path, preset="moderate", output_path=None):
    """Generate a mutated wordlist by applying rules to each word.

    This is for use with aircrack-ng which doesn't support rule files.
    For hashcat, use generate_hashcat_rules() instead (more efficient).

    Args:
        wordlist_path: Path to the original wordlist.
        preset: Mutation preset to use.
        output_path: Where to save. Auto-generated if None.

    Returns:
        str: Path to the mutated wordlist.
    """
    if not os.path.isfile(wordlist_path):
        print_warning(f"Wordlist not found: {wordlist_path}")
        return None

    if not output_path:
        base = os.path.splitext(os.path.basename(wordlist_path))[0]
        output_path = os.path.join(
            MUTATIONS_DIR,
            f"{base}_mutated_{preset}.txt"
        )

    print_status(f"Generating mutated wordlist ({preset})...")
    print_info(f"  Source: {wordlist_path}")

    count = 0
    seen = set()

    with open(wordlist_path, "r", errors="ignore") as fin, \
         open(output_path, "w") as fout:

        for line in fin:
            word = line.strip()
            if not word or len(word) < 4:
                continue

            mutations = _apply_mutations(word, preset)
            for mutated in mutations:
                if mutated not in seen:
                    seen.add(mutated)
                    fout.write(mutated + "\n")
                    count += 1

    print_success(f"Generated {count:,} mutated passwords")
    print_info(f"  Output: {output_path}")
    return output_path


def _apply_mutations(word, preset="moderate"):
    """Apply mutation rules to a single word.

    Args:
        word: The base word to mutate.
        preset: Which mutation level to apply.

    Returns:
        list: List of mutated strings.
    """
    results = [word]

    # Capitalization variants
    results.append(word.capitalize())
    results.append(word.upper())
    results.append(word.lower())
    results.append(word.swapcase())

    # Append common numbers
    for n in ["1", "12", "123", "1234", "!", "!!", "69", "007"]:
        results.append(word + n)
        results.append(word.capitalize() + n)

    if preset in ("moderate", "aggressive"):
        # Year suffixes
        for year in range(2018, 2027):
            results.append(word + str(year))
            results.append(word.capitalize() + str(year))

        # Leet speak
        leet_map = {"a": "@", "e": "3", "i": "1", "o": "0", "s": "$", "t": "7"}
        leet = word
        for orig, repl in leet_map.items():
            leet = leet.replace(orig, repl)
        if leet != word:
            results.append(leet)
            results.append(leet.capitalize())

        # Common separators + numbers
        for sep in ["_", "-", ".", "@"]:
            for n in ["1", "123", "!"]:
                results.append(word + sep + n)

    if preset == "aggressive":
        # Reversed
        results.append(word[::-1])
        results.append(word + word)

        # Two-digit suffixes
        for n in range(100):
            results.append(word + str(n).zfill(2))

        # Prefix numbers
        for n in range(10):
            results.append(str(n) + word)

    return results


def list_presets():
    """Print available mutation presets."""
    print(f"\n{Colors.BOLD}Available mutation presets:{Colors.RESET}\n")
    for name, config in PRESETS.items():
        rule_count = len(config["rules"])
        print(f"  {Colors.CYAN}{name:<15s}{Colors.RESET} "
              f"{config['description']} ({rule_count} rules)")
    print()
