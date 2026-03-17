#!/usr/bin/env python3
"""LAN Packet Cracker - WPA/WPA2 Handshake Capture & Cracking Tool.

A wireless security auditing tool for educational and authorized testing.
Supports: network scanning, deauth attacks, handshake capture, PMKID attacks,
aircrack-ng/hashcat cracking, mask attacks, combo attacks, rule-based mutations,
multi-wordlist support, session resume, and detailed reporting.
"""

import argparse
import signal
import sys
import time

from utils import (
    print_banner, print_disclaimer, require_root,
    print_status, print_success, print_error, print_warning, print_info, Colors
)
from config import CAPTURES_DIR
from monitor import MonitorMode
from scanner import NetworkScanner
from deauth import DeauthAttack, MultiClientDeauth
from capture import HandshakeCapture, PassiveCapture
from mac_changer import change_mac, restore_mac, print_mac_info
from cracker import AircrackCracker
from hashcat_cracker import HashcatCracker
from validator import HandshakeValidator
from pmkid import PMKIDAttack
from mutations import generate_hashcat_rules, generate_mutated_wordlist, list_presets
from wordlists import (
    list_available as list_wordlists, download_wordlist, download_all as download_all_wordlists,
    merge_wordlists, get_wordlist_path
)
from reporter import AttackReporter, list_reports
from wps_attack import WPSScanner, WPSAttack
from pmk_precomp import PMKPrecomputer, list_databases as list_pmk_databases
from evil_twin import EvilTwin
from target_wordlist import generate_targeted_wordlist, interactive_generate as interactive_targetwl


# Global monitor mode instance for cleanup on exit
_monitor = None


def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully."""
    print(f"\n{Colors.YELLOW}[!] Interrupted. Cleaning up...{Colors.RESET}")
    if _monitor:
        _monitor.disable()
    sys.exit(0)


# ─── SCAN ────────────────────────────────────────────────────────────────

def cmd_scan(args):
    """Scan for wireless networks (with WPA3 detection)."""
    global _monitor
    _original_mac = None

    mon = MonitorMode(args.interface)
    _monitor = mon

    iface = mon.enable()
    if not iface:
        return

    try:
        # MAC randomization if requested
        if hasattr(args, 'randomize_mac') and args.randomize_mac:
            _original_mac, _ = change_mac(iface, preserve_vendor=True)

        band = getattr(args, 'band', 'all') or 'all'
        mon.start_channel_hop(band=band)
        scanner = NetworkScanner(iface)
        scanner.scan(timeout=args.timeout)
        mon.stop_channel_hop()
        scanner.print_results(sort_by_signal=True)
    finally:
        if _original_mac:
            restore_mac(iface, _original_mac)
        mon.disable()


# ─── DEAUTH ──────────────────────────────────────────────────────────────

def cmd_deauth(args):
    """Send deauthentication frames."""
    global _monitor
    mon = MonitorMode(args.interface)
    _monitor = mon

    iface = mon.enable()
    if not iface:
        return

    try:
        if args.channel:
            mon.set_channel(args.channel)
        elif not hasattr(args, 'no_auto_channel') or not args.no_auto_channel:
            # Auto-detect channel for target BSSID
            scanner = NetworkScanner(iface)
            ch = scanner.quick_channel_detect(args.bssid, timeout=10)
            if ch:
                mon.set_channel(ch)
                print_info(f"Auto-detected channel: {ch}")

        evasion = getattr(args, 'evasion', False)

        if args.all_clients:
            print_warning("--all-clients requires known clients. Using broadcast as base.")
            if args.client and "," in args.client:
                clients = [c.strip() for c in args.client.split(",")]
                multi = MultiClientDeauth(iface, args.bssid, clients)
                multi.start(count=args.count, bursts=args.bursts)
            else:
                attack = DeauthAttack(iface, args.bssid, client=args.client,
                                      evasion=evasion)
                attack.start(count=args.count, bursts=args.bursts)
        else:
            attack = DeauthAttack(iface, args.bssid, client=args.client,
                                  evasion=evasion)
            attack.start(count=args.count, bursts=args.bursts)
    finally:
        mon.disable()


# ─── CAPTURE ─────────────────────────────────────────────────────────────

def cmd_capture(args):
    """Capture WPA handshake."""
    global _monitor
    mon = MonitorMode(args.interface)
    _monitor = mon

    iface = mon.enable()
    if not iface:
        return

    try:
        # Auto-detect channel if not specified
        if args.channel:
            mon.set_channel(args.channel)
        else:
            scanner = NetworkScanner(iface)
            ch = scanner.quick_channel_detect(args.bssid, timeout=10)
            if ch:
                mon.set_channel(ch)
                print_info(f"Auto-detected channel: {ch}")

        # Passive or active capture
        passive = getattr(args, 'passive', False)
        if passive:
            cap = PassiveCapture(iface, bssid=args.bssid, ssid=args.ssid or "unknown")
        else:
            cap = HandshakeCapture(iface, args.bssid, ssid=args.ssid or "unknown")

        pcap_path = cap.capture(timeout=args.timeout)
        if pcap_path:
            print_info(f"Capture file: {pcap_path}")
            if args.validate:
                print()
                HandshakeValidator(pcap_path, bssid=args.bssid).validate()
    finally:
        mon.disable()


# ─── PMKID ───────────────────────────────────────────────────────────────

def cmd_pmkid(args):
    """Execute PMKID attack (clientless capture)."""
    global _monitor
    mon = MonitorMode(args.interface)
    _monitor = mon

    iface = mon.enable()
    if not iface:
        return

    try:
        if args.channel:
            mon.set_channel(args.channel)

        pmkid = PMKIDAttack(iface, args.bssid, ssid=args.ssid or "unknown")
        pcap_path = pmkid.capture(timeout=args.timeout)

        if pcap_path and args.wordlist:
            print()
            print_status("Cracking PMKID with hashcat...")
            cracker = HashcatCracker(pcap_path, bssid=args.bssid)
            if cracker.convert_to_hc22000():
                cracker.crack(wordlist=args.wordlist)
    finally:
        mon.disable()


# ─── VALIDATE ────────────────────────────────────────────────────────────

def cmd_validate(args):
    """Validate a capture file before cracking."""
    validator = HandshakeValidator(args.pcap, bssid=args.bssid)
    result = validator.validate()

    if result["valid"]:
        print_success("Capture is valid and ready for cracking.")
        if result["score"] >= 70:
            print_info("Recommended: proceed with cracking.")
        else:
            print_warning("Quality is marginal. Consider re-capturing for better results.")
    else:
        print_error("Capture is NOT suitable for cracking.")
        print_info("Re-capture the handshake with a better signal or closer proximity.")


# ─── CRACK ───────────────────────────────────────────────────────────────

def cmd_crack(args):
    """Crack a captured handshake with aircrack-ng or hashcat."""
    reporter = AttackReporter() if args.report else None

    # Step 1: Validate
    if not args.skip_validation:
        if reporter:
            reporter.start_phase("validation")
        print_status("Validating capture file...")
        validator = HandshakeValidator(args.pcap, bssid=args.bssid)
        result = validator.validate()
        if reporter:
            reporter.end_phase(success=result["valid"],
                               details=reporter.log_validation_result(result) if reporter else {})

        if not result["valid"]:
            print_error("Capture validation FAILED.")
            confirm = input(f"{Colors.YELLOW}Try cracking anyway? [y/N]: {Colors.RESET}")
            if confirm.lower() != 'y':
                if reporter:
                    reporter.set_result(False)
                    reporter.finish()
                return

    if args.verify:
        return

    # Handle mask attack (no wordlist needed)
    if args.mask:
        if reporter:
            reporter.start_phase("crack_mask")
        cracker = HashcatCracker(args.pcap, bssid=args.bssid)
        password = cracker.mask_attack(mask=args.mask)
        if reporter:
            reporter.end_phase(success=password is not None,
                               details={"engine": "hashcat", "attack": "mask", "mask": args.mask})
            reporter.set_result(password is not None, password)
            reporter.finish()
        return

    # Handle combo attack
    if args.combo:
        parts = args.combo.split(",")
        if len(parts) != 2:
            print_error("--combo requires two wordlists separated by comma")
            return
        wl1, wl2 = get_wordlist_path(parts[0].strip()), get_wordlist_path(parts[1].strip())
        if not wl1 or not wl2:
            return
        if reporter:
            reporter.start_phase("crack_combo")
        cracker = HashcatCracker(args.pcap, bssid=args.bssid)
        password = cracker.combo_attack(wl1, wl2)
        if reporter:
            reporter.end_phase(success=password is not None,
                               details={"engine": "hashcat", "attack": "combo"})
            reporter.set_result(password is not None, password)
            reporter.finish()
        return

    # Handle hybrid attack (wordlist + mask)
    if args.hybrid:
        parts = args.hybrid.split(",")
        if len(parts) != 2:
            print_error("--hybrid requires wordlist,mask (e.g. wordlist.txt,?d?d?d?d)")
            return
        wl = get_wordlist_path(parts[0].strip())
        mask = parts[1].strip()
        if not wl:
            return
        hybrid_mode = args.hybrid_mode if hasattr(args, 'hybrid_mode') and args.hybrid_mode else 6
        if reporter:
            reporter.start_phase("crack_hybrid")
        cracker = HashcatCracker(args.pcap, bssid=args.bssid)
        password = cracker.hybrid_attack(wl, mask, mode=hybrid_mode)
        if reporter:
            reporter.end_phase(success=password is not None,
                               details={"engine": "hashcat", "attack": "hybrid",
                                        "mode": hybrid_mode, "mask": mask})
            reporter.set_result(password is not None, password)
            reporter.finish()
        return

    # Handle PRINCE attack
    if getattr(args, 'prince', None):
        wl = get_wordlist_path(args.prince)
        if not wl:
            return
        if reporter:
            reporter.start_phase("crack_prince")
        cracker = HashcatCracker(args.pcap, bssid=args.bssid)
        password = cracker.prince_attack(wl)
        if reporter:
            reporter.end_phase(success=password is not None,
                               details={"engine": "hashcat", "attack": "prince"})
            reporter.set_result(password is not None, password)
            reporter.finish()
        return

    # Handle session restore
    if args.restore:
        cracker = HashcatCracker(args.pcap, bssid=args.bssid)
        password = cracker.crack_with_session(
            wordlist="", session_name=args.session or "wpa_session", restore=True)
        return

    # Standard wordlist attack
    if not args.wordlist:
        print_error("Wordlist required. Use -w <path> or --mask for brute-force.")
        return

    # Resolve wordlists (support multiple via comma separation)
    wordlist_inputs = [w.strip() for w in args.wordlist.split(",")]
    wordlists = []
    for w in wordlist_inputs:
        resolved = get_wordlist_path(w)
        if resolved:
            wordlists.append(resolved)
    if not wordlists:
        print_error("No valid wordlists found.")
        return

    # Merge if multiple wordlists for aircrack, or keep list for iteration
    if len(wordlists) > 1:
        print_info(f"Using {len(wordlists)} wordlists")

    # Generate mutations
    rules_file = None
    wordlist_for_crack = wordlists[0] if len(wordlists) == 1 else None

    if args.mutate:
        print_status(f"Applying '{args.mutate}' mutations...")
        if args.engine == "hashcat":
            rules_file = generate_hashcat_rules(preset=args.mutate)
        elif len(wordlists) == 1:
            mutated = generate_mutated_wordlist(wordlists[0], preset=args.mutate)
            if mutated:
                wordlist_for_crack = mutated

    # Crack
    print()
    if reporter:
        reporter.start_phase("crack")

    crack_start = time.time()
    password = None

    if args.engine == "hashcat":
        cracker = HashcatCracker(args.pcap, bssid=args.bssid)
        if not cracker.convert_to_hc22000():
            print_error("Failed to convert capture for hashcat.")
            print_info("Falling back to aircrack-ng...")
            cracker_ac = AircrackCracker(args.pcap, bssid=args.bssid)
            if len(wordlists) > 1:
                password = cracker_ac.crack(wordlists)
            else:
                password = cracker_ac.crack(wordlist_for_crack or wordlists[0])
        else:
            if args.session:
                password = cracker.crack_with_session(
                    wordlist=wordlists[0], session_name=args.session,
                    rules_file=rules_file)
            else:
                # Try each wordlist in sequence
                for i, wl in enumerate(wordlists):
                    if password:
                        break
                    if len(wordlists) > 1:
                        print_status(f"Wordlist {i + 1}/{len(wordlists)}: {wl}")
                    password = cracker.crack(wordlist=wl, rules_file=rules_file)
    else:
        print_status("Using aircrack-ng (CPU)...")
        cracker = AircrackCracker(args.pcap, bssid=args.bssid)
        if len(wordlists) > 1:
            # aircrack-ng supports comma-separated wordlists natively
            password = cracker.crack(wordlists)
        else:
            password = cracker.crack(wordlist_for_crack or wordlists[0])

    crack_duration = time.time() - crack_start

    if reporter:
        reporter.end_phase(
            success=password is not None,
            details=reporter.log_crack_result(
                engine=args.engine, wordlist=args.wordlist,
                password=password, duration=crack_duration,
                mutate_preset=args.mutate))
        reporter.set_result(password is not None, password)
        reporter.finish()


# ─── MUTATE ──────────────────────────────────────────────────────────────

def cmd_mutate(args):
    """Generate mutated wordlists or hashcat rule files."""
    if args.list_presets:
        list_presets()
        return

    if not args.wordlist:
        print_error("Wordlist required. Use --wordlist <path>")
        return

    if args.rules_only:
        generate_hashcat_rules(preset=args.preset, output_path=args.output)
    else:
        generate_mutated_wordlist(args.wordlist, preset=args.preset, output_path=args.output)


# ─── WORDLIST ────────────────────────────────────────────────────────────

def cmd_wordlist(args):
    """Manage wordlists - list, download, merge."""
    if args.list:
        list_wordlists()
    elif args.download:
        if args.download == "all":
            download_all_wordlists()
        else:
            download_wordlist(args.download)
    elif args.merge:
        paths = [get_wordlist_path(w.strip()) for w in args.merge.split(",")]
        paths = [p for p in paths if p]
        if paths:
            merge_wordlists(paths, output_path=args.output)


# ─── AUTO ────────────────────────────────────────────────────────────────

def cmd_auto(args):
    """Full automated pipeline with retry loop and reporting."""
    global _monitor
    mon = MonitorMode(args.interface)
    _monitor = mon

    reporter = AttackReporter()
    engine_label = "hashcat (GPU)" if args.engine == "hashcat" else "aircrack-ng (CPU)"
    max_retries = args.retries

    # Step 1: Enable monitor mode
    reporter.start_phase("monitor_mode")
    print_status("Step 1: Enabling monitor mode...")
    iface = mon.enable()
    if not iface:
        reporter.end_phase(success=False, errors=["Failed to enable monitor mode"])
        reporter.set_result(False)
        reporter.finish()
        return
    reporter.end_phase(success=True)

    try:
        # Step 2: Scan
        reporter.start_phase("scan")
        print_status("Step 2: Scanning for networks...")
        mon.start_channel_hop()
        scanner = NetworkScanner(iface)
        scanner.scan(timeout=args.scan_timeout)
        mon.stop_channel_hop()

        if not scanner.access_points:
            print_error("No networks found.")
            reporter.end_phase(success=False, errors=["No networks found"])
            reporter.set_result(False)
            reporter.finish()
            return

        reporter.end_phase(success=True,
                           details=reporter.log_scan_results(scanner.access_points))

        # Step 3: Select target
        print_status("Step 3: Select target network...")
        target = scanner.select_target()
        if not target:
            print_warning("No target selected.")
            reporter.set_result(False)
            reporter.finish()
            return

        reporter.set_target(
            bssid=target.bssid, ssid=target.ssid,
            channel=target.channel, encryption=target.encryption,
            clients=target.clients)

        mon.set_channel(target.channel)

        # Step 4: Capture (with retry loop)
        pcap_path = None
        validation_result = None

        for attempt in range(1, max_retries + 1):
            if attempt > 1:
                print_warning(f"Retry {attempt}/{max_retries}...")

            reporter.start_phase(f"capture_attempt_{attempt}")

            # Try PMKID first if requested
            if args.pmkid and not pcap_path:
                print_status(f"Step 4: Attempting PMKID capture (attempt {attempt})...")
                pmkid_attack = PMKIDAttack(iface, target.bssid, ssid=target.ssid)
                pcap_path = pmkid_attack.capture(timeout=args.capture_timeout // 2)

                if pcap_path:
                    reporter.end_phase(success=True,
                                       details={"method": "pmkid", "pcap": pcap_path})
                    break

            # Traditional deauth + handshake
            if not pcap_path:
                print_status(f"Step 4: Capturing handshake (attempt {attempt})...")
                cap = HandshakeCapture(iface, target.bssid, ssid=target.ssid)
                cap.capture_async(timeout=args.capture_timeout)
                time.sleep(1)

                # Multi-client or single deauth
                if len(target.clients) > 1 and args.multi_deauth:
                    multi = MultiClientDeauth(iface, target.bssid, target.clients)
                    multi.start(blocking=True)
                else:
                    client = list(target.clients)[0] if target.clients else None
                    attack = DeauthAttack(iface, target.bssid, client=client)
                    attack.start(blocking=True)

                print_status("Waiting for handshake capture...")
                cap.wait(timeout=args.capture_timeout)
                pcap_path = cap.pcap_path

            if not pcap_path:
                reporter.end_phase(success=False, errors=["No capture"])
                continue

            # Validate capture quality
            print_status("Step 5: Validating capture...")
            validator = HandshakeValidator(pcap_path, bssid=target.bssid)
            validation_result = validator.validate()

            if validation_result["score"] >= 40:
                reporter.end_phase(success=True,
                                   details={"pcap": pcap_path,
                                            "score": validation_result["score"]})
                break
            else:
                print_warning(f"Capture quality too low (score: {validation_result['score']}). Retrying...")
                reporter.end_phase(success=False,
                                   errors=[f"Low quality score: {validation_result['score']}"])
                pcap_path = None  # Reset to try again

        if not pcap_path:
            print_error("Failed to capture a usable handshake after all retries.")
            reporter.set_result(False)
            reporter.finish()
            return

        # Step 6: Crack
        if args.wordlist:
            reporter.start_phase("crack")
            print_status(f"Step 6: Cracking password ({engine_label})...")

            # Resolve wordlists
            wordlist_inputs = [w.strip() for w in args.wordlist.split(",")]
            wordlists = [get_wordlist_path(w) for w in wordlist_inputs]
            wordlists = [w for w in wordlists if w]

            if not wordlists:
                print_error("No valid wordlists found.")
                reporter.end_phase(success=False, errors=["No wordlists"])
                reporter.set_result(False)
                reporter.finish()
                return

            # Mutations
            rules_file = None
            if args.mutate:
                if args.engine == "hashcat":
                    rules_file = generate_hashcat_rules(preset=args.mutate)
                else:
                    mutated = generate_mutated_wordlist(wordlists[0], preset=args.mutate)
                    if mutated:
                        wordlists = [mutated] + wordlists[1:]

            crack_start = time.time()
            password = None

            if args.engine == "hashcat":
                cracker = HashcatCracker(pcap_path, bssid=target.bssid)
                if cracker.convert_to_hc22000():
                    for wl in wordlists:
                        password = cracker.crack(wordlist=wl, rules_file=rules_file)
                        if password:
                            break

                    # If dictionary failed, try mask attack for 8-digit PINs
                    if not password and args.mask:
                        print_status("Dictionary failed. Trying mask attack...")
                        password = cracker.mask_attack(mask=args.mask)
                else:
                    cracker_ac = AircrackCracker(pcap_path, bssid=target.bssid)
                    password = cracker_ac.crack(wordlists if len(wordlists) > 1 else wordlists[0])
            else:
                cracker = AircrackCracker(pcap_path, bssid=target.bssid)
                password = cracker.crack(wordlists if len(wordlists) > 1 else wordlists[0])

            crack_duration = time.time() - crack_start
            reporter.end_phase(
                success=password is not None,
                details=reporter.log_crack_result(
                    engine=args.engine, wordlist=args.wordlist,
                    password=password, duration=crack_duration,
                    mutate_preset=args.mutate, mask=args.mask))

            reporter.set_result(password is not None, password)

            if password:
                print()
                print(f"{Colors.BOLD}{Colors.GREEN}{'=' * 50}")
                print(f" Network:  {target.ssid}")
                print(f" BSSID:    {target.bssid}")
                print(f" Password: {password}")
                print(f" Engine:   {engine_label}")
                print(f"{'=' * 50}{Colors.RESET}")
        else:
            print_warning("No wordlist provided. Skipping cracking step.")
            print_info(f"To crack later: python main.py crack --pcap {pcap_path} -w <path>")
            reporter.set_result(False)

        reporter.finish()

    finally:
        mon.disable()


# ─── REPORTS ─────────────────────────────────────────────────────────────

def cmd_reports(args):
    """List or view reports."""
    if args.view:
        from reporter import load_report
        data = load_report(args.view)
        if data:
            import json
            print(json.dumps(data, indent=2, default=str))
    else:
        list_reports()


# ─── BENCHMARK ───────────────────────────────────────────────────────────

def cmd_benchmark(args):
    """Run hashcat benchmark to show GPU cracking speed."""
    cracker = HashcatCracker(pcap_path="/dev/null")
    cracker.benchmark()


# ─── MAC ─────────────────────────────────────────────────────────────────

def cmd_mac(args):
    """MAC address management - randomize, set, or restore."""
    if args.show:
        print_mac_info(args.interface)
    elif args.random:
        change_mac(args.interface, preserve_vendor=args.preserve_vendor)
    elif args.set:
        change_mac(args.interface, new_mac=args.set)
    elif args.restore:
        restore_mac(args.interface, args.restore)
    else:
        print_mac_info(args.interface)


# ─── WPS ─────────────────────────────────────────────────────────────────

def cmd_wps(args):
    """WPS PIN attack - brute-force WPS to recover WPA password."""
    global _monitor
    mon = MonitorMode(args.interface)
    _monitor = mon

    iface = mon.enable()
    if not iface:
        return

    try:
        if args.channel:
            mon.set_channel(args.channel)

        if args.scan_only:
            scanner = WPSScanner(iface)
            scanner.scan(timeout=args.timeout)
            scanner.print_results()
            return

        if not args.bssid:
            print_error("Target BSSID required. Use -b <BSSID> or --scan-only to find targets.")
            return

        attack = WPSAttack(iface, args.bssid, channel=args.channel, ssid=args.ssid)

        if args.pin:
            # Try a specific known PIN
            pin, password = attack.attack_reaver(pin=args.pin)
        elif args.pixie_only:
            # Only try Pixie Dust (fast offline attack)
            pin, password = attack.attack_reaver(pixie_dust=True, timeout=120)
        else:
            # Full attack: Pixie Dust first, then brute-force
            pin, password = attack.attack(
                pixie_dust=not args.no_pixie,
                delay=args.delay,
                timeout=args.timeout
            )

        if password:
            print()
            print(f"{Colors.BOLD}{Colors.GREEN}{'=' * 50}")
            print(f"  WPS PIN: {pin}")
            print(f"  Password: {password}")
            print(f"{'=' * 50}{Colors.RESET}")

    finally:
        mon.disable()


# ─── PRECOMPUTE ──────────────────────────────────────────────────────────

def cmd_precompute(args):
    """Precompute PMK hash tables for faster cracking."""
    if args.list:
        list_pmk_databases()
        return

    if not args.ssid:
        print_error("SSID required. Use --ssid <name>")
        return

    precomp = PMKPrecomputer(args.ssid, db_path=args.db)

    if args.crack:
        # Crack using existing precomputed database
        precomp.crack(args.crack, bssid=args.bssid)
    elif args.stats:
        precomp.stats()
    else:
        if not args.wordlist:
            print_error("Wordlist required for precomputation. Use -w <path>")
            return
        wl = get_wordlist_path(args.wordlist)
        if wl:
            precomp.precompute(wl)


# ─── EVIL TWIN ───────────────────────────────────────────────────────────

def cmd_eviltwin(args):
    """Evil Twin / Rogue AP attack with captive portal."""
    if not args.bssid or not args.ssid or not args.channel:
        print_error("Required: --bssid, --ssid, and --channel")
        return

    if not args.ap_interface or not args.deauth_interface:
        print_error("Evil Twin requires two interfaces:")
        print_info("  --ap-interface:    Creates the rogue AP (needs AP mode support)")
        print_info("  --deauth-interface: Sends deauth frames (needs monitor mode)")
        return

    twin = EvilTwin(
        ap_interface=args.ap_interface,
        deauth_interface=args.deauth_interface,
        target_bssid=args.bssid,
        target_ssid=args.ssid,
        target_channel=args.channel,
    )

    twin.start(deauth_continuous=not args.no_deauth)


# ─── TARGET WORDLIST ─────────────────────────────────────────────────────

def cmd_targetwl(args):
    """Generate targeted OSINT-based wordlist."""
    if args.interactive:
        interactive_targetwl()
        return

    if not args.keywords:
        print_error("Provide keywords with --keywords or use --interactive")
        return

    keywords = [k.strip() for k in args.keywords.split(",")]
    generate_targeted_wordlist(
        keywords,
        output_path=args.output,
        include_wifi_patterns=not args.no_wifi_patterns,
    )


# ─── CLI SETUP ───────────────────────────────────────────────────────────

def main():
    """Main entry point."""
    signal.signal(signal.SIGINT, signal_handler)

    parser = argparse.ArgumentParser(
        description="LAN Packet Cracker - WPA/WPA2 Security Auditing Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s scan -i wlan0 --band 5
  %(prog)s scan -i wlan0 --randomize-mac
  %(prog)s deauth -i wlan0mon -b AA:BB:CC:DD:EE:FF --all-clients --evasion
  %(prog)s capture -i wlan0mon -b AA:BB:CC:DD:EE:FF --passive
  %(prog)s capture -i wlan0mon -b AA:BB:CC:DD:EE:FF -c 6 --validate
  %(prog)s pmkid -i wlan0mon -b AA:BB:CC:DD:EE:FF -c 6
  %(prog)s validate --pcap captures/handshake.pcap
  %(prog)s crack --pcap capture.pcap -w rockyou,wifi-passwords --engine hashcat
  %(prog)s crack --pcap capture.pcap --mask "?d?d?d?d?d?d?d?d"
  %(prog)s crack --pcap capture.pcap --combo "words.txt,numbers.txt"
  %(prog)s crack --pcap capture.pcap -w wordlist.txt --session my_session
  %(prog)s crack --pcap capture.pcap --restore --session my_session
  %(prog)s wordlist --list
  %(prog)s wordlist --download rockyou
  %(prog)s crack --pcap capture.pcap --hybrid "rockyou,?d?d?d?d" --hybrid-mode 6
  %(prog)s auto -i wlan0 -w rockyou --engine hashcat --mutate moderate --retries 3
  %(prog)s wps -i wlan0mon --scan-only
  %(prog)s wps -i wlan0mon -b AA:BB:CC:DD:EE:FF --pixie-only
  %(prog)s precompute --ssid "HomeNetwork" -w rockyou
  %(prog)s precompute --ssid "HomeNetwork" --crack captures/handshake.pcap
  %(prog)s eviltwin --ap-interface wlan1 --deauth-interface wlan0mon -b AA:BB:CC:DD:EE:FF -s MyWiFi -c 6
  %(prog)s targetwl --interactive
  %(prog)s targetwl --keywords "AcmeCorp,Smith,MainStreet,Springfield"
  %(prog)s crack --pcap capture.pcap --prince rockyou
  %(prog)s mac -i wlan0 --random --preserve-vendor
  %(prog)s reports
"""
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # --- scan ---
    scan_p = subparsers.add_parser("scan", help="Scan for wireless networks (detects WPA3)")
    scan_p.add_argument("-i", "--interface", help="Wireless interface")
    scan_p.add_argument("-t", "--timeout", type=int, default=30, help="Scan timeout (seconds)")
    scan_p.add_argument("--band", choices=["2.4", "5", "all"], default="all",
                        help="Frequency band to scan (default: all)")
    scan_p.add_argument("--randomize-mac", action="store_true",
                        help="Randomize MAC address before scanning")

    # --- deauth ---
    deauth_p = subparsers.add_parser("deauth", help="Send deauthentication frames")
    deauth_p.add_argument("-i", "--interface", help="Monitor mode interface")
    deauth_p.add_argument("-b", "--bssid", required=True, help="Target AP BSSID")
    deauth_p.add_argument("--client", help="Target client MAC(s) - comma-separated for multiple")
    deauth_p.add_argument("-c", "--channel", type=int, help="Channel number")
    deauth_p.add_argument("--count", type=int, default=50, help="Packets per burst")
    deauth_p.add_argument("--bursts", type=int, default=5, help="Number of bursts")
    deauth_p.add_argument("--all-clients", action="store_true",
                          help="Deauth all known clients (provide via --client as comma list)")
    deauth_p.add_argument("--evasion", action="store_true",
                          help="Enable IDS evasion (random jitter, reason rotation)")

    # --- capture ---
    capture_p = subparsers.add_parser("capture", help="Capture WPA handshake")
    capture_p.add_argument("-i", "--interface", help="Monitor mode interface")
    capture_p.add_argument("-b", "--bssid", required=True, help="Target AP BSSID")
    capture_p.add_argument("-s", "--ssid", help="Target SSID (for filename)")
    capture_p.add_argument("-c", "--channel", type=int, help="Channel number")
    capture_p.add_argument("-t", "--timeout", type=int, default=60, help="Capture timeout (seconds)")
    capture_p.add_argument("--validate", action="store_true", help="Validate capture after saving")
    capture_p.add_argument("--passive", action="store_true",
                           help="Passive capture - no deauth, wait for natural reconnections (stealth)")

    # --- pmkid ---
    pmkid_p = subparsers.add_parser("pmkid", help="PMKID attack (no client needed)")
    pmkid_p.add_argument("-i", "--interface", help="Monitor mode interface")
    pmkid_p.add_argument("-b", "--bssid", required=True, help="Target AP BSSID")
    pmkid_p.add_argument("-s", "--ssid", help="Target SSID")
    pmkid_p.add_argument("-c", "--channel", type=int, help="Channel number")
    pmkid_p.add_argument("-t", "--timeout", type=int, default=30, help="Capture timeout")
    pmkid_p.add_argument("-w", "--wordlist", help="Wordlist for immediate cracking")

    # --- validate ---
    validate_p = subparsers.add_parser("validate", help="Validate a capture file")
    validate_p.add_argument("--pcap", required=True, help="Path to .pcap file")
    validate_p.add_argument("-b", "--bssid", help="Target AP BSSID")

    # --- crack ---
    crack_p = subparsers.add_parser("crack", help="Crack a captured handshake")
    crack_p.add_argument("--pcap", required=True, help="Path to .pcap capture file")
    crack_p.add_argument("-b", "--bssid", help="Target AP BSSID")
    crack_p.add_argument("-w", "--wordlist",
                         help="Wordlist path(s) or name(s), comma-separated (e.g. rockyou,wifi-passwords)")
    crack_p.add_argument("--verify", action="store_true", help="Only verify handshake")
    crack_p.add_argument("--engine", choices=["aircrack", "hashcat"], default="aircrack",
                         help="Cracking engine (default: aircrack)")
    crack_p.add_argument("--mutate", choices=["light", "moderate", "aggressive"],
                         help="Apply mutation rules to wordlist")
    crack_p.add_argument("--mask", help="Hashcat mask for brute-force (e.g. ?d?d?d?d?d?d?d?d)")
    crack_p.add_argument("--combo", help="Combinator attack: two wordlists comma-separated")
    crack_p.add_argument("--hybrid",
                         help="Hybrid attack: wordlist,mask (e.g. rockyou,?d?d?d?d)")
    crack_p.add_argument("--prince",
                         help="PRINCE attack: wordlist for probability-based word chaining")
    crack_p.add_argument("--hybrid-mode", type=int, choices=[6, 7], default=6,
                         help="Hybrid mode: 6=wordlist+mask (default), 7=mask+wordlist")
    crack_p.add_argument("--session", help="Hashcat session name for pause/resume")
    crack_p.add_argument("--restore", action="store_true", help="Resume a paused hashcat session")
    crack_p.add_argument("--skip-validation", action="store_true", help="Skip capture validation")
    crack_p.add_argument("--report", action="store_true", help="Save detailed report")

    # --- mutate ---
    mutate_p = subparsers.add_parser("mutate", help="Generate mutated wordlists or rule files")
    mutate_p.add_argument("-w", "--wordlist", help="Source wordlist")
    mutate_p.add_argument("--preset", choices=["light", "moderate", "aggressive"],
                          default="moderate", help="Mutation preset")
    mutate_p.add_argument("--rules-only", action="store_true", help="Generate hashcat rules only")
    mutate_p.add_argument("-o", "--output", help="Output file path")
    mutate_p.add_argument("--list-presets", action="store_true", help="List mutation presets")

    # --- wordlist ---
    wl_p = subparsers.add_parser("wordlist", help="Manage wordlists (download, list, merge)")
    wl_p.add_argument("--list", action="store_true", help="List available wordlists")
    wl_p.add_argument("--download", help="Download a wordlist by name (or 'all')")
    wl_p.add_argument("--merge", help="Merge wordlists (comma-separated paths/names)")
    wl_p.add_argument("-o", "--output", help="Output path for merge")

    # --- auto ---
    auto_p = subparsers.add_parser("auto", help="Full automated pipeline with reporting")
    auto_p.add_argument("-i", "--interface", help="Wireless interface")
    auto_p.add_argument("-w", "--wordlist",
                        help="Wordlist path(s)/name(s), comma-separated")
    auto_p.add_argument("--engine", choices=["aircrack", "hashcat"], default="aircrack",
                        help="Cracking engine")
    auto_p.add_argument("--mutate", choices=["light", "moderate", "aggressive"],
                        help="Apply mutations during cracking")
    auto_p.add_argument("--mask", help="Fallback mask attack if dictionary fails")
    auto_p.add_argument("--pmkid", action="store_true", help="Try PMKID first")
    auto_p.add_argument("--multi-deauth", action="store_true",
                        help="Deauth all detected clients")
    auto_p.add_argument("--retries", type=int, default=3,
                        help="Max capture retries on low quality (default: 3)")
    auto_p.add_argument("--scan-timeout", type=int, default=30, help="Scan timeout")
    auto_p.add_argument("--capture-timeout", type=int, default=60, help="Capture timeout")

    # --- reports ---
    reports_p = subparsers.add_parser("reports", help="View attack reports")
    reports_p.add_argument("--view", help="View a specific report by name")

    # --- benchmark ---
    subparsers.add_parser("benchmark", help="Run hashcat GPU benchmark for WPA2")

    # --- wps ---
    wps_p = subparsers.add_parser("wps", help="WPS PIN attack (brute-force or Pixie Dust)")
    wps_p.add_argument("-i", "--interface", required=True, help="Wireless interface")
    wps_p.add_argument("-b", "--bssid", help="Target AP BSSID")
    wps_p.add_argument("-s", "--ssid", help="Target SSID")
    wps_p.add_argument("-c", "--channel", type=int, help="Channel number")
    wps_p.add_argument("--pin", help="Try a specific WPS PIN")
    wps_p.add_argument("--pixie-only", action="store_true",
                        help="Only try Pixie Dust (fast offline attack)")
    wps_p.add_argument("--no-pixie", action="store_true",
                        help="Skip Pixie Dust, go straight to brute-force")
    wps_p.add_argument("--delay", type=int, default=1,
                        help="Delay between PIN attempts in seconds (default: 1)")
    wps_p.add_argument("-t", "--timeout", type=int, default=28800,
                        help="Max attack duration in seconds (default: 8 hours)")
    wps_p.add_argument("--scan-only", action="store_true",
                        help="Only scan for WPS-enabled networks")

    # --- precompute ---
    precomp_p = subparsers.add_parser("precompute",
                                       help="Precompute PMK tables for fast cracking")
    precomp_p.add_argument("--ssid", help="Target SSID to precompute PMKs for")
    precomp_p.add_argument("-w", "--wordlist", help="Wordlist for precomputation")
    precomp_p.add_argument("--db", help="Path to PMK database file")
    precomp_p.add_argument("-b", "--bssid", help="BSSID for cracking with precomputed PMKs")
    precomp_p.add_argument("--crack", help="Crack a .pcap using precomputed PMKs")
    precomp_p.add_argument("--stats", action="store_true", help="Show database statistics")
    precomp_p.add_argument("--list", action="store_true", help="List all PMK databases")

    # --- eviltwin ---
    et_p = subparsers.add_parser("eviltwin",
                                  help="Evil Twin / Rogue AP with captive portal")
    et_p.add_argument("--ap-interface", required=True,
                       help="Interface for rogue AP (must support AP mode)")
    et_p.add_argument("--deauth-interface", required=True,
                       help="Interface for deauth (must support monitor mode)")
    et_p.add_argument("-b", "--bssid", help="Target AP BSSID")
    et_p.add_argument("-s", "--ssid", help="Target SSID to clone")
    et_p.add_argument("-c", "--channel", type=int, help="Target channel")
    et_p.add_argument("--no-deauth", action="store_true",
                       help="Don't deauth clients from real AP")

    # --- targetwl ---
    twl_p = subparsers.add_parser("targetwl",
                                   help="Generate targeted OSINT-based wordlist")
    twl_p.add_argument("--keywords",
                        help="Comma-separated keywords (company, name, address, etc.)")
    twl_p.add_argument("--interactive", action="store_true",
                        help="Interactive mode with guided prompts")
    twl_p.add_argument("-o", "--output", help="Output file path")
    twl_p.add_argument("--no-wifi-patterns", action="store_true",
                        help="Skip WiFi-specific patterns")

    # --- mac ---
    mac_p = subparsers.add_parser("mac", help="MAC address management (randomize/spoof)")
    mac_p.add_argument("-i", "--interface", required=True, help="Wireless interface")
    mac_p.add_argument("--show", action="store_true", help="Show current MAC address")
    mac_p.add_argument("--random", action="store_true",
                        help="Set a random MAC address")
    mac_p.add_argument("--preserve-vendor", action="store_true",
                        help="Keep OUI prefix when randomizing (blend in with real devices)")
    mac_p.add_argument("--set", help="Set a specific MAC address")
    mac_p.add_argument("--restore", help="Restore original MAC address")

    # --- tui ---
    subparsers.add_parser("tui", help="Launch interactive terminal UI")

    args = parser.parse_args()

    if not args.command or args.command == "tui":
        from tui import run_tui
        run_tui()
        return

    print_banner()
    print_disclaimer()

    # Root check (not needed for non-wireless commands)
    no_root = {"crack", "validate", "mutate", "wordlist", "benchmark", "reports",
                "precompute", "targetwl"}
    if args.command not in no_root:
        require_root()

    # Dispatch
    commands = {
        "scan": cmd_scan,
        "deauth": cmd_deauth,
        "capture": cmd_capture,
        "pmkid": cmd_pmkid,
        "validate": cmd_validate,
        "crack": cmd_crack,
        "mutate": cmd_mutate,
        "wordlist": cmd_wordlist,
        "auto": cmd_auto,
        "reports": cmd_reports,
        "benchmark": cmd_benchmark,
        "wps": cmd_wps,
        "precompute": cmd_precompute,
        "eviltwin": cmd_eviltwin,
        "targetwl": cmd_targetwl,
        "mac": cmd_mac,
    }

    commands[args.command](args)


if __name__ == "__main__":
    main()
