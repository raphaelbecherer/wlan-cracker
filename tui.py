"""Interactive Terminal UI for LAN Packet Cracker using Rich."""

import os
import sys
import signal
import time

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.rule import Rule
from rich.text import Text
from rich import box

from utils import check_root, get_wireless_interfaces, Colors
from config import CAPTURES_DIR


# Actions that don't require root
NO_ROOT_ACTIONS = {
    "crack", "validate", "mutate", "wordlist", "benchmark",
    "reports", "precompute", "targetwl",
}

# Menu structure: category -> list of (action_key, label, description)
MENU_CATEGORIES = {
    "1": {
        "name": "Reconnaissance",
        "desc": "Network discovery & information gathering",
        "actions": [
            ("scan", "Network Scan", "Discover wireless networks (WPA3 detection)"),
            ("mac", "MAC Changer", "Randomize or spoof MAC address"),
        ],
    },
    "2": {
        "name": "Attack",
        "desc": "Active wireless attacks",
        "actions": [
            ("deauth", "Deauth Attack", "Send deauthentication frames"),
            ("capture", "Handshake Capture", "Capture WPA 4-way handshake"),
            ("pmkid", "PMKID Attack", "Clientless PMKID capture"),
            ("wps", "WPS Attack", "WPS PIN brute-force / Pixie Dust"),
            ("eviltwin", "Evil Twin", "Rogue AP with captive portal"),
        ],
    },
    "3": {
        "name": "Cracking",
        "desc": "Password recovery & wordlist tools",
        "actions": [
            ("crack", "Crack Password", "Dictionary, mask, combo, hybrid, PRINCE attacks"),
            ("mutate", "Mutate Wordlist", "Generate mutated wordlists or hashcat rules"),
            ("wordlist", "Wordlist Manager", "Download, list, merge wordlists"),
            ("precompute", "PMK Precompute", "Precompute PMK tables for fast cracking"),
            ("benchmark", "GPU Benchmark", "Benchmark hashcat GPU cracking speed"),
            ("targetwl", "Targeted Wordlist", "Generate OSINT-based wordlist"),
        ],
    },
    "4": {
        "name": "Utilities",
        "desc": "Validation, reporting & automation",
        "actions": [
            ("auto", "Auto Pipeline", "Full automated scan -> capture -> crack"),
            ("validate", "Validate Capture", "Check capture file quality"),
            ("reports", "View Reports", "List and view attack session reports"),
        ],
    },
}


class TUI:
    """Interactive Terminal UI for LAN Packet Cracker."""

    def __init__(self):
        self.console = Console()
        self._monitor = None

    # ─── DISPLAY ────────────────────────────────────────────────────────

    def show_banner(self):
        """Display the tool banner in a styled panel."""
        banner_text = Text()
        banner_text.append(
            "  _     _   _  _   ___         _           ___             _\n"
            " | |   /_\\ | \\| | | _ \\__ _ __| |_____ ___/ __|_ _ __ _ __| |_____ _ _\n"
            " | |__/ _ \\| .` | |  _/ _` / _| / / -_)___|  _| '_/ _` / _| / / -_) '_|\n"
            " |____/_/ \\_\\_|\\_| |_| \\__,_\\__|_\\_\\_____|  |___|_| \\__,_\\__|_\\_\\___|_|\n",
            style="bold cyan",
        )
        banner_text.append("\n  WPA/WPA2 Handshake Capture & Cracking Tool", style="yellow")
        self.console.print(Panel(banner_text, border_style="cyan", padding=(0, 2)))

    def show_disclaimer(self):
        """Display legal disclaimer and require acceptance."""
        disclaimer = (
            "[bold]DISCLAIMER[/bold]\n\n"
            "This tool is intended for [bold]educational purposes[/bold] and\n"
            "[bold]authorized security testing ONLY.[/bold]\n\n"
            "Unauthorized access to computer networks is illegal.\n"
            "Use this tool only on networks you own or have\n"
            "explicit written permission to test.\n\n"
            "The author assumes no liability for misuse."
        )
        self.console.print(Panel(disclaimer, border_style="red", title="Legal Notice"))
        if not Confirm.ask("[yellow]Do you accept and wish to continue?[/yellow]", default=True):
            self.console.print("[dim]Goodbye.[/dim]")
            sys.exit(0)

    def show_main_menu(self):
        """Display the main category menu. Returns category key or 'exit'."""
        self.console.print()
        table = Table(
            title="Main Menu",
            box=box.ROUNDED,
            title_style="bold cyan",
            show_header=True,
            header_style="bold",
        )
        table.add_column("#", style="bold cyan", width=4, justify="center")
        table.add_column("Category", width=20)
        table.add_column("Description", width=44)
        table.add_column("Commands", style="dim", width=30)

        for key, cat in MENU_CATEGORIES.items():
            cmds = ", ".join(a[0] for a in cat["actions"])
            table.add_row(key, cat["name"], cat["desc"], cmds)

        table.add_row("0", "[red]Exit[/red]", "Quit the tool", "")
        self.console.print(table)

        choice = Prompt.ask(
            "\n[bold]Select category[/bold]",
            choices=["0", "1", "2", "3", "4"],
            default="1",
        )
        return "exit" if choice == "0" else choice

    def show_category_menu(self, category_key):
        """Display actions within a category. Returns action key or None for back."""
        cat = MENU_CATEGORIES[category_key]
        self.console.print()
        self.console.print(Rule(f"[bold]{cat['name']}[/bold]"))

        table = Table(box=box.SIMPLE, show_header=True, header_style="bold")
        table.add_column("#", style="bold cyan", width=4, justify="center")
        table.add_column("Action", width=22)
        table.add_column("Description", width=54)

        valid_choices = ["0"]
        for idx, (key, label, desc) in enumerate(cat["actions"], 1):
            table.add_row(str(idx), label, desc)
            valid_choices.append(str(idx))

        table.add_row("0", "[dim]Back[/dim]", "[dim]Return to main menu[/dim]")
        self.console.print(table)

        choice = Prompt.ask("[bold]Select action[/bold]", choices=valid_choices, default="0")
        if choice == "0":
            return None
        return cat["actions"][int(choice) - 1][0]

    # ─── SHARED PROMPTS ─────────────────────────────────────────────────

    def prompt_interface(self):
        """Detect and prompt for wireless interface selection."""
        interfaces = get_wireless_interfaces()
        if interfaces:
            self.console.print("[cyan]Detected wireless interfaces:[/cyan]")
            for i, iface in enumerate(interfaces, 1):
                self.console.print(f"  {i}. {iface}")
            choice = Prompt.ask(
                "Select interface (number or name)",
                default=interfaces[0],
            )
            try:
                return interfaces[int(choice) - 1]
            except (ValueError, IndexError):
                return choice
        return Prompt.ask("Enter wireless interface name")

    def prompt_bssid(self):
        """Prompt for target BSSID."""
        return Prompt.ask("Target BSSID (MAC address)")

    def prompt_pcap(self):
        """Prompt for pcap file path with validation."""
        while True:
            path = Prompt.ask("Path to .pcap file")
            if os.path.isfile(path):
                return path
            self.console.print(f"[red]File not found: {path}[/red]")

    def prompt_wordlist(self):
        """Prompt for wordlist path/name."""
        from wordlists import get_wordlist_path, list_available
        show = Confirm.ask("Show available wordlists first?", default=False)
        if show:
            list_available()
        name = Prompt.ask("Wordlist path or name")
        resolved = get_wordlist_path(name)
        return resolved if resolved else name

    def prompt_engine(self):
        """Prompt for cracking engine."""
        return Prompt.ask("Cracking engine", choices=["aircrack", "hashcat"], default="aircrack")

    def require_root_check(self, action_name):
        """Check root if action requires it. Returns True if OK to proceed."""
        if action_name in NO_ROOT_ACTIONS:
            return True
        if check_root():
            return True
        self.console.print(
            Panel(
                "[red]This action requires root/administrator privileges.\n"
                "Run with: [bold]sudo python main.py[/bold][/red]",
                title="Permission Error",
                border_style="red",
            )
        )
        return False

    # ─── RICH DISPLAY HELPERS ───────────────────────────────────────────

    def display_scan_results(self, scanner):
        """Display scan results as a rich Table."""
        if not scanner.access_points:
            self.console.print("[yellow]No networks found.[/yellow]")
            return

        ap_list = scanner.get_sorted_by_signal()

        table = Table(
            title="Discovered Networks",
            box=box.ROUNDED,
            title_style="bold",
            show_lines=False,
        )
        table.add_column("#", style="bold", width=4, justify="right")
        table.add_column("BSSID", style="cyan", width=18)
        table.add_column("SSID", width=30)
        table.add_column("CH", justify="right", width=4)
        table.add_column("Signal", justify="right", width=8)
        table.add_column("Band", width=6)
        table.add_column("Encryption", width=16)
        table.add_column("Clients", justify="right", width=10)

        for idx, ap in enumerate(ap_list, 1):
            if ap.is_wpa3:
                enc_style = "red"
            elif ap.encryption == "OPEN":
                enc_style = "green"
            elif "WPA2" in ap.encryption:
                enc_style = "cyan"
            else:
                enc_style = "yellow"

            band = "5 GHz" if ap.channel >= 36 else "2.4G"
            clients = str(len(ap.clients)) if ap.clients else "-"
            wpa3_flag = " [red]WPA3[/red]" if ap.is_wpa3 else ""

            table.add_row(
                str(idx),
                ap.bssid,
                ap.ssid + wpa3_flag,
                str(ap.channel),
                f"{ap.signal} dBm",
                band,
                f"[{enc_style}]{ap.encryption}[/{enc_style}]",
                clients,
            )

        self.console.print(table)

        # Summary
        count_24 = sum(1 for ap in ap_list if ap.channel < 36)
        count_5 = sum(1 for ap in ap_list if ap.channel >= 36)
        wpa3_count = sum(1 for ap in ap_list if ap.is_wpa3)

        summary = f"[bold]Total: {len(ap_list)} networks[/bold]"
        if count_5 > 0:
            summary += f"  [cyan](2.4 GHz: {count_24} | 5 GHz: {count_5})[/cyan]"
        self.console.print(summary)

        if wpa3_count > 0:
            self.console.print(
                f"[red bold]Warning: {wpa3_count} WPA3/SAE network(s) detected. "
                f"These are resistant to offline dictionary attacks.[/red bold]"
            )

    def select_target(self, scanner):
        """Interactive target selection from scan results. Returns AccessPoint or None."""
        if not scanner.access_points:
            return None

        self.display_scan_results(scanner)
        ap_list = scanner.get_sorted_by_signal()

        while True:
            choice = Prompt.ask(
                f"\n[bold]Select target[/bold] [1-{len(ap_list)}, or 0 to cancel]",
                default="0",
            )
            if choice == "0":
                return None
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(ap_list):
                    target = ap_list[idx]
                    if target.is_wpa3:
                        self.console.print(
                            Panel(
                                f"[red bold]WARNING: {target.ssid} uses WPA3/SAE![/red bold]\n\n"
                                "WPA3 is resistant to offline dictionary attacks.\n"
                                "The 4-way handshake capture approach will NOT work.",
                                title="WPA3 Warning",
                                border_style="red",
                            )
                        )
                        if not Confirm.ask("Continue anyway?", default=False):
                            continue
                    self.console.print(
                        f"[green][+] Target: {target.ssid} ({target.bssid}) "
                        f"on channel {target.channel}[/green]"
                    )
                    return target
                self.console.print("[red]Invalid selection.[/red]")
            except ValueError:
                self.console.print("[red]Enter a number.[/red]")

    # ─── ACTION HANDLERS ────────────────────────────────────────────────

    def action_scan(self):
        """Scan for wireless networks."""
        from monitor import MonitorMode
        from scanner import NetworkScanner
        from mac_changer import change_mac, restore_mac

        if not self.require_root_check("scan"):
            return

        iface = self.prompt_interface()
        timeout = IntPrompt.ask("Scan timeout (seconds)", default=30)
        band = Prompt.ask("Frequency band", choices=["2.4", "5", "all"], default="all")
        randomize = Confirm.ask("Randomize MAC address?", default=False)

        mon = MonitorMode(iface)
        self._monitor = mon
        mon_iface = mon.enable()
        if not mon_iface:
            self.console.print("[red]Failed to enable monitor mode.[/red]")
            self._monitor = None
            return

        original_mac = None
        try:
            if randomize:
                original_mac, _ = change_mac(mon_iface, preserve_vendor=True)

            mon.start_channel_hop(band=band)

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                TimeElapsedColumn(),
                console=self.console,
            ) as progress:
                task = progress.add_task("Scanning for networks...", total=None)
                scanner = NetworkScanner(mon_iface)
                scanner.scan(timeout=timeout)
                progress.update(task, description="[green]Scan complete[/green]")

            mon.stop_channel_hop()
            self.console.print()
            self.display_scan_results(scanner)
        finally:
            if original_mac:
                restore_mac(mon_iface, original_mac)
            mon.disable()
            self._monitor = None

    def action_deauth(self):
        """Send deauthentication frames."""
        from monitor import MonitorMode
        from scanner import NetworkScanner
        from deauth import DeauthAttack, MultiClientDeauth

        if not self.require_root_check("deauth"):
            return

        iface = self.prompt_interface()
        bssid = self.prompt_bssid()
        channel = IntPrompt.ask("Channel (0 for auto-detect)", default=0)
        client = Prompt.ask("Target client MAC (leave blank for broadcast)", default="")
        count = IntPrompt.ask("Packets per burst", default=50)
        bursts = IntPrompt.ask("Number of bursts", default=5)
        evasion = Confirm.ask("Enable IDS evasion mode?", default=False)

        mon = MonitorMode(iface)
        self._monitor = mon
        mon_iface = mon.enable()
        if not mon_iface:
            self.console.print("[red]Failed to enable monitor mode.[/red]")
            self._monitor = None
            return

        try:
            if channel > 0:
                mon.set_channel(channel)
            else:
                scanner = NetworkScanner(mon_iface)
                ch = scanner.quick_channel_detect(bssid, timeout=10)
                if ch:
                    mon.set_channel(ch)
                    self.console.print(f"[cyan]Auto-detected channel: {ch}[/cyan]")

            client_mac = client.strip() if client.strip() else None

            if client_mac and "," in client_mac:
                clients = [c.strip() for c in client_mac.split(",")]
                multi = MultiClientDeauth(mon_iface, bssid, clients)
                multi.start(count=count, bursts=bursts)
            else:
                attack = DeauthAttack(mon_iface, bssid, client=client_mac, evasion=evasion)
                attack.start(count=count, bursts=bursts)
        finally:
            mon.disable()
            self._monitor = None

    def action_capture(self):
        """Capture WPA handshake."""
        from monitor import MonitorMode
        from scanner import NetworkScanner
        from capture import HandshakeCapture, PassiveCapture
        from validator import HandshakeValidator

        if not self.require_root_check("capture"):
            return

        iface = self.prompt_interface()
        bssid = self.prompt_bssid()
        ssid = Prompt.ask("Target SSID (for filename)", default="unknown")
        channel = IntPrompt.ask("Channel (0 for auto-detect)", default=0)
        timeout = IntPrompt.ask("Capture timeout (seconds)", default=60)
        passive = Confirm.ask("Passive mode (stealth, no deauth)?", default=False)
        validate = Confirm.ask("Validate capture after saving?", default=True)

        mon = MonitorMode(iface)
        self._monitor = mon
        mon_iface = mon.enable()
        if not mon_iface:
            self.console.print("[red]Failed to enable monitor mode.[/red]")
            self._monitor = None
            return

        try:
            if channel > 0:
                mon.set_channel(channel)
            else:
                scanner = NetworkScanner(mon_iface)
                ch = scanner.quick_channel_detect(bssid, timeout=10)
                if ch:
                    mon.set_channel(ch)
                    self.console.print(f"[cyan]Auto-detected channel: {ch}[/cyan]")

            if passive:
                cap = PassiveCapture(mon_iface, bssid=bssid, ssid=ssid)
            else:
                cap = HandshakeCapture(mon_iface, bssid, ssid=ssid)

            self.console.print(f"\n[bold]{'Passive' if passive else 'Active'} capture started...[/bold]")
            pcap_path = cap.capture(timeout=timeout)

            if pcap_path:
                self.console.print(
                    Panel(f"[green]Capture saved to: {pcap_path}[/green]",
                          title="Success", border_style="green")
                )
                if validate:
                    self.console.print()
                    HandshakeValidator(pcap_path, bssid=bssid).validate()
            else:
                self.console.print("[yellow]No handshake captured.[/yellow]")
        finally:
            mon.disable()
            self._monitor = None

    def action_pmkid(self):
        """Execute PMKID attack."""
        from monitor import MonitorMode
        from pmkid import PMKIDAttack
        from hashcat_cracker import HashcatCracker

        if not self.require_root_check("pmkid"):
            return

        iface = self.prompt_interface()
        bssid = self.prompt_bssid()
        ssid = Prompt.ask("Target SSID", default="unknown")
        channel = IntPrompt.ask("Channel (0 to skip)", default=0)
        timeout = IntPrompt.ask("Capture timeout (seconds)", default=30)
        crack_now = Confirm.ask("Crack immediately if captured?", default=False)
        wordlist = None
        if crack_now:
            wordlist = self.prompt_wordlist()

        mon = MonitorMode(iface)
        self._monitor = mon
        mon_iface = mon.enable()
        if not mon_iface:
            self.console.print("[red]Failed to enable monitor mode.[/red]")
            self._monitor = None
            return

        try:
            if channel > 0:
                mon.set_channel(channel)

            pmkid = PMKIDAttack(mon_iface, bssid, ssid=ssid)
            pcap_path = pmkid.capture(timeout=timeout)

            if pcap_path and wordlist:
                self.console.print("\n[bold]Cracking PMKID with hashcat...[/bold]")
                cracker = HashcatCracker(pcap_path, bssid=bssid)
                if cracker.convert_to_hc22000():
                    cracker.crack(wordlist=wordlist)
        finally:
            mon.disable()
            self._monitor = None

    def action_validate(self):
        """Validate a capture file."""
        from validator import HandshakeValidator

        pcap = self.prompt_pcap()
        bssid = Prompt.ask("Target BSSID (optional, press Enter to skip)", default="")
        bssid = bssid.strip() if bssid.strip() else None

        validator = HandshakeValidator(pcap, bssid=bssid)
        result = validator.validate()

        if result["valid"]:
            quality = "Excellent" if result["score"] >= 70 else "Marginal"
            self.console.print(
                Panel(
                    f"[green bold]Capture is VALID[/green bold]\n\n"
                    f"Score: {result['score']}/100\n"
                    f"Quality: {quality}\n"
                    f"Ready for cracking: Yes",
                    title="Validation Result",
                    border_style="green",
                )
            )
        else:
            self.console.print(
                Panel(
                    f"[red bold]Capture is NOT suitable for cracking[/red bold]\n\n"
                    f"Score: {result['score']}/100\n"
                    f"Consider re-capturing with better signal/proximity.",
                    title="Validation Result",
                    border_style="red",
                )
            )

    def action_crack(self):
        """Crack a captured handshake."""
        from cracker import AircrackCracker
        from hashcat_cracker import HashcatCracker
        from validator import HandshakeValidator
        from wordlists import get_wordlist_path
        from mutations import generate_hashcat_rules, generate_mutated_wordlist
        from reporter import AttackReporter

        pcap = self.prompt_pcap()
        bssid = Prompt.ask("Target BSSID (optional)", default="")
        bssid = bssid.strip() if bssid.strip() else None

        # Attack type selection
        self.console.print()
        attack_table = Table(box=box.SIMPLE, show_header=False)
        attack_table.add_column("#", style="bold cyan", width=4)
        attack_table.add_column("Attack Type", width=50)
        attack_table.add_row("1", "Dictionary attack (wordlist)")
        attack_table.add_row("2", "Mask/brute-force attack (e.g. ?d?d?d?d?d?d?d?d)")
        attack_table.add_row("3", "Combinator attack (two wordlists)")
        attack_table.add_row("4", "Hybrid attack (wordlist + mask)")
        attack_table.add_row("5", "PRINCE attack (probability word chaining)")
        attack_table.add_row("6", "Restore previous hashcat session")
        self.console.print(attack_table)

        attack_choice = Prompt.ask("Attack type", choices=["1", "2", "3", "4", "5", "6"], default="1")

        if attack_choice == "1":
            self._crack_dictionary(pcap, bssid)
        elif attack_choice == "2":
            self._crack_mask(pcap, bssid)
        elif attack_choice == "3":
            self._crack_combo(pcap, bssid)
        elif attack_choice == "4":
            self._crack_hybrid(pcap, bssid)
        elif attack_choice == "5":
            self._crack_prince(pcap, bssid)
        elif attack_choice == "6":
            self._crack_restore(pcap, bssid)

    def _crack_dictionary(self, pcap, bssid):
        """Dictionary attack handler."""
        from cracker import AircrackCracker
        from hashcat_cracker import HashcatCracker
        from wordlists import get_wordlist_path
        from mutations import generate_hashcat_rules, generate_mutated_wordlist

        wordlist = self.prompt_wordlist()
        engine = self.prompt_engine()
        mutate = Prompt.ask(
            "Apply mutations?",
            choices=["none", "light", "moderate", "aggressive"],
            default="none",
        )

        rules_file = None
        if mutate != "none":
            if engine == "hashcat":
                rules_file = generate_hashcat_rules(preset=mutate)
            else:
                mutated = generate_mutated_wordlist(wordlist, preset=mutate)
                if mutated:
                    wordlist = mutated

        self.console.print(f"\n[bold]Cracking with {engine}...[/bold]")

        password = None
        if engine == "hashcat":
            cracker = HashcatCracker(pcap, bssid=bssid)
            if cracker.convert_to_hc22000():
                password = cracker.crack(wordlist=wordlist, rules_file=rules_file)
            else:
                self.console.print("[yellow]Hashcat conversion failed. Falling back to aircrack-ng...[/yellow]")
                cracker = AircrackCracker(pcap, bssid=bssid)
                password = cracker.crack(wordlist)
        else:
            cracker = AircrackCracker(pcap, bssid=bssid)
            password = cracker.crack(wordlist)

        self._show_crack_result(password)

    def _crack_mask(self, pcap, bssid):
        """Mask/brute-force attack handler."""
        from hashcat_cracker import HashcatCracker

        mask = Prompt.ask("Mask pattern (e.g. ?d?d?d?d?d?d?d?d)", default="?d?d?d?d?d?d?d?d")

        self.console.print(f"\n[bold]Mask attack with hashcat: {mask}[/bold]")
        cracker = HashcatCracker(pcap, bssid=bssid)
        password = cracker.mask_attack(mask=mask)
        self._show_crack_result(password)

    def _crack_combo(self, pcap, bssid):
        """Combinator attack handler."""
        from hashcat_cracker import HashcatCracker
        from wordlists import get_wordlist_path

        self.console.print("[cyan]Wordlist 1:[/cyan]")
        wl1 = self.prompt_wordlist()
        self.console.print("[cyan]Wordlist 2:[/cyan]")
        wl2 = self.prompt_wordlist()

        self.console.print("\n[bold]Combinator attack with hashcat...[/bold]")
        cracker = HashcatCracker(pcap, bssid=bssid)
        password = cracker.combo_attack(wl1, wl2)
        self._show_crack_result(password)

    def _crack_hybrid(self, pcap, bssid):
        """Hybrid attack handler."""
        from hashcat_cracker import HashcatCracker

        wordlist = self.prompt_wordlist()
        mask = Prompt.ask("Mask to append/prepend (e.g. ?d?d?d?d)", default="?d?d?d?d")
        mode = IntPrompt.ask("Mode (6=wordlist+mask, 7=mask+wordlist)", default=6)

        self.console.print(f"\n[bold]Hybrid attack (mode {mode}) with hashcat...[/bold]")
        cracker = HashcatCracker(pcap, bssid=bssid)
        password = cracker.hybrid_attack(wordlist, mask, mode=mode)
        self._show_crack_result(password)

    def _crack_prince(self, pcap, bssid):
        """PRINCE attack handler."""
        from hashcat_cracker import HashcatCracker

        wordlist = self.prompt_wordlist()

        self.console.print("\n[bold]PRINCE attack with hashcat...[/bold]")
        cracker = HashcatCracker(pcap, bssid=bssid)
        password = cracker.prince_attack(wordlist)
        self._show_crack_result(password)

    def _crack_restore(self, pcap, bssid):
        """Restore a previous hashcat session."""
        from hashcat_cracker import HashcatCracker

        session = Prompt.ask("Session name", default="wpa_session")
        cracker = HashcatCracker(pcap, bssid=bssid)
        password = cracker.crack_with_session(wordlist="", session_name=session, restore=True)
        self._show_crack_result(password)

    def _show_crack_result(self, password):
        """Display cracking result."""
        if password:
            self.console.print(
                Panel(
                    f"[green bold]PASSWORD FOUND![/green bold]\n\n"
                    f"[bold]{password}[/bold]",
                    title="Cracking Result",
                    border_style="green",
                    padding=(1, 4),
                )
            )
        else:
            self.console.print(
                Panel(
                    "[yellow]Password not found.[/yellow]\n\n"
                    "Try a different wordlist, mutation preset, or attack type.",
                    title="Cracking Result",
                    border_style="yellow",
                )
            )

    def action_mutate(self):
        """Generate mutated wordlists or hashcat rule files."""
        from mutations import generate_hashcat_rules, generate_mutated_wordlist, list_presets

        list_presets()
        self.console.print()

        wordlist = self.prompt_wordlist()
        preset = Prompt.ask("Mutation preset", choices=["light", "moderate", "aggressive"], default="moderate")
        rules_only = Confirm.ask("Generate hashcat rules only (no wordlist)?", default=False)
        output = Prompt.ask("Output path (leave blank for auto)", default="")
        output = output.strip() if output.strip() else None

        if rules_only:
            generate_hashcat_rules(preset=preset, output_path=output)
        else:
            generate_mutated_wordlist(wordlist, preset=preset, output_path=output)

    def action_wordlist(self):
        """Manage wordlists."""
        from wordlists import list_available, download_wordlist, download_all, merge_wordlists, get_wordlist_path

        table = Table(box=box.SIMPLE, show_header=False)
        table.add_column("#", style="bold cyan", width=4)
        table.add_column("Action", width=40)
        table.add_row("1", "List available wordlists")
        table.add_row("2", "Download a wordlist")
        table.add_row("3", "Download all wordlists")
        table.add_row("4", "Merge wordlists")
        self.console.print(table)

        choice = Prompt.ask("Action", choices=["1", "2", "3", "4"], default="1")

        if choice == "1":
            list_available()
        elif choice == "2":
            name = Prompt.ask("Wordlist name to download")
            download_wordlist(name)
        elif choice == "3":
            if Confirm.ask("Download ALL wordlists?", default=False):
                download_all()
        elif choice == "4":
            paths_str = Prompt.ask("Wordlist paths/names (comma-separated)")
            paths = [get_wordlist_path(w.strip()) for w in paths_str.split(",")]
            paths = [p for p in paths if p]
            if paths:
                output = Prompt.ask("Output path (leave blank for auto)", default="")
                merge_wordlists(paths, output_path=output.strip() or None)

    def action_auto(self):
        """Full automated pipeline."""
        from monitor import MonitorMode
        from scanner import NetworkScanner
        from capture import HandshakeCapture
        from deauth import DeauthAttack, MultiClientDeauth
        from validator import HandshakeValidator
        from cracker import AircrackCracker
        from hashcat_cracker import HashcatCracker
        from pmkid import PMKIDAttack
        from wordlists import get_wordlist_path
        from mutations import generate_hashcat_rules, generate_mutated_wordlist
        from reporter import AttackReporter

        if not self.require_root_check("auto"):
            return

        self.console.print(Rule("[bold]Automated Attack Pipeline[/bold]"))

        iface = self.prompt_interface()
        wordlist = self.prompt_wordlist()
        engine = self.prompt_engine()
        mutate = Prompt.ask(
            "Mutations", choices=["none", "light", "moderate", "aggressive"], default="none"
        )
        mutate = None if mutate == "none" else mutate
        try_pmkid = Confirm.ask("Try PMKID capture first?", default=True)
        multi_deauth = Confirm.ask("Deauth all detected clients?", default=True)
        retries = IntPrompt.ask("Max capture retries", default=3)
        scan_timeout = IntPrompt.ask("Scan timeout (seconds)", default=30)
        capture_timeout = IntPrompt.ask("Capture timeout (seconds)", default=60)

        reporter = AttackReporter()

        # Step 1: Monitor mode
        self.console.print(Rule("[bold cyan]Step 1: Monitor Mode[/bold cyan]"))
        reporter.start_phase("monitor_mode")
        mon = MonitorMode(iface)
        self._monitor = mon
        mon_iface = mon.enable()
        if not mon_iface:
            self.console.print("[red]Failed to enable monitor mode.[/red]")
            reporter.end_phase(success=False, errors=["Failed to enable monitor mode"])
            reporter.set_result(False)
            reporter.finish()
            self._monitor = None
            return
        reporter.end_phase(success=True)

        try:
            # Step 2: Scan
            self.console.print(Rule("[bold cyan]Step 2: Network Scan[/bold cyan]"))
            reporter.start_phase("scan")
            mon.start_channel_hop()

            with Progress(
                SpinnerColumn(), TextColumn("{task.description}"), TimeElapsedColumn(),
                console=self.console,
            ) as progress:
                task = progress.add_task("Scanning...", total=None)
                scanner = NetworkScanner(mon_iface)
                scanner.scan(timeout=scan_timeout)
                progress.update(task, description="[green]Scan complete[/green]")

            mon.stop_channel_hop()

            if not scanner.access_points:
                self.console.print("[red]No networks found.[/red]")
                reporter.end_phase(success=False, errors=["No networks found"])
                reporter.set_result(False)
                reporter.finish()
                return

            reporter.end_phase(success=True,
                               details=reporter.log_scan_results(scanner.access_points))

            # Step 3: Select target
            self.console.print(Rule("[bold cyan]Step 3: Target Selection[/bold cyan]"))
            target = self.select_target(scanner)
            if not target:
                self.console.print("[yellow]No target selected.[/yellow]")
                reporter.set_result(False)
                reporter.finish()
                return

            reporter.set_target(
                bssid=target.bssid, ssid=target.ssid,
                channel=target.channel, encryption=target.encryption,
                clients=target.clients,
            )
            mon.set_channel(target.channel)

            # Step 4: Capture (with retry loop)
            pcap_path = None
            for attempt in range(1, retries + 1):
                self.console.print(
                    Rule(f"[bold cyan]Step 4: Capture (attempt {attempt}/{retries})[/bold cyan]")
                )
                reporter.start_phase(f"capture_attempt_{attempt}")

                # Try PMKID first
                if try_pmkid and not pcap_path:
                    self.console.print("[bold]Attempting PMKID capture...[/bold]")
                    pmkid_attack = PMKIDAttack(mon_iface, target.bssid, ssid=target.ssid)
                    pcap_path = pmkid_attack.capture(timeout=capture_timeout // 2)
                    if pcap_path:
                        reporter.end_phase(success=True, details={"method": "pmkid"})
                        break

                # Traditional deauth + handshake
                if not pcap_path:
                    self.console.print("[bold]Capturing handshake (deauth + capture)...[/bold]")
                    cap = HandshakeCapture(mon_iface, target.bssid, ssid=target.ssid)
                    cap.capture_async(timeout=capture_timeout)
                    time.sleep(1)

                    if len(target.clients) > 1 and multi_deauth:
                        multi = MultiClientDeauth(mon_iface, target.bssid, target.clients)
                        multi.start(blocking=True)
                    else:
                        client = list(target.clients)[0] if target.clients else None
                        attack = DeauthAttack(mon_iface, target.bssid, client=client)
                        attack.start(blocking=True)

                    cap.wait(timeout=capture_timeout)
                    pcap_path = cap.pcap_path

                if not pcap_path:
                    reporter.end_phase(success=False, errors=["No capture"])
                    continue

                # Validate
                validator = HandshakeValidator(pcap_path, bssid=target.bssid)
                result = validator.validate()
                if result["score"] >= 40:
                    reporter.end_phase(success=True, details={"score": result["score"]})
                    break
                else:
                    self.console.print(
                        f"[yellow]Capture quality too low (score: {result['score']}). Retrying...[/yellow]"
                    )
                    reporter.end_phase(success=False,
                                       errors=[f"Low quality: {result['score']}"])
                    pcap_path = None

            if not pcap_path:
                self.console.print("[red]Failed to capture handshake after all retries.[/red]")
                reporter.set_result(False)
                reporter.finish()
                return

            # Step 5: Crack
            self.console.print(Rule("[bold cyan]Step 5: Cracking[/bold cyan]"))
            reporter.start_phase("crack")

            resolved_wl = get_wordlist_path(wordlist) or wordlist
            rules_file = None
            if mutate:
                if engine == "hashcat":
                    rules_file = generate_hashcat_rules(preset=mutate)
                else:
                    mutated = generate_mutated_wordlist(resolved_wl, preset=mutate)
                    if mutated:
                        resolved_wl = mutated

            password = None
            crack_start = time.time()

            if engine == "hashcat":
                cracker = HashcatCracker(pcap_path, bssid=target.bssid)
                if cracker.convert_to_hc22000():
                    password = cracker.crack(wordlist=resolved_wl, rules_file=rules_file)
                else:
                    cracker_ac = AircrackCracker(pcap_path, bssid=target.bssid)
                    password = cracker_ac.crack(resolved_wl)
            else:
                cracker = AircrackCracker(pcap_path, bssid=target.bssid)
                password = cracker.crack(resolved_wl)

            crack_duration = time.time() - crack_start
            reporter.end_phase(
                success=password is not None,
                details=reporter.log_crack_result(
                    engine=engine, wordlist=wordlist,
                    password=password, duration=crack_duration,
                    mutate_preset=mutate,
                ),
            )
            reporter.set_result(password is not None, password)

            # Show result
            if password:
                self.console.print(
                    Panel(
                        f"[green bold]PASSWORD FOUND![/green bold]\n\n"
                        f"Network:  {target.ssid}\n"
                        f"BSSID:    {target.bssid}\n"
                        f"Password: [bold]{password}[/bold]\n"
                        f"Engine:   {engine}\n"
                        f"Duration: {crack_duration:.1f}s",
                        title="Success",
                        border_style="green",
                        padding=(1, 4),
                    )
                )
            else:
                self.console.print(
                    Panel(
                        "[yellow]Password not found.[/yellow]\n"
                        f"Capture saved: {pcap_path}\n\n"
                        "Try a different wordlist or attack type.",
                        title="Result",
                        border_style="yellow",
                    )
                )

            reporter.finish()
        finally:
            mon.disable()
            self._monitor = None

    def action_reports(self):
        """List and view attack reports."""
        from reporter import list_reports, load_report
        import json

        list_reports()
        view = Prompt.ask("\nView a specific report? (filename or Enter to skip)", default="")
        if view.strip():
            data = load_report(view.strip())
            if data:
                self.console.print_json(json.dumps(data, default=str))

    def action_benchmark(self):
        """Run hashcat GPU benchmark."""
        from hashcat_cracker import HashcatCracker

        self.console.print("[bold]Running hashcat WPA2 benchmark...[/bold]\n")
        cracker = HashcatCracker(pcap_path="/dev/null")
        cracker.benchmark()

    def action_wps(self):
        """WPS PIN attack."""
        from monitor import MonitorMode
        from wps_attack import WPSScanner, WPSAttack

        if not self.require_root_check("wps"):
            return

        iface = self.prompt_interface()

        table = Table(box=box.SIMPLE, show_header=False)
        table.add_column("#", style="bold cyan", width=4)
        table.add_column("Action", width=50)
        table.add_row("1", "Scan for WPS-enabled networks")
        table.add_row("2", "Pixie Dust attack (fast offline)")
        table.add_row("3", "Full WPS attack (Pixie Dust + brute-force)")
        table.add_row("4", "Try a specific WPS PIN")
        self.console.print(table)

        choice = Prompt.ask("Action", choices=["1", "2", "3", "4"], default="1")

        mon = MonitorMode(iface)
        self._monitor = mon
        mon_iface = mon.enable()
        if not mon_iface:
            self.console.print("[red]Failed to enable monitor mode.[/red]")
            self._monitor = None
            return

        try:
            if choice == "1":
                timeout = IntPrompt.ask("Scan timeout", default=30)
                scanner = WPSScanner(mon_iface)
                scanner.scan(timeout=timeout)
                scanner.print_results()
                return

            bssid = self.prompt_bssid()
            channel = IntPrompt.ask("Channel (0 to skip)", default=0)
            if channel > 0:
                mon.set_channel(channel)

            ssid = Prompt.ask("SSID (optional)", default="")
            attack = WPSAttack(mon_iface, bssid, channel=channel if channel > 0 else None,
                               ssid=ssid.strip() or None)

            if choice == "2":
                pin, password = attack.attack_reaver(pixie_dust=True, timeout=120)
            elif choice == "3":
                delay = IntPrompt.ask("Delay between PIN attempts (seconds)", default=1)
                timeout = IntPrompt.ask("Max attack duration (seconds)", default=28800)
                pin, password = attack.attack(pixie_dust=True, delay=delay, timeout=timeout)
            elif choice == "4":
                pin_val = Prompt.ask("WPS PIN to try")
                pin, password = attack.attack_reaver(pin=pin_val)

            if password:
                self.console.print(
                    Panel(
                        f"[green bold]WPS CRACKED![/green bold]\n\n"
                        f"PIN:      {pin}\n"
                        f"Password: [bold]{password}[/bold]",
                        title="Success",
                        border_style="green",
                    )
                )
        finally:
            mon.disable()
            self._monitor = None

    def action_precompute(self):
        """Precompute PMK hash tables."""
        from pmk_precomp import PMKPrecomputer, list_databases
        from wordlists import get_wordlist_path

        table = Table(box=box.SIMPLE, show_header=False)
        table.add_column("#", style="bold cyan", width=4)
        table.add_column("Action", width=50)
        table.add_row("1", "Precompute PMKs for an SSID")
        table.add_row("2", "Crack with precomputed PMKs")
        table.add_row("3", "Show database statistics")
        table.add_row("4", "List all PMK databases")
        self.console.print(table)

        choice = Prompt.ask("Action", choices=["1", "2", "3", "4"], default="1")

        if choice == "4":
            list_databases()
            return

        ssid = Prompt.ask("Target SSID")
        db = Prompt.ask("Database path (leave blank for auto)", default="")
        precomp = PMKPrecomputer(ssid, db_path=db.strip() or None)

        if choice == "1":
            wordlist = self.prompt_wordlist()
            precomp.precompute(wordlist)
        elif choice == "2":
            pcap = self.prompt_pcap()
            bssid = Prompt.ask("BSSID (optional)", default="")
            precomp.crack(pcap, bssid=bssid.strip() or None)
        elif choice == "3":
            precomp.stats()

    def action_eviltwin(self):
        """Evil Twin / Rogue AP attack."""
        from evil_twin import EvilTwin

        if not self.require_root_check("eviltwin"):
            return

        self.console.print(
            Panel(
                "[yellow]Evil Twin requires TWO wireless interfaces:[/yellow]\n"
                "1. AP interface (creates the rogue AP)\n"
                "2. Deauth interface (sends deauth frames)",
                border_style="yellow",
            )
        )

        self.console.print("[cyan]AP interface:[/cyan]")
        ap_iface = self.prompt_interface()
        self.console.print("[cyan]Deauth interface:[/cyan]")
        deauth_iface = self.prompt_interface()
        bssid = self.prompt_bssid()
        ssid = Prompt.ask("Target SSID to clone")
        channel = IntPrompt.ask("Target channel")
        deauth = Confirm.ask("Send deauth to force clients to rogue AP?", default=True)

        twin = EvilTwin(
            ap_interface=ap_iface,
            deauth_interface=deauth_iface,
            target_bssid=bssid,
            target_ssid=ssid,
            target_channel=channel,
        )
        twin.start(deauth_continuous=deauth)

    def action_targetwl(self):
        """Generate targeted OSINT-based wordlist."""
        from target_wordlist import generate_targeted_wordlist, interactive_generate

        interactive = Confirm.ask("Use interactive mode (guided prompts)?", default=True)

        if interactive:
            interactive_generate()
        else:
            keywords_str = Prompt.ask("Keywords (comma-separated: company, name, address, etc.)")
            keywords = [k.strip() for k in keywords_str.split(",")]
            output = Prompt.ask("Output path (leave blank for auto)", default="")
            wifi_patterns = Confirm.ask("Include WiFi-specific patterns?", default=True)
            generate_targeted_wordlist(
                keywords,
                output_path=output.strip() or None,
                include_wifi_patterns=wifi_patterns,
            )

    def action_mac(self):
        """MAC address management."""
        from mac_changer import change_mac, restore_mac, print_mac_info

        if not self.require_root_check("mac"):
            return

        iface = self.prompt_interface()

        table = Table(box=box.SIMPLE, show_header=False)
        table.add_column("#", style="bold cyan", width=4)
        table.add_column("Action", width=40)
        table.add_row("1", "Show current MAC address")
        table.add_row("2", "Set random MAC (vendor-preserving)")
        table.add_row("3", "Set fully random MAC")
        table.add_row("4", "Set a specific MAC address")
        table.add_row("5", "Restore original MAC address")
        self.console.print(table)

        choice = Prompt.ask("Action", choices=["1", "2", "3", "4", "5"], default="1")

        if choice == "1":
            print_mac_info(iface)
        elif choice == "2":
            change_mac(iface, preserve_vendor=True)
        elif choice == "3":
            change_mac(iface, preserve_vendor=False)
        elif choice == "4":
            new_mac = Prompt.ask("New MAC address")
            change_mac(iface, new_mac=new_mac)
        elif choice == "5":
            original = Prompt.ask("Original MAC address to restore")
            restore_mac(iface, original)

    # ─── MAIN LOOP ──────────────────────────────────────────────────────

    def run(self):
        """Main TUI loop."""
        self.show_banner()
        self.show_disclaimer()

        while True:
            try:
                category = self.show_main_menu()
                if category == "exit":
                    self.console.print("\n[dim]Goodbye. Stay ethical.[/dim]\n")
                    break

                action = self.show_category_menu(category)
                if action is None:
                    continue

                # Root check
                if not self.require_root_check(action):
                    Prompt.ask("\nPress Enter to continue")
                    continue

                # Dispatch to action handler
                handler = getattr(self, f"action_{action}", None)
                if handler:
                    handler()
                else:
                    self.console.print(f"[red]Action '{action}' not implemented.[/red]")

                self.console.print()
                Prompt.ask("[dim]Press Enter to return to menu[/dim]")

            except KeyboardInterrupt:
                self.console.print("\n[yellow]Interrupted.[/yellow]")
                if self._monitor:
                    try:
                        self._monitor.disable()
                    except Exception:
                        pass
                    self._monitor = None
                continue
            except EOFError:
                break

        # Cleanup
        if self._monitor:
            try:
                self._monitor.disable()
            except Exception:
                pass


def run_tui():
    """Entry point for the TUI, called from main.py."""
    tui = TUI()
    tui.run()
