"""Result logging and reporting module.

Logs all attack attempts, timing, and results to a structured JSON
report file. Useful for thesis documentation and analysis.
"""

import os
import json
import time
from datetime import datetime, timezone

from config import BASE_DIR
from utils import print_status, print_success, print_info, Colors


REPORTS_DIR = os.path.join(BASE_DIR, "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)


class AttackReporter:
    """Logs and reports on all attack activities in a session."""

    def __init__(self, session_name=None):
        """
        Args:
            session_name: Optional name for this session. Auto-generated if None.
        """
        self.session_name = session_name or datetime.now().strftime("session_%Y%m%d_%H%M%S")
        self.report = {
            "session": self.session_name,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "finished_at": None,
            "target": {},
            "phases": [],
            "result": {
                "success": False,
                "password": None,
            },
            "system_info": self._get_system_info(),
        }
        self._phase_start = None

    def _get_system_info(self):
        """Collect basic system info for the report."""
        import platform
        import shutil

        return {
            "platform": platform.system(),
            "platform_version": platform.version(),
            "python_version": platform.python_version(),
            "tools": {
                "aircrack-ng": bool(shutil.which("aircrack-ng")),
                "hashcat": bool(shutil.which("hashcat")),
                "hcxpcapngtool": bool(shutil.which("hcxpcapngtool")),
                "hcxdumptool": bool(shutil.which("hcxdumptool")),
            },
        }

    def set_target(self, bssid, ssid=None, channel=None, encryption=None, clients=None):
        """Record target network information."""
        self.report["target"] = {
            "bssid": bssid,
            "ssid": ssid,
            "channel": channel,
            "encryption": encryption,
            "clients_count": len(clients) if clients else 0,
            "clients": list(clients) if clients else [],
        }

    def start_phase(self, name, details=None):
        """Begin a new attack phase (scan, deauth, capture, crack, etc.)."""
        self._phase_start = time.time()
        phase = {
            "name": name,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "finished_at": None,
            "duration_seconds": None,
            "success": False,
            "details": details or {},
            "errors": [],
        }
        self.report["phases"].append(phase)
        return len(self.report["phases"]) - 1

    def end_phase(self, success=False, details=None, errors=None):
        """Complete the current phase."""
        if not self.report["phases"]:
            return

        phase = self.report["phases"][-1]
        phase["finished_at"] = datetime.now(timezone.utc).isoformat()
        phase["duration_seconds"] = round(time.time() - self._phase_start, 2) if self._phase_start else 0
        phase["success"] = success

        if details:
            phase["details"].update(details)
        if errors:
            phase["errors"].extend(errors)

    def log_scan_results(self, access_points):
        """Log network scan results."""
        networks = []
        for bssid, ap in access_points.items():
            networks.append({
                "bssid": bssid,
                "ssid": ap.ssid,
                "channel": ap.channel,
                "encryption": ap.encryption,
                "signal": ap.signal,
                "is_wpa3": ap.is_wpa3,
                "clients": list(ap.clients),
            })
        return {"networks_found": len(networks), "networks": networks}

    def log_capture_result(self, pcap_path, handshake_complete, messages_captured):
        """Log handshake capture result."""
        return {
            "pcap_path": pcap_path,
            "handshake_complete": handshake_complete,
            "messages_captured": messages_captured,
        }

    def log_validation_result(self, validation_result):
        """Log capture validation result."""
        return {
            "valid": validation_result.get("valid", False),
            "score": validation_result.get("score", 0),
            "issues": validation_result.get("issues", []),
        }

    def log_crack_result(self, engine, wordlist, password=None, duration=None,
                         mutate_preset=None, mask=None):
        """Log cracking attempt result."""
        result = {
            "engine": engine,
            "wordlist": wordlist,
            "password_found": password is not None,
            "mutate_preset": mutate_preset,
            "mask": mask,
        }
        if duration:
            result["duration_seconds"] = round(duration, 2)
        return result

    def set_result(self, success, password=None):
        """Set the final result."""
        self.report["result"]["success"] = success
        self.report["result"]["password"] = password

    def finish(self):
        """Finalize and save the report."""
        self.report["finished_at"] = datetime.now(timezone.utc).isoformat()

        # Calculate total duration
        try:
            start = datetime.fromisoformat(self.report["started_at"])
            end = datetime.fromisoformat(self.report["finished_at"])
            self.report["total_duration_seconds"] = round((end - start).total_seconds(), 2)
        except Exception:
            pass

        report_path = self._save()
        self._print_summary()
        return report_path

    def _save(self):
        """Save the report to a JSON file."""
        filename = f"{self.session_name}.json"
        report_path = os.path.join(REPORTS_DIR, filename)

        with open(report_path, "w") as f:
            json.dump(self.report, f, indent=2, default=str)

        print_success(f"Report saved: {report_path}")
        return report_path

    def _print_summary(self):
        """Print a summary of the report."""
        r = self.report
        print()
        print(f"{Colors.BOLD}{'=' * 60}")
        print(f"  SESSION REPORT: {r['session']}")
        print(f"{'=' * 60}{Colors.RESET}")

        # Target
        t = r.get("target", {})
        if t:
            print(f"\n  {Colors.CYAN}Target:{Colors.RESET}")
            print(f"    SSID:       {t.get('ssid', 'N/A')}")
            print(f"    BSSID:      {t.get('bssid', 'N/A')}")
            print(f"    Encryption: {t.get('encryption', 'N/A')}")
            print(f"    Channel:    {t.get('channel', 'N/A')}")

        # Phases
        print(f"\n  {Colors.CYAN}Phases:{Colors.RESET}")
        for i, phase in enumerate(r.get("phases", []), 1):
            status = f"{Colors.GREEN}✓{Colors.RESET}" if phase["success"] else f"{Colors.RED}✗{Colors.RESET}"
            duration = phase.get("duration_seconds", "?")
            print(f"    {status} {phase['name']:<25s} {duration}s")
            if phase.get("errors"):
                for err in phase["errors"]:
                    print(f"      {Colors.RED}Error: {err}{Colors.RESET}")

        # Result
        result = r.get("result", {})
        print(f"\n  {Colors.CYAN}Result:{Colors.RESET}")
        if result.get("success"):
            print(f"    {Colors.GREEN}{Colors.BOLD}PASSWORD FOUND: {result.get('password')}{Colors.RESET}")
        else:
            print(f"    {Colors.RED}Password not found{Colors.RESET}")

        # Timing
        total = r.get("total_duration_seconds")
        if total:
            minutes = int(total // 60)
            seconds = int(total % 60)
            print(f"\n  {Colors.CYAN}Total time:{Colors.RESET} {minutes}m {seconds}s")

        print(f"\n{'=' * 60}")


def list_reports():
    """List all saved reports."""
    reports = sorted(
        [f for f in os.listdir(REPORTS_DIR) if f.endswith(".json")],
        reverse=True
    )

    if not reports:
        print_info("No reports found.")
        return

    print(f"\n{Colors.BOLD}Saved Reports:{Colors.RESET}\n")
    for filename in reports:
        path = os.path.join(REPORTS_DIR, filename)
        try:
            with open(path, "r") as f:
                data = json.load(f)
            success = data.get("result", {}).get("success", False)
            target_ssid = data.get("target", {}).get("ssid", "N/A")
            status = f"{Colors.GREEN}CRACKED{Colors.RESET}" if success else f"{Colors.RED}FAILED{Colors.RESET}"
            total = data.get("total_duration_seconds", 0)
            print(f"  {filename:<45s} {target_ssid:<20s} {status}")
        except Exception:
            print(f"  {filename:<45s} (corrupt)")

    print()


def load_report(report_name):
    """Load a report by name or path."""
    if os.path.isfile(report_name):
        path = report_name
    else:
        path = os.path.join(REPORTS_DIR, report_name)
        if not path.endswith(".json"):
            path += ".json"

    if not os.path.isfile(path):
        print_error(f"Report not found: {path}")
        return None

    with open(path, "r") as f:
        return json.load(f)
