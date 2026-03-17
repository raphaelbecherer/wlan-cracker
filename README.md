# LAN Packet Cracker

A wireless security auditing tool for **educational purposes** and **authorized penetration testing**. Built as a diploma thesis project.

Automates WPA/WPA2 handshake capture via deauthentication attacks and integrates with aircrack-ng/hashcat for password cracking. Features an interactive terminal UI (TUI) powered by Rich.

## Legal Disclaimer

**This tool is provided for educational and authorized security testing purposes ONLY.**

- You **must** have explicit written permission from the network owner before using this tool on any network.
- Unauthorized access to computer networks is a criminal offense in most jurisdictions, including but not limited to the **Computer Fraud and Abuse Act (CFAA)** in the US, **Computer Misuse Act 1990** in the UK, and equivalent laws worldwide.
- The authors and contributors assume **no liability** for misuse of this software.
- By using this tool, you agree that you are solely responsible for your actions and will only use it in a lawful manner.
- This tool is intended for: security researchers, penetration testers with authorization, students in controlled lab environments, and network administrators testing their own infrastructure.

**If you do not agree with these terms, do not use this software.**

## Features

### Reconnaissance
- **Network scanning** with WPA3/SAE detection
- **5 GHz support** (UNII-1 through UNII-3 bands)
- **Signal strength sorting** and band breakdown
- **MAC address randomization** with vendor-preserving mode
- **Automatic channel detection** for target BSSIDs

### Attacks
- **Deauthentication** — single client, broadcast, or multi-client
- **Deauth evasion** — randomized timing, rotating reason codes, variable burst sizes
- **Handshake capture** — active (with deauth) or passive (stealth) mode
- **PMKID capture** — clientless attack, no connected stations needed
- **WPS PIN attack** — Pixie Dust offline attack + brute-force via reaver/bully
- **Evil Twin** — rogue AP with captive portal using hostapd/dnsmasq

### Cracking
- **aircrack-ng** (CPU) and **hashcat** (GPU, mode 22000)
- **Dictionary**, **mask/brute-force**, **combinator**, **hybrid**, and **PRINCE** attacks
- **Wordlist mutations** with light/moderate/aggressive presets
- **PMK precomputation** via airolib-ng for instant cracking
- **Targeted wordlist generation** from OSINT keywords
- **Session save/restore** for long hashcat runs

### Utilities
- **Full auto pipeline** — scan, select, capture, validate, crack in one command
- **Capture validation** with quality scoring
- **JSON session reports**
- **GPU benchmarking**

## Requirements

### System
- **Linux** (Kali Linux recommended)
- A wireless adapter that supports **monitor mode** and **packet injection**
- Root/sudo privileges

### Python
- Python 3.8+
- Dependencies: `scapy`, `rich`

### External Tools

| Tool | Required For | Pre-installed on Kali |
|------|--------------|-----------------------|
| aircrack-ng | Core cracking, monitor mode | Yes |
| hashcat | GPU cracking | Yes |
| hcxtools | PMKID/hc22000 conversion | Yes |
| reaver | WPS attacks | Yes |
| bully | WPS attacks (alternative) | Yes |
| hostapd | Evil Twin AP | Yes |
| dnsmasq | Evil Twin DNS/DHCP | Yes |
| macchanger | MAC spoofing | Yes |

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/lan-packet-cracker.git
cd lan-packet-cracker
pip install -r requirements.txt
```

On Kali Linux, all external tools are pre-installed. On other distros:

```bash
sudo apt install aircrack-ng hashcat hcxtools reaver bully hostapd dnsmasq macchanger
```

## Usage

### Interactive TUI (recommended)

```bash
sudo python main.py
```

This launches the interactive terminal UI with menus for all features.

### CLI Mode

Every feature is also available as a CLI subcommand:

```bash
# Scan for networks
sudo python main.py scan -i wlan0 --band all

# Capture handshake
sudo python main.py capture -i wlan0 -b AA:BB:CC:DD:EE:FF --validate

# Passive capture (stealth)
sudo python main.py capture -i wlan0 -b AA:BB:CC:DD:EE:FF --passive

# Crack with wordlist
python main.py crack --pcap captures/handshake.pcap -w rockyou --engine hashcat

# Mask attack (8-digit PINs)
python main.py crack --pcap captures/handshake.pcap --mask "?d?d?d?d?d?d?d?d"

# Full auto pipeline
sudo python main.py auto -i wlan0 -w rockyou --engine hashcat --mutate moderate

# PMKID attack
sudo python main.py pmkid -i wlan0 -b AA:BB:CC:DD:EE:FF

# WPS Pixie Dust
sudo python main.py wps -i wlan0 -b AA:BB:CC:DD:EE:FF --pixie-only

# MAC randomization
sudo python main.py mac -i wlan0 --random --preserve-vendor
```

Run `python main.py --help` for all options.

## Project Structure

```
lan-packet-cracker/
├── main.py              # CLI entry point (argparse + TUI dispatch)
├── tui.py               # Interactive terminal UI (Rich)
├── config.py            # Constants, paths, channel definitions
├── utils.py             # Color output, platform detection, helpers
├── monitor.py           # Monitor mode management, channel hopping
├── scanner.py           # Network discovery, WPA3 detection
├── deauth.py            # Deauthentication attacks with evasion
├── capture.py           # Handshake capture (active + passive)
├── cracker.py           # aircrack-ng integration
├── hashcat_cracker.py   # hashcat GPU integration
├── pmkid.py             # PMKID clientless attack
├── validator.py         # Capture quality validation
├── wps_attack.py        # WPS PIN attacks (reaver/bully)
├── evil_twin.py         # Rogue AP with captive portal
├── mac_changer.py       # MAC address spoofing
├── mutations.py         # Wordlist mutation engine
├── wordlists.py         # Wordlist download/merge manager
├── target_wordlist.py   # OSINT-based wordlist generator
├── pmk_precomp.py       # PMK precomputation (airolib-ng)
├── reporter.py          # JSON session reporting
└── requirements.txt
```

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

This software is provided "as is", without warranty of any kind. The authors are not responsible for any damages or legal consequences resulting from its use. Users are solely responsible for ensuring they have proper authorization before using this tool on any network.
