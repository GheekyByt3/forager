#!/usr/bin/env python3
"""
Forager - Internal Network Recon Automation Tool

Automates the internal pentest recon workflow:
  1. Resolve Domain Controller IPs from DNS
  2. Build subnets from DC IPs
  3. Ping sweep to find live hosts
  4. Port scan live hosts
  5. Parse and categorize results
  6. Web screenshots via gowitness
  7. SMB enumeration via NetExec

Requirements:
  - nslookup (phase 1)
  - nmap (phases 3-4, --snmp, --ipmi)
  - gowitness (phase 6, --screenshots) — optional, skipped if not installed
  - nxc / NetExec (phase 7)

Usage:
    python3 forager.py corp.local              # interactive phase selection
    python3 forager.py corp.local --full-scan  # run all phases
    python3 forager.py --live-hosts hosts.txt  # start from phase 4
    python3 forager.py -h                      # full help
"""

VERSION = "1.1.0"

import argparse
import csv
import subprocess
import sys
import re
import json
import shutil
import ipaddress
import time
from datetime import datetime
from pathlib import Path


# ANSI color codes
class C:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    ORANGE  = "\033[38;5;208m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"


PHASES = {
    1: "Resolve Domain Controller IPs from DNS",
    2: "Build subnets from DC IPs",
    3: "Ping sweep to find live hosts",
    4: "Port scan live hosts",
    5: "Parse and categorize results",
    6: "Web screenshots via gowitness",
    7: "SMB enumeration via NetExec",
}

MAX_PHASE = 7

# Port categories for result parsing
PORT_CATEGORIES = {
    "web": [80, 443, 3000, 4443, 5480, 5601, 8000, 8008, 8009, 8080, 8081,
            8090, 8161, 8222, 8333, 8443, 8500, 8880, 8983, 9000, 9080,
            9090, 9200, 9443, 10000],
    "rdp": [3389],
    "ssh": [22],
    "smb": [445],
    "winrm": [5985, 5986],
    "mssql":    list(range(1433, 1451)),
    "database": [1521, 1529, 3306, 5432, 50000],
    "ftp": [21],
    "ldap": [389, 636],
    "vnc": [5800, 5900],
    "dns": [53],
    "nfs": [111, 2049],
    "redis": [6379],
}

# Full target port list
TARGET_PORTS = (
    "21-23,25,53,79,80,111,389,443,445,513,548,636,689,"
    "902,1099,1433-1450,1494,1521-1529,1581,1585,1588,"
    "2010,2049,2301,2381,2598,3000,3306,3389,4070,4443,4444,4545,"
    "4848,4899,5005,5432,5480,5601,5631,5800,5900,5985-5986,"
    "6000-6005,6379,7000-7002,8000,8008,8009,8080,8081,8090,8161,"
    "8222,8333,8443,8500,8880,8983,"
    "9000,9080,9084,9090,9200,9443,9999,10000,50000,50013"
)

# Ports that default to HTTPS
HTTPS_PORTS = {443, 4443, 8443, 9443}

STATE_FILE = ".forager_state.json"

# Global quiet mode flag
QUIET = False


def print_banner():
    """Print the tool banner. Call before argparse so it shows on -h too."""
    try:
        import pyfiglet
        raw = pyfiglet.figlet_format("FORAGER", font="big_money-nw")
    except Exception:
        raw = (
            "  ███████╗ ██████╗ ██████╗  █████╗  ██████╗ ███████╗██████╗ \n"
            "  ██╔════╝██╔═══██╗██╔══██╗██╔══██╗██╔════╝ ██╔════╝██╔══██╗\n"
            "  █████╗  ██║   ██║██████╔╝███████║██║  ███╗█████╗  ██████╔╝\n"
            "  ██╔══╝  ██║   ██║██╔══██╗██╔══██║██║   ██║██╔══╝  ██╔══██╗\n"
            "  ██║     ╚██████╔╝██║  ██║██║  ██║╚██████╔╝███████╗██║  ██║\n"
            "  ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝\n"
        )

    raw = raw.rstrip()
    print(f"\n\n{C.CYAN}{C.BOLD}{raw}{C.RESET}\n")
    print(f"  {C.DIM}Automated network enumeration tool for pentesters{C.RESET}")
    print(f"  {C.DIM}Created with <3 by Prithvi Chintha{C.RESET}\n")
    print(f"  {C.ORANGE}{C.BOLD}[ ! ]{C.RESET}  Noisy by design. For Authorized Pentests only.\n")


def log(msg, level="info", hint=None, indent=0):
    styles = {
        "info": (f"{C.CYAN}[*]{C.RESET}", ""),
        "ok":   (f"{C.GREEN}[+]{C.RESET}", C.GREEN),
        "warn": (f"{C.YELLOW}[!]{C.RESET}", C.YELLOW),
        "err":  (f"{C.RED}[-]{C.RESET}",   C.RED),
    }
    prefix, color = styles.get(level, styles["info"])
    pad = "    " * indent
    if level == "err":
        print(f"\n  {C.RED}{C.BOLD}[ ERROR ]{C.RESET}  {C.RED}{msg}{C.RESET}")
        if hint:
            print(f"  {C.DIM}{'·'*9}{C.RESET}  {C.ORANGE}↳  {hint}{C.RESET}")
        print()
    elif QUIET and level == "info":
        pass  # suppress verbose info in quiet mode
    else:
        print(f"{pad}{prefix} {color}{msg}{C.RESET}")


def phase_header(num, title):
    """Print a boxed phase header with divider."""
    print()
    print(f"{C.BOLD}{C.CYAN}┌─ Phase {num}: {title} {'─' * max(2, 50 - len(title))}{C.RESET}")


def phase_footer(num, elapsed):
    """Print a phase completion footer."""
    print(f"{C.BOLD}{C.CYAN}└─ Phase {num} complete{C.RESET} {C.DIM}({fmt_duration(elapsed)}){C.RESET}")


def section_header(title):
    """Print a boxed section header (for non-phase operations like additional scans)."""
    print()
    print(f"{C.BOLD}{C.MAGENTA}┌─ {title} {'─' * max(2, 55 - len(title))}{C.RESET}")


def section_footer(title, elapsed):
    """Print a section completion footer."""
    print(f"{C.BOLD}{C.MAGENTA}└─ {title} complete{C.RESET} {C.DIM}({fmt_duration(elapsed)}){C.RESET}")


def run(cmd, shell=True, check=True, capture=True):
    """Run a shell command and return stdout."""
    if not QUIET:
        log(f"Running: {cmd}")
    result = subprocess.run(
        cmd, shell=shell, check=check,
        capture_output=capture, text=True
    )
    return result.stdout.strip() if capture else ""


def fmt_duration(seconds):
    """Format seconds into human-readable duration."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes = int(seconds // 60)
    secs = seconds % 60
    if minutes < 60:
        return f"{minutes}m {secs:.0f}s"
    hours = minutes // 60
    mins = minutes % 60
    return f"{hours}h {mins}m {secs:.0f}s"


def save_state(output_dir, phase, domain, data=None):
    state_path = output_dir / STATE_FILE
    state = {}
    if state_path.exists():
        state = json.loads(state_path.read_text())
    state["domain"] = domain
    state["last_phase"] = phase
    state["timestamp"] = datetime.now().isoformat()
    if data:
        state.update(data)
    state_path.write_text(json.dumps(state, indent=2))


def load_state(output_dir):
    state_path = output_dir / STATE_FILE
    if state_path.exists():
        return json.loads(state_path.read_text())
    return None


def check_dependencies(start_phase=1, stop_phase=MAX_PHASE, snmp=False, ipmi=False,
                       skip_gowitness=False, screenshots=False):
    """Check required tools based on which phases will run."""
    required = []
    if start_phase <= 1 <= stop_phase:
        required.append("nslookup")
    if start_phase <= 4 and stop_phase >= 3:
        required.append("nmap")
    if start_phase <= 7 <= stop_phase:
        required.append("nxc")
    if snmp or ipmi:
        if "nmap" not in required:
            required.append("nmap")
    if screenshots:
        required.append("gowitness")
    for tool in required:
        if not shutil.which(tool):
            log(f"Required tool not found: {tool}", "err")
            sys.exit(1)
    # Soft check: gowitness is optional for phase 6 — warn but don't exit
    if start_phase <= 6 <= stop_phase and not skip_gowitness:
        if shutil.which("gowitness"):
            if "gowitness" not in required:
                required.append("gowitness")
        else:
            log("gowitness not found — phase 6 (web screenshots) will be skipped", "warn")
    if required:
        log(f"Dependencies found: {', '.join(required)}", "ok")


def load_dc_ips(args, output_dir):
    """Load DC IPs from --dc-ips flag (file or comma-separated) and write to output dir."""
    dc_ips_path = Path(args.dc_ips)
    if dc_ips_path.is_file():
        dc_ips = [l.strip() for l in dc_ips_path.read_text().splitlines() if l.strip()]
        log(f"Loaded {len(dc_ips)} DC IP(s) from {dc_ips_path}", "ok")
    else:
        dc_ips = [ip.strip() for ip in args.dc_ips.split(",") if ip.strip()]
        log(f"Using provided DC IPs: {', '.join(dc_ips)}", "ok")
    dc_file = output_dir / "DC_IPs.txt"
    dc_file.write_text("\n".join(dc_ips) + "\n")
    return dc_ips


def validate_input_files(args):
    """Validate all user-provided input file paths upfront."""
    if args.dc_ips:
        p = Path(args.dc_ips)
        # Only validate if it looks like a path (not comma-separated IPs)
        if "/" in args.dc_ips or p.suffix:
            if not p.is_file():
                log(f"DC IPs file not found: {args.dc_ips}", "err")
                sys.exit(1)
    if args.subnets:
        if not Path(args.subnets).is_file():
            log(f"Subnets file not found: {args.subnets}", "err")
            sys.exit(1)
    if args.live_hosts:
        if not Path(args.live_hosts).is_file():
            log(f"Live hosts file not found: {args.live_hosts}", "err")
            sys.exit(1)


# ─── Phase functions ────────────────────────────────────────────


def phase1_resolve_dcs(domain, output_dir):
    """Resolve Domain Controller IPs via DNS SRV records."""
    phase_header(1, f"Resolve DCs for {domain}")

    dc_ips_file = output_dir / "DC_IPs.txt"
    srv_query = f"_ldap._tcp.dc._msdcs.{domain}"

    # Step 1: Query SRV records to get DC hostnames
    log(f"Querying SRV record: {srv_query}")
    raw = run(f"nslookup -type=SRV {srv_query} 2>/dev/null || true")

    dc_hostnames = []
    for line in raw.splitlines():
        line = line.strip()
        # SRV lines look like: "svr hostname = dc01.corp.local"
        if "svr hostname" in line.lower():
            parts = line.split("=")
            if len(parts) == 2:
                hostname = parts[1].strip().rstrip(".")
                if hostname:
                    dc_hostnames.append(hostname)

    if not dc_hostnames:
        log("No SRV records found — falling back to A record lookup", "warn")
        raw = run(f"nslookup {domain} 2>/dev/null || true")
        ips = []
        for line in raw.splitlines():
            line = line.strip()
            if line.startswith("Address"):
                parts = line.split()
                if len(parts) >= 2:
                    candidate = parts[-1]
                    try:
                        ipaddress.ip_address(candidate)
                        ips.append(candidate)
                    except ValueError:
                        continue
        if not ips:
            log("No IPs resolved. Check domain name and DNS config", "err")
            sys.exit(1)
        ips = list(dict.fromkeys(ips))
        dc_ips_file.write_text("\n".join(ips) + "\n")
        log(f"Found {len(ips)} IP(s) via A record fallback: {', '.join(ips)}", "ok")
        return ips

    log(f"Found {len(dc_hostnames)} DC hostname(s): {', '.join(dc_hostnames)}", "ok")

    # Step 2: Resolve each DC hostname to an IP
    ips = []
    for hostname in dc_hostnames:
        raw = run(f"nslookup {hostname} 2>/dev/null || true")
        for line in raw.splitlines():
            line = line.strip()
            if line.startswith("Address"):
                parts = line.split()
                if len(parts) >= 2:
                    candidate = parts[-1]
                    try:
                        ipaddress.ip_address(candidate)
                        ips.append(candidate)
                        log(f"{hostname} -> {candidate}", "ok", indent=1)
                        break
                    except ValueError:
                        continue
        else:
            log(f"Could not resolve IP for {hostname}", "warn", indent=1)

    if not ips:
        log("No DC IPs resolved. Check domain name and DNS config", "err")
        sys.exit(1)

    ips = list(dict.fromkeys(ips))
    dc_ips_file.write_text("\n".join(ips) + "\n")
    log(f"Resolved {len(ips)} DC IP(s): {', '.join(ips)}", "ok")
    return ips


def phase2_build_subnets(dc_ips, subnet_mask, output_dir):
    """Build subnet list from DC IPs."""
    phase_header(2, f"Build /{subnet_mask} subnets from DC IPs")

    subnets_file = output_dir / "DC_subnets.txt"
    subnets = set()

    for ip in dc_ips:
        try:
            network = ipaddress.ip_network(f"{ip}/{subnet_mask}", strict=False)
            subnets.add(str(network))
        except ValueError:
            log(f"Invalid IP skipped: {ip}", "warn")

    subnets = sorted(subnets)
    subnets_file.write_text("\n".join(subnets) + "\n")
    log(f"Generated {len(subnets)} subnet(s)", "ok")
    return subnets


def phase3_ping_sweep(output_dir, parallelism=100, rate=None):
    """Fast ping sweep to find live hosts."""
    phase_header(3, "Ping sweep for live hosts")

    subnets_file = output_dir / "DC_subnets.txt"
    ping_output = output_dir / "ping_sweep.gnmap"
    live_hosts_file = output_dir / "live_hosts.txt"

    nmap_cmd = (
        f"nmap -sn -T5 -v --min-parallelism {parallelism} "
        f"-iL {subnets_file} -oG {ping_output}"
    )
    if rate:
        nmap_cmd += f" --min-rate {rate}"

    run(nmap_cmd, capture=False)

    live_hosts = []
    if ping_output.exists():
        for line in ping_output.read_text().splitlines():
            if "Status: Up" in line:
                parts = line.split()
                if len(parts) >= 2:
                    live_hosts.append(parts[1])

    live_hosts = list(dict.fromkeys(live_hosts))
    live_hosts_file.write_text("\n".join(live_hosts) + "\n")
    if not live_hosts:
        log("Ping sweep found 0 live hosts — nothing to scan", "warn")
    else:
        log(f"Found {len(live_hosts)} live host(s)", "ok")
    return live_hosts


def phase4_port_scan(output_dir, ports=None, max_retries=5):
    """Targeted port scan against live hosts."""
    phase_header(4, "Port scan live hosts")

    live_hosts_file = output_dir / "live_hosts.txt"
    nmap_dir = output_dir / "nmap_scans"
    nmap_dir.mkdir(exist_ok=True)

    scan_base = nmap_dir / "port_scan"
    ports = ports or TARGET_PORTS

    host_count = len(live_hosts_file.read_text().strip().splitlines())
    log(f"Scanning {host_count} hosts on ports: {ports}")

    nmap_cmd = (
        f"nmap -sS -sV -Pn --open -p {ports} "
        f"-oA {scan_base} -iL {live_hosts_file} "
        f"-v --max-retries {max_retries}"
    )

    run(nmap_cmd, capture=False)
    log("Port scan complete", "ok")


def phase5_parse_results(output_dir):
    """Parse nmap results into categorized host files."""
    phase_header(5, "Parse scan results")

    nmap_file = output_dir / "nmap_scans" / "port_scan.nmap"
    results_dir = output_dir / "parsed_results"
    results_dir.mkdir(exist_ok=True)

    if not nmap_file.exists():
        log("Nmap output file not found", "err")
        return

    content = nmap_file.read_text()

    hosts = {}
    current_host = None

    for line in content.splitlines():
        host_match = re.match(
            r"Nmap scan report for (?:(\S+) \((\S+)\)|(\S+))", line
        )
        if host_match:
            hostname = host_match.group(1) or ""
            ip = host_match.group(2) or host_match.group(3)
            current_host = ip
            hosts[current_host] = {"hostname": hostname, "ports": []}
            continue

        port_match = re.match(r"\s*(\d+)/tcp\s+open\s+(\S+)\s*(.*)", line)
        if port_match and current_host:
            port_num = int(port_match.group(1))
            service = port_match.group(2)
            version = port_match.group(3).strip()
            hosts[current_host]["ports"].append({
                "port": port_num,
                "service": service,
                "version": version,
            })

    categorized = {cat: [] for cat in PORT_CATEGORIES}

    for ip, info in hosts.items():
        open_ports = [p["port"] for p in info["ports"]]
        for category, cat_ports in PORT_CATEGORIES.items():
            if any(p in cat_ports for p in open_ports):
                label = f"{ip}"
                if info["hostname"]:
                    label = f"{ip} ({info['hostname'].upper()})"
                categorized[category].append(label)

    for category, host_list in categorized.items():
        if host_list:
            out_file = results_dir / f"{category}_hosts.txt"
            out_file.write_text("\n".join(sorted(host_list)) + "\n")
            log(f"{category}: {len(host_list)} host(s) -> {out_file.name}", "ok", indent=1)

    summary_file = results_dir / "full_summary.csv"
    with open(summary_file, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["IP", "Hostname", "Port", "Service", "Version"])
        for ip, info in sorted(hosts.items()):
            for p in info["ports"]:
                writer.writerow([ip, info["hostname"] or "", p["port"], p["service"], p["version"]])

    total_ports = sum(len(info["ports"]) for info in hosts.values())
    log(f"Full summary -> parsed_results/{summary_file.name}", "ok")
    log(f"Total hosts with open ports: {len(hosts)}", "ok")
    return {"hosts_with_open_ports": len(hosts), "total_open_ports": total_ports}


def phase6_web_screenshots(output_dir):
    """Capture web screenshots via gowitness v3."""
    phase_header(6, "Web screenshots via gowitness")

    if not shutil.which("gowitness"):
        log("gowitness not found — skipping screenshots (install gowitness to enable this phase)", "warn")
        return None

    summary_file = output_dir / "parsed_results" / "full_summary.csv"
    gowitness_dir = output_dir / "gowitness_results"
    gowitness_dir.mkdir(exist_ok=True)

    if not summary_file.exists():
        log("full_summary.csv not found — run phase 5 first", "err")
        return None

    # Build URL list from hosts with web ports open
    web_ports = set(PORT_CATEGORIES["web"])
    urls = set()

    with open(summary_file, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            port = int(row["Port"])
            if port in web_ports:
                ip = row["IP"]
                if port == 80:
                    urls.add(f"http://{ip}")
                elif port == 443:
                    urls.add(f"https://{ip}")
                elif port in HTTPS_PORTS:
                    urls.add(f"https://{ip}:{port}")
                else:
                    urls.add(f"http://{ip}:{port}")

    if not urls:
        log("No hosts with web ports found — skipping screenshots", "warn")
        return None

    url_file = gowitness_dir / "target_urls.txt"
    url_file.write_text("\n".join(sorted(urls)) + "\n")
    log(f"Found {len(urls)} web URL(s) to screenshot", "ok")

    screenshot_path = gowitness_dir / "screenshots"
    screenshot_path.mkdir(exist_ok=True)
    db_path = gowitness_dir / "gowitness.sqlite3"
    db_uri = f"sqlite://{db_path.resolve()}"

    gowitness_cmd = (
        f"gowitness scan file -f {url_file} "
        f"--screenshot-path {screenshot_path} "
        f"--write-db --write-db-uri {db_uri}"
    )
    try:
        run(gowitness_cmd, capture=False)
    except subprocess.CalledProcessError as e:
        log(f"gowitness scan failed (exit {e.returncode}) — continuing", "warn")
        return None

    log(f"Screenshots saved -> gowitness_results/screenshots/", "ok")
    log(f"To browse results, run:", "info")
    log(f"  gowitness report server --db-uri {db_uri}", "info")

    return {"screenshot_urls": len(urls)}


def phase7_smb_enum(output_dir):
    """Run nxc smb against live hosts and parse results."""
    phase_header(7, "SMB enumeration via NetExec")

    live_hosts_file = output_dir / "live_hosts.txt"
    if not live_hosts_file.exists():
        log("live_hosts.txt not found — cannot run SMB enumeration", "err")
        return {}

    smb_dir = output_dir / "nxc_smb_parsed_results"
    smb_dir.mkdir(exist_ok=True)

    raw_output_file = smb_dir / "smb_connection_scan.txt"

    nxc_cmd = f"nxc smb {live_hosts_file}"
    raw = run(nxc_cmd, check=False)

    raw_output_file.write_text(raw + "\n")
    log(f"Raw output saved -> nxc_smb_parsed_results/{raw_output_file.name}", "ok")

    signing_disabled = []
    relay_targets = []
    smbv1_enabled = []
    os_hosts = {}

    for line in raw.splitlines():
        if "445" not in line:
            continue

        parts = line.split()
        if len(parts) < 4:
            continue

        ip = None
        hostname = None

        for part in parts:
            try:
                ipaddress.ip_address(part)
                ip = part
                break
            except ValueError:
                continue

        if not ip:
            continue

        name_match = re.search(r'\(name:([^)]+)\)', line)
        if name_match:
            hostname = name_match.group(1)
        else:
            hostname = parts[3] if len(parts) > 3 else None

        # Consistent format: "IP (HOSTNAME)" with uppercase hostname, or just "IP"
        label = f"{ip} ({hostname.upper()})" if hostname and hostname != ip else ip

        signing_match = re.search(r'\(signing:(True|False)\)', line)
        if signing_match and signing_match.group(1) == "False":
            signing_disabled.append(label)
            relay_targets.append(f"smb://{ip}")

        smbv1_match = re.search(r'\(SMBv1:(True|False)\)', line)
        if smbv1_match and smbv1_match.group(1) == "True":
            smbv1_enabled.append(label)

        os_match = re.search(r'Windows\s+(Server\s+\d+|[\d.]+)', line, re.IGNORECASE)
        if os_match:
            os_ver = os_match.group(0).strip()
            os_key = os_ver.replace(" ", "_")
            if os_key not in os_hosts:
                os_hosts[os_key] = []
            os_hosts[os_key].append(label)

    files_written = 0
    smb_stats = {}

    if signing_disabled:
        f = smb_dir / "smb_signing_disabled_hosts.txt"
        f.write_text("\n".join(sorted(set(signing_disabled))) + "\n")
        count = len(set(signing_disabled))
        log(f"SMB signing disabled: {count} host(s) -> {f.name}", "ok", indent=1)
        smb_stats["signing_disabled"] = count
        files_written += 1

    if relay_targets:
        f = smb_dir / "smb_relay_targets.txt"
        f.write_text("\n".join(sorted(set(relay_targets))) + "\n")
        count = len(set(relay_targets))
        log(f"SMB relay targets: {count} host(s) -> {f.name}", "ok", indent=1)
        smb_stats["relay_targets"] = count
        files_written += 1

    if smbv1_enabled:
        f = smb_dir / "smbv1_enabled_hosts.txt"
        f.write_text("\n".join(sorted(set(smbv1_enabled))) + "\n")
        count = len(set(smbv1_enabled))
        log(f"SMBv1 enabled: {count} host(s) -> {f.name}", "ok", indent=1)
        smb_stats["smbv1_enabled"] = count
        files_written += 1

    for os_key, hosts in sorted(os_hosts.items()):
        f = smb_dir / f"{os_key}_hosts.txt"
        f.write_text("\n".join(sorted(set(hosts))) + "\n")
        log(f"{os_key.replace('_', ' ')}: {len(set(hosts))} host(s) -> {f.name}", "ok", indent=1)
        files_written += 1

    if files_written == 0:
        log("No SMB hosts found or parsed", "warn")
    else:
        log(f"SMB results saved to {smb_dir.name}/", "ok")

    return smb_stats


def parse_gnmap_hosts(gnmap_file):
    """Parse an nmap .gnmap file and return a sorted list of 'IP (HOSTNAME)' entries
    for hosts with at least one open port. Hostname is uppercased."""
    if not gnmap_file.exists():
        return []
    entries = set()
    for line in gnmap_file.read_text().splitlines():
        if not line.startswith("Host:") or "Ports:" not in line:
            continue
        if "/open/" not in line:
            continue
        # Format: "Host: 10.0.1.15 (hostname.corp.local) Ports: ..."
        m = re.match(r"Host:\s+(\S+)\s+\(([^)]*)\)", line)
        if not m:
            continue
        ip, hostname = m.group(1), m.group(2).strip()
        label = f"{ip} ({hostname.upper()})" if hostname else ip
        entries.add(label)
    return sorted(entries)


def run_snmp_scan(output_dir):
    """Run UDP SNMP scan against live hosts."""
    section_header("SNMP scan (UDP 161/162)")

    live_hosts_file = output_dir / "live_hosts.txt"
    if not live_hosts_file.exists():
        log("live_hosts.txt not found — cannot run SNMP scan", "err")
        return

    nmap_dir = output_dir / "nmap_scans"
    nmap_dir.mkdir(exist_ok=True)
    scan_base = nmap_dir / "snmp_scan"

    nmap_cmd = (
        f"nmap -p 161,162 --open -sU -v -Pn "
        f"-iL {live_hosts_file} -oA {scan_base}"
    )
    try:
        run(nmap_cmd, capture=False)
    except subprocess.CalledProcessError as e:
        log(f"SNMP scan failed (exit {e.returncode}) — continuing", "warn")
        return

    # Parse results into IP (HOSTNAME) list
    hosts = parse_gnmap_hosts(Path(f"{scan_base}.gnmap"))
    if hosts:
        results_dir = output_dir / "parsed_results"
        results_dir.mkdir(exist_ok=True)
        out_file = results_dir / "snmp_hosts.txt"
        out_file.write_text("\n".join(hosts) + "\n")
        log(f"snmp: {len(hosts)} host(s) -> {out_file.name}", "ok", indent=1)


def run_ipmi_scan(output_dir):
    """Run UDP IPMI scan against live hosts."""
    section_header("IPMI scan (UDP 623)")

    live_hosts_file = output_dir / "live_hosts.txt"
    if not live_hosts_file.exists():
        log("live_hosts.txt not found — cannot run IPMI scan", "err")
        return

    nmap_dir = output_dir / "nmap_scans"
    nmap_dir.mkdir(exist_ok=True)
    scan_base = nmap_dir / "ipmi_hosts_scan"

    nmap_cmd = (
        f"nmap -sU -p 623 -Pn --open --script ipmi-version "
        f"-iL {live_hosts_file} -oA {scan_base}"
    )
    try:
        run(nmap_cmd, capture=False)
    except subprocess.CalledProcessError as e:
        log(f"IPMI scan failed (exit {e.returncode}) — continuing", "warn")
        return

    # Parse results into IP (HOSTNAME) list
    hosts = parse_gnmap_hosts(Path(f"{scan_base}.gnmap"))
    if hosts:
        results_dir = output_dir / "parsed_results"
        results_dir.mkdir(exist_ok=True)
        out_file = results_dir / "ipmi_hosts.txt"
        out_file.write_text("\n".join(hosts) + "\n")
        log(f"ipmi: {len(hosts)} host(s) -> {out_file.name}", "ok", indent=1)


def run_screenshots_scan(output_dir):
    """Run gowitness directly against live hosts (no parsed results needed)."""
    section_header("Screenshots scan (gowitness)")

    if not shutil.which("gowitness"):
        log("gowitness not found — install gowitness to use --screenshots", "err")
        return

    live_hosts_file = output_dir / "live_hosts.txt"
    if not live_hosts_file.exists():
        log("live_hosts.txt not found — cannot run screenshots scan", "err")
        return

    gowitness_dir = output_dir / "gowitness_results"
    gowitness_dir.mkdir(exist_ok=True)
    screenshot_path = gowitness_dir / "screenshots"
    screenshot_path.mkdir(exist_ok=True)
    db_path = gowitness_dir / "gowitness.sqlite3"
    db_uri = f"sqlite://{db_path.resolve()}"

    gowitness_cmd = (
        f"gowitness scan file -f {live_hosts_file} "
        f"--screenshot-path {screenshot_path} "
        f"--write-db --write-db-uri {db_uri}"
    )
    try:
        run(gowitness_cmd, capture=False)
    except subprocess.CalledProcessError as e:
        log(f"gowitness scan failed (exit {e.returncode}) — continuing", "warn")
        return

    log(f"Screenshots saved -> gowitness_results/screenshots/", "ok")
    log(f"To browse results, run:", "info")
    log(f"  gowitness report server --db-uri {db_uri}", "info")


# ─── Interactive prompt ─────────────────────────────────────────


def prompt_phase_selection():
    """Interactively ask the user which phases to run."""
    print(f"\n{C.BOLD}{C.WHITE}  SELECT PHASES{C.RESET}")
    print(f"  {C.DIM}{'─'*44}{C.RESET}")
    for n, desc in PHASES.items():
        print(f"  {C.CYAN}{n}{C.RESET}  {desc}")
    print(f"  {C.DIM}{'─'*44}{C.RESET}\n")

    def read_phase(prompt):
        while True:
            raw = input(f"  {C.BOLD}{prompt}{C.RESET} ").strip()
            if raw.lower() == "all":
                return None
            if raw.isdigit() and 1 <= int(raw) <= MAX_PHASE:
                return int(raw)
            print(f"  {C.YELLOW}[!]{C.RESET} Enter a number 1-{MAX_PHASE} or 'all'")

    print(f"  {C.DIM}Enter phase numbers (1-{MAX_PHASE}) or 'all' to run everything{C.RESET}\n")
    start = read_phase("Start phase:")
    if start is None:
        return 1, MAX_PHASE

    stop = read_phase("Stop phase: ")
    if stop is None:
        stop = MAX_PHASE

    if stop < start:
        print(f"  {C.RED}[!]{C.RESET} Stop phase cannot be less than start phase — running phase {start} only")
        stop = start

    print()
    return start, stop


# ─── CLI setup ──────────────────────────────────────────────────


class ForagerArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage()
        print(f"\n  {C.RED}{C.BOLD}[ ERROR ]{C.RESET}  {C.RED}{message}{C.RESET}\n\n")
        sys.exit(2)


class ColoredHelpFormatter(argparse.RawTextHelpFormatter):
    def __init__(self, *args, **kwargs):
        kwargs.setdefault("max_help_position", 36)
        kwargs.setdefault("width", 90)
        super().__init__(*args, **kwargs)

    def start_section(self, heading):
        super().start_section(f"\n{C.BOLD}{C.WHITE}{heading.upper()}{C.RESET}")

    def _format_action(self, action):
        result = super()._format_action(action)
        for opt in action.option_strings:
            result = result.replace(opt, f"{C.CYAN}{opt}{C.RESET}", 1)
        if not action.option_strings and action.dest == "domain":
            result = result.replace("domain", f"{C.GREEN}domain{C.RESET}", 1)
        return result

    def _format_usage(self, usage, actions, groups, prefix):
        if prefix is None:
            prefix = f"{C.BOLD}{C.WHITE}USAGE{C.RESET}\n  "
        return super()._format_usage(usage, actions, groups, prefix)


# ─── Main ───────────────────────────────────────────────────────


def main():
    global QUIET

    prog = Path(sys.argv[0]).name
    phase_list = "\n".join(f"    {n}  {desc}" for n, desc in PHASES.items())

    parser = ForagerArgumentParser(
        description="",
        prog=prog,
        formatter_class=ColoredHelpFormatter,
        epilog=(
            f"\n{C.BOLD}{C.WHITE}EXAMPLES{C.RESET}\n"
            #
            f"\n  {C.BOLD}{C.WHITE}Basic usage:{C.RESET}\n\n"
            f"    {C.DIM}# Interactive mode — prompts which phases to run{C.RESET}\n"
            f"    {C.CYAN}python3 {prog}{C.RESET} corp.local\n\n"
            f"    {C.DIM}# Run everything (phases 1-{MAX_PHASE}) without prompting{C.RESET}\n"
            f"    {C.CYAN}python3 {prog}{C.RESET} corp.local {C.CYAN}--full-scan{C.RESET}\n"
            #
            f"\n  {C.BOLD}{C.WHITE}Phase control:{C.RESET}\n\n"
            f"    {C.DIM}# Run phases 1-3 only (DC resolve -> subnets -> ping sweep){C.RESET}\n"
            f"    {C.CYAN}python3 {prog}{C.RESET} corp.local {C.CYAN}--stop-phase{C.RESET} 3\n\n"
            f"    {C.DIM}# Run only phase 7 (SMB enumeration) on an existing output dir{C.RESET}\n"
            f"    {C.CYAN}python3 {prog}{C.RESET} corp.local {C.CYAN}--start-phase{C.RESET} 7 {C.CYAN}--stop-phase{C.RESET} 7\n\n"
            f"    {C.DIM}# Resume from where the last run stopped (prompts for stop phase){C.RESET}\n"
            f"    {C.CYAN}python3 {prog}{C.RESET} {C.CYAN}--resume{C.RESET}\n\n"
            f"    {C.DIM}# Resume but only run up to phase 4{C.RESET}\n"
            f"    {C.CYAN}python3 {prog}{C.RESET} {C.CYAN}--resume{C.RESET} {C.CYAN}--stop-phase{C.RESET} 4\n"
            #
            f"\n  {C.BOLD}{C.WHITE}Input shortcuts:{C.RESET}\n\n"
            f"    {C.DIM}# Have subnets already? Starts at phase 3 -> runs to end{C.RESET}\n"
            f"    {C.CYAN}python3 {prog}{C.RESET} {C.CYAN}--subnets{C.RESET} subnets.txt\n\n"
            f"    {C.DIM}# Have live hosts? Starts at phase 4 -> runs to end{C.RESET}\n"
            f"    {C.CYAN}python3 {prog}{C.RESET} {C.CYAN}--live-hosts{C.RESET} hosts.txt\n\n"
            f"    {C.DIM}# Have live hosts but only want port scan (no SMB enumeration)?{C.RESET}\n"
            f"    {C.CYAN}python3 {prog}{C.RESET} {C.CYAN}--live-hosts{C.RESET} hosts.txt {C.CYAN}--stop-phase{C.RESET} 5\n\n"
            f"    {C.DIM}# Have live hosts and only want SMB enumeration?{C.RESET}\n"
            f"    {C.CYAN}python3 {prog}{C.RESET} {C.CYAN}--live-hosts{C.RESET} hosts.txt {C.CYAN}--start-phase{C.RESET} 7\n"
            #
            f"\n  {C.BOLD}{C.WHITE}Additional scans:{C.RESET}\n\n"
            f"    {C.DIM}# Quick screenshots — feed hosts directly to gowitness{C.RESET}\n"
            f"    {C.CYAN}python3 {prog}{C.RESET} {C.CYAN}--live-hosts{C.RESET} hosts.txt {C.CYAN}--screenshots{C.RESET}\n\n"
            f"    {C.DIM}# Full scan + SNMP + IPMI{C.RESET}\n"
            f"    {C.CYAN}python3 {prog}{C.RESET} corp.local {C.CYAN}--full-scan{C.RESET} {C.CYAN}--snmp{C.RESET} {C.CYAN}--ipmi{C.RESET}\n\n"
            f"    {C.DIM}# Run only SNMP scan on existing output dir{C.RESET}\n"
            f"    {C.CYAN}python3 {prog}{C.RESET} {C.CYAN}--snmp{C.RESET}\n\n"
            f"    {C.DIM}# SNMP + IPMI with custom host list{C.RESET}\n"
            f"    {C.CYAN}python3 {prog}{C.RESET} {C.CYAN}--live-hosts{C.RESET} hosts.txt {C.CYAN}--snmp{C.RESET} {C.CYAN}--ipmi{C.RESET}\n"
            #
            f"\n  {C.BOLD}{C.WHITE}Output control:{C.RESET}\n\n"
            f"    {C.DIM}# Force a fresh timestamped directory{C.RESET}\n"
            f"    {C.CYAN}python3 {prog}{C.RESET} corp.local {C.CYAN}--full-scan{C.RESET} {C.CYAN}--new{C.RESET}\n\n"
            f"    {C.DIM}# Use a custom output directory{C.RESET}\n"
            f"    {C.CYAN}python3 {prog}{C.RESET} corp.local {C.CYAN}--output{C.RESET} /tmp/myrecon\n\n"
            f"    {C.DIM}# Suppress verbose output{C.RESET}\n"
            f"    {C.CYAN}python3 {prog}{C.RESET} corp.local {C.CYAN}--full-scan{C.RESET} {C.CYAN}-q{C.RESET}\n"
        ),
    )

    # --- Target ---
    parser.add_argument("domain", nargs="?", help="Target domain name")

    # --- Phase control ---
    phase_group = parser.add_argument_group("Phase control")
    phase_group.add_argument(
        "--full-scan", action="store_true",
        help=f"Run all phases without prompting (1-{MAX_PHASE})"
    )
    phase_group.add_argument(
        "--start-phase", type=int, choices=list(range(1, MAX_PHASE + 1)),
        metavar=f"{{1-{MAX_PHASE}}}",
        help=f"Start execution from a specific phase:\n{phase_list}"
    )
    phase_group.add_argument(
        "--stop-phase", type=int, choices=list(range(1, MAX_PHASE + 1)),
        metavar=f"{{1-{MAX_PHASE}}}",
        help="Stop execution after a specific phase (see --start-phase for list)"
    )
    phase_group.add_argument(
        "--resume", action="store_true",
        help="Resume from last completed phase (prompts for stop phase, or use --stop-phase)"
    )
    phase_group.add_argument(
        "--skip-gowitness", action="store_true",
        help="Skip phase 6 (gowitness web screenshots)"
    )

    # --- Input shortcuts ---
    input_group = parser.add_argument_group("Input shortcuts")
    input_group.add_argument(
        "--dc-ips", default=None,
        help="DC IPs as comma-separated values or a file path (one IP per line)"
    )
    input_group.add_argument(
        "--subnets", default=None,
        help="File of subnets (one per line, e.g. 10.0.1.0/24) — starts at phase 3"
    )
    input_group.add_argument(
        "--live-hosts", default=None,
        help="File of live hosts (one IP per line) — starts at phase 4"
    )

    # --- Scan options ---
    scan_group = parser.add_argument_group("Scan options")
    scan_group.add_argument(
        "--subnet-mask", type=int, default=24,
        help="Subnet mask for DC subnets (default: 24)"
    )
    scan_group.add_argument(
        "--parallelism", type=int, default=100,
        help="Nmap min-parallelism for ping sweep (default: 100)"
    )
    scan_group.add_argument(
        "--min-rate", type=int, default=None,
        help="Nmap min-rate for ping sweep"
    )
    scan_group.add_argument(
        "--ports", default=None,
        help="Custom port list (default: standard pentest ports)"
    )
    scan_group.add_argument(
        "--max-retries", type=int, default=5,
        help="Nmap max-retries for port scan (default: 5)"
    )

    # --- Additional scans (independent of phases) ---
    addl_group = parser.add_argument_group("Additional scans (independent of phases)")
    addl_group.add_argument(
        "--snmp", action="store_true",
        help="Run SNMP UDP scan (ports 161/162) after phases complete"
    )
    addl_group.add_argument(
        "--ipmi", action="store_true",
        help="Run IPMI UDP scan (port 623) with ipmi-version script after phases complete"
    )
    addl_group.add_argument(
        "--screenshots", action="store_true",
        help="Run gowitness directly against --live-hosts file (no prior port scan needed)"
    )

    # --- Output options ---
    output_group = parser.add_argument_group("Output options")
    output_group.add_argument(
        "-o", "--output", default=None,
        help="Custom output directory path"
    )
    output_group.add_argument(
        "--new", action="store_true",
        help="Force a new timestamped directory instead of reusing forager_<domain>/"
    )
    output_group.add_argument(
        "-q", "--quiet", action="store_true",
        help="Suppress verbose output (command echoes, info messages)"
    )
    output_group.add_argument(
        "-V", "--version", action="version",
        version=f"Forager {VERSION}",
        help="Show version number and exit"
    )

    print_banner()

    args = parser.parse_args()

    # Set global quiet mode
    QUIET = args.quiet

    # --- Conflict checks ---
    if args.resume and args.full_scan:
        parser.error("--resume and --full-scan cannot be used together")
    if args.resume and args.start_phase:
        parser.error("--resume and --start-phase cannot be used together")
    if args.resume and (args.live_hosts or args.subnets):
        parser.error("--resume cannot be combined with --live-hosts or --subnets")
    if args.full_scan and (args.start_phase or args.stop_phase):
        parser.error("--full-scan cannot be combined with --start-phase or --stop-phase")
    if args.subnets and args.live_hosts:
        parser.error("--subnets and --live-hosts cannot be used together — pick one")
    if args.dc_ips and (args.subnets or args.live_hosts):
        parser.error("--dc-ips cannot be combined with --subnets or --live-hosts")
    if args.screenshots and not args.live_hosts:
        parser.error("--screenshots requires --live-hosts")
    if args.screenshots and args.full_scan:
        parser.error("--screenshots cannot be combined with --full-scan (quick screenshot mode runs no phases)")
    if args.screenshots and (args.start_phase or args.stop_phase):
        parser.error("--screenshots cannot be combined with --start-phase or --stop-phase")
    if args.screenshots and args.skip_gowitness:
        parser.error("--screenshots and --skip-gowitness are contradictory")

    # --- Validate input files early ---
    validate_input_files(args)

    # --- Check if running additional scans only (no phases) ---
    addl_only = ((args.snmp or args.ipmi)
                  and not args.domain and not args.full_scan
                  and not args.start_phase and not args.resume
                  and not args.subnets and not args.live_hosts)

    # --- Additional conflict checks ---
    if addl_only and (args.start_phase or args.stop_phase):
        parser.error("--start-phase/--stop-phase are not used with standalone --snmp/--ipmi scans")

    # --- Domain requirement check (before interactive prompt) ---
    if not addl_only and not args.resume and not args.domain and not args.live_hosts and not args.subnets:
        parser.error("domain is required unless --resume, --subnets, --live-hosts, --snmp, or --ipmi is used")

    # --- Determine starting and stopping phase ---
    # Implicit start phase based on input shortcuts
    implicit_start = 3 if args.subnets else 4 if args.live_hosts else 1

    if addl_only or args.screenshots:
        start_phase, stop_phase = 0, 0  # no phases, just additional scans / screenshots
    elif args.resume:
        start_phase, stop_phase = 1, MAX_PHASE  # overridden below by resume logic
    elif args.full_scan:
        start_phase, stop_phase = 1, MAX_PHASE
    elif args.start_phase or args.stop_phase:
        start_phase = args.start_phase or implicit_start
        stop_phase  = args.stop_phase  or MAX_PHASE
        if stop_phase < start_phase:
            parser.error(f"--stop-phase {stop_phase} cannot be less than --start-phase {start_phase}")
    elif args.subnets:
        start_phase, stop_phase = 3, MAX_PHASE
    elif args.live_hosts:
        start_phase, stop_phase = 4, MAX_PHASE
    else:
        start_phase, stop_phase = prompt_phase_selection()

    # Handle resume
    if args.resume:
        candidates = sorted(
            [p for p in Path(".").glob("forager_*") if p.is_dir()],
            key=lambda p: p.stat().st_mtime, reverse=True
        )
        if not candidates:
            log("No previous forager directory found to resume", "err")
            sys.exit(1)
        output_dir = candidates[0]
        state = load_state(output_dir)
        if not state:
            log("No state file found in last forager dir", "err")
            sys.exit(1)
        args.domain = state["domain"]
        start_phase = state["last_phase"] + 1
        if start_phase > MAX_PHASE:
            log("All phases already completed — nothing to resume", "warn")
            sys.exit(0)
        log(f"Resuming domain={args.domain} from phase {start_phase} in {output_dir}", "ok")
        if args.stop_phase:
            stop_phase = args.stop_phase
            if stop_phase < start_phase:
                log(f"--stop-phase {stop_phase} is before resume start phase {start_phase} — nothing to do", "warn")
                sys.exit(0)
        else:
            print(f"\n  {C.DIM}Remaining phases:{C.RESET}")
            for n in range(start_phase, MAX_PHASE + 1):
                print(f"  {C.CYAN}{n}{C.RESET}  {PHASES[n]}")
            print()
            while True:
                raw = input(f"  {C.BOLD}Stop after phase ({start_phase}-{MAX_PHASE}) or 'all': {C.RESET}").strip()
                if raw.lower() == "all" or raw == "":
                    stop_phase = MAX_PHASE
                    break
                if raw.isdigit() and start_phase <= int(raw) <= MAX_PHASE:
                    stop_phase = int(raw)
                    break
                print(f"  {C.YELLOW}[!]{C.RESET} Enter a number {start_phase}-{MAX_PHASE} or 'all'")

    # Setup output directory
    if args.output:
        output_dir = Path(args.output)
    elif addl_only:
        # Additional scans only: find most recent forager dir
        candidates = sorted(
            [p for p in Path(".").glob("forager_*") if p.is_dir()],
            key=lambda p: p.stat().st_mtime, reverse=True
        )
        if not candidates:
            log("No previous forager directory found — use --output or --live-hosts", "err")
            sys.exit(1)
        output_dir = candidates[0]
        log(f"Using output directory: {output_dir}", "ok")
    elif not args.resume:
        label = args.domain or "custom"
        if args.new:
            datestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_dir = Path(f"forager_{label}_{datestamp}")
        else:
            output_dir = Path(f"forager_{label}")

    # Validate phase prerequisites before creating directories
    if start_phase > 1:
        phase_requirements = {
            2: (output_dir / "DC_IPs.txt",
                f"Starting at phase 2 requires DC_IPs.txt to exist in {output_dir}",
                "Run from phase 1 first, or supply IPs directly with --dc-ips"),
            3: (output_dir / "DC_subnets.txt",
                f"Starting at phase 3 requires DC_subnets.txt to exist in {output_dir}",
                "Run from phase 1 or 2 first, or provide subnets with --subnets"),
            4: (output_dir / "live_hosts.txt",
                f"Starting at phase 4 requires live_hosts.txt to exist in {output_dir}",
                "Run from an earlier phase first, or provide hosts with --live-hosts"),
            5: (output_dir / "nmap_scans" / "port_scan.nmap",
                f"Starting at phase 5 requires a completed nmap scan in {output_dir}/nmap_scans/",
                "Run from phase 4 first to generate the scan output"),
            6: (output_dir / "parsed_results" / "full_summary.csv",
                f"Starting at phase 6 requires parsed results in {output_dir}/parsed_results/",
                "Run from phase 5 first to generate the parsed results"),
            7: (output_dir / "live_hosts.txt",
                f"Starting at phase 7 requires live_hosts.txt to exist in {output_dir}",
                "Run from an earlier phase first, or provide hosts with --live-hosts"),
        }
        bypasses = {
            2: bool(args.dc_ips),
            3: bool(args.subnets),
            4: bool(args.live_hosts),
            7: bool(args.live_hosts),
        }
        if start_phase in phase_requirements:
            required_file, err_msg, hint = phase_requirements[start_phase]
            if not required_file.exists() and not bypasses.get(start_phase, False):
                log(err_msg, "err", hint=hint)
                sys.exit(1)

    dir_existed = output_dir.exists()
    output_dir.mkdir(parents=True, exist_ok=True)

    def cleanup_on_error():
        if not dir_existed and output_dir.exists():
            if not any(output_dir.iterdir()):
                output_dir.rmdir()

    # --- Execution ---
    run_stats = {"phases_run": [], "timings": {}}
    total_start = time.time()

    try:
        check_dependencies(start_phase, stop_phase, args.snmp, args.ipmi,
                           args.skip_gowitness, args.screenshots)

        print(f"{C.BOLD}{C.BLUE}{'─'*60}{C.RESET}")
        print(f"  {C.BOLD}Target :{C.RESET} {C.WHITE}{args.domain or 'custom targets'}{C.RESET}")
        if addl_only or args.screenshots:
            scan_labels = []
            if args.screenshots:
                scan_labels.append("Screenshots")
            if args.snmp:
                scan_labels.append("SNMP")
            if args.ipmi:
                scan_labels.append("IPMI")
            print(f"  {C.BOLD}Scans  :{C.RESET} {C.WHITE}{', '.join(scan_labels)}{C.RESET}")
        else:
            print(f"  {C.BOLD}Phases :{C.RESET} {C.WHITE}{start_phase} -> {stop_phase}{C.RESET}")
        print(f"  {C.BOLD}Started:{C.RESET} {C.WHITE}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{C.RESET}")
        print(f"{C.BOLD}{C.BLUE}{'─'*60}{C.RESET}\n")

        # Handle --subnets shortcut
        if args.subnets:
            src = Path(args.subnets)
            valid_subnets = []
            for line in src.read_text().strip().splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    net = ipaddress.ip_network(line, strict=False)
                    valid_subnets.append(str(net))
                except ValueError:
                    log(f"Skipping invalid subnet: {line}", "warn")
            if not valid_subnets:
                log("No valid subnets found in file", "err")
                sys.exit(1)
            dest = output_dir / "DC_subnets.txt"
            dest.write_text("\n".join(valid_subnets) + "\n")
            log(f"Loaded {len(valid_subnets)} subnet(s) from {src}", "ok")

        # Handle --live-hosts shortcut
        if args.live_hosts:
            src = Path(args.live_hosts)
            dest = output_dir / "live_hosts.txt"
            shutil.copy(src, dest)
            log(f"Loaded live hosts from {src}", "ok")

        # Phase 1: Resolve DCs
        if start_phase <= 1 <= stop_phase:
            t = time.time()
            if args.dc_ips:
                dc_ips = load_dc_ips(args, output_dir)
            else:
                dc_ips = phase1_resolve_dcs(args.domain, output_dir)
            save_state(output_dir, 1, args.domain)
            elapsed = time.time() - t
            run_stats["timings"]["Phase 1"] = elapsed
            run_stats["phases_run"].append(1)
            phase_footer(1, elapsed)
        else:
            if args.dc_ips:
                dc_ips = load_dc_ips(args, output_dir)
            else:
                dc_file = output_dir / "DC_IPs.txt"
                dc_ips = dc_file.read_text().strip().splitlines() if dc_file.exists() else []

        # Phase 2: Build subnets
        if start_phase <= 2 <= stop_phase:
            t = time.time()
            phase2_build_subnets(dc_ips, args.subnet_mask, output_dir)
            save_state(output_dir, 2, args.domain)
            elapsed = time.time() - t
            run_stats["timings"]["Phase 2"] = elapsed
            run_stats["phases_run"].append(2)
            phase_footer(2, elapsed)

        # Phase 3: Ping sweep
        if start_phase <= 3 <= stop_phase:
            t = time.time()
            live = phase3_ping_sweep(output_dir, args.parallelism, args.min_rate)
            save_state(output_dir, 3, args.domain)
            elapsed = time.time() - t
            run_stats["timings"]["Phase 3"] = elapsed
            run_stats["phases_run"].append(3)
            phase_footer(3, elapsed)
            if not live:
                stop_phase = 3  # skip remaining phases

        # Phase 4: Port scan
        if start_phase <= 4 <= stop_phase:
            t = time.time()
            phase4_port_scan(output_dir, args.ports, args.max_retries)
            save_state(output_dir, 4, args.domain)
            elapsed = time.time() - t
            run_stats["timings"]["Phase 4"] = elapsed
            run_stats["phases_run"].append(4)
            phase_footer(4, elapsed)

        # Phase 5: Parse results
        if start_phase <= 5 <= stop_phase:
            t = time.time()
            p5_stats = phase5_parse_results(output_dir)
            save_state(output_dir, 5, args.domain)
            elapsed = time.time() - t
            run_stats["timings"]["Phase 5"] = elapsed
            run_stats["phases_run"].append(5)
            if p5_stats:
                run_stats.update(p5_stats)
            phase_footer(5, elapsed)

        # Phase 6: Web screenshots
        if start_phase <= 6 <= stop_phase:
            if args.skip_gowitness:
                log("Phase 6 skipped (--skip-gowitness)", "warn")
                save_state(output_dir, 6, args.domain)
            else:
                t = time.time()
                gw_stats = phase6_web_screenshots(output_dir)
                save_state(output_dir, 6, args.domain)
                elapsed = time.time() - t
                run_stats["timings"]["Phase 6"] = elapsed
                run_stats["phases_run"].append(6)
                if gw_stats:
                    run_stats.update(gw_stats)
                phase_footer(6, elapsed)

        # Phase 7: SMB enumeration
        if start_phase <= 7 <= stop_phase:
            t = time.time()
            smb_stats = phase7_smb_enum(output_dir)
            save_state(output_dir, 7, args.domain)
            elapsed = time.time() - t
            run_stats["timings"]["Phase 7"] = elapsed
            run_stats["phases_run"].append(7)
            if smb_stats:
                run_stats.update(smb_stats)
            phase_footer(7, elapsed)

        # --- Additional scans ---
        if args.screenshots:
            t = time.time()
            run_screenshots_scan(output_dir)
            elapsed = time.time() - t
            run_stats["timings"]["Screenshots scan"] = elapsed
            section_footer("Screenshots scan", elapsed)

        if args.snmp:
            t = time.time()
            run_snmp_scan(output_dir)
            elapsed = time.time() - t
            run_stats["timings"]["SNMP scan"] = elapsed
            section_footer("SNMP scan", elapsed)

        if args.ipmi:
            t = time.time()
            run_ipmi_scan(output_dir)
            elapsed = time.time() - t
            run_stats["timings"]["IPMI scan"] = elapsed
            section_footer("IPMI scan", elapsed)

        # --- Summary ---
        total_elapsed = time.time() - total_start
        phases_str = ", ".join(str(p) for p in run_stats["phases_run"]) or "none (additional scans only)"

        print(f"\n{C.BOLD}{C.GREEN}{'─'*60}{C.RESET}")
        print(f"  {C.BOLD}{C.GREEN}Complete!{C.RESET}")
        print(f"  {C.BOLD}Output      :{C.RESET} {C.WHITE}{output_dir.resolve()}{C.RESET}")
        print(f"  {C.BOLD}Phases run  :{C.RESET} {C.WHITE}{phases_str}{C.RESET}")
        print(f"  {C.BOLD}Total time  :{C.RESET} {C.WHITE}{fmt_duration(total_elapsed)}{C.RESET}")

        # Live host count
        live_file = output_dir / "live_hosts.txt"
        if live_file.exists():
            live_count = len([l for l in live_file.read_text().strip().splitlines() if l.strip()])
            print(f"  {C.BOLD}Live hosts  :{C.RESET} {C.WHITE}{live_count}{C.RESET}")

        if "hosts_with_open_ports" in run_stats:
            print(f"  {C.BOLD}Open ports  :{C.RESET} {C.WHITE}{run_stats['total_open_ports']} across {run_stats['hosts_with_open_ports']} host(s){C.RESET}")
        if "screenshot_urls" in run_stats:
            print(f"  {C.BOLD}Screenshots :{C.RESET} {C.WHITE}{run_stats['screenshot_urls']} web URL(s) captured{C.RESET}")
        if "signing_disabled" in run_stats:
            print(f"  {C.BOLD}SMB signing :{C.RESET} {C.WHITE}{run_stats['signing_disabled']} host(s) with signing disabled{C.RESET}")
        if "relay_targets" in run_stats:
            print(f"  {C.BOLD}SMB relay   :{C.RESET} {C.WHITE}{run_stats['relay_targets']} relay target(s){C.RESET}")
        if "smbv1_enabled" in run_stats:
            print(f"  {C.BOLD}SMBv1       :{C.RESET} {C.WHITE}{run_stats['smbv1_enabled']} host(s) with SMBv1 enabled{C.RESET}")

        # Per-phase timing
        if len(run_stats["timings"]) > 1:
            print(f"\n  {C.DIM}Timing breakdown:{C.RESET}")
            for phase_name, secs in run_stats["timings"].items():
                print(f"    {C.DIM}{phase_name}: {fmt_duration(secs)}{C.RESET}")

        print(f"{C.BOLD}{C.GREEN}{'─'*60}{C.RESET}\n\n")

    except (SystemExit, KeyboardInterrupt):
        cleanup_on_error()
        raise


if __name__ == "__main__":
    main()
