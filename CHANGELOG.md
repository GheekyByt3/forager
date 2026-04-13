# Changelog

All notable changes to Forager will be documented here.

Format: [Semantic Versioning](https://semver.org/) — `MAJOR.MINOR.PATCH`

---

## [1.1.0] — 2026-04-11

### Added

**Phase 6 — Web screenshots via gowitness:**
- New phase between parse (5) and SMB enum (now 7)
- Reads `full_summary.csv` to build precise URLs from known open web ports
- Correct protocol detection (HTTPS for 443/4443/8443/9443, HTTP for the rest)
- Outputs to `gowitness_results/` with SQLite database
- Prints `gowitness server` command for browsing results
- Soft dependency — skips with warning if gowitness is not installed
- `--skip-gowitness` flag to explicitly skip phase 6

**SMB enumeration moved to Phase 7** (was Phase 6)

**Additional scans (independent of phases):**
- `--snmp` — UDP SNMP scan (ports 161/162) via nmap
- `--ipmi` — UDP IPMI scan (port 623) with `ipmi-version` NSE script
- `--screenshots` — run gowitness directly against `--live-hosts` file (no prior port scan needed)
- Can run standalone (e.g., `--snmp` alone) or alongside phases
- SNMP/IPMI get upfront nmap dependency check; `--screenshots` gets upfront gowitness check

**New ports:**
- Web: 3000, 4443, 5480, 5601, 8008, 8009, 8090, 8161, 8500, 8880, 8983, 9080, 9090, 9200, 9443
- Redis: 6379

**New port category:**
- `redis` — port 6379

### Fixed

- `--subnets --stop-phase` and `--live-hosts --stop-phase` now correctly use implicit start phase (3 or 4) instead of defaulting to 1
- Port 443 no longer produces `https://ip:443` — correctly outputs `https://ip`
- `--live-hosts --snmp` no longer silently skips all phases
- `--full-scan` + `--start-phase`/`--stop-phase` now errors instead of silently ignoring
- `--resume` + `--live-hosts`/`--subnets` now errors (conflicting intent)
- `--dc-ips` + `--subnets`/`--live-hosts` now errors (conflicting input)
- `phase7_smb_enum` validates `live_hosts.txt` exists before invoking nxc
- `--skip-gowitness` correctly calls `save_state` so `--resume` skips past phase 6
- gowitness `db-uri` uses absolute path for reliable SQLite access
- Summary label alignment standardized (12-char labels)

### Changed

- MAX_PHASE increased from 6 to 7
- Phase dependency checks updated for new phase numbering
- Help text examples updated for phase 7 SMB references

---

## [1.0.0] — 2026-04-08

### Initial release

**Core workflow (6 phases):**
- Phase 1: Resolve Domain Controller IPs via nslookup
- Phase 2: Build subnets from DC IPs
- Phase 3: Ping sweep to find live hosts (nmap)
- Phase 4: Port scan live hosts (nmap)
- Phase 5: Parse and categorize scan results
- Phase 6: SMB enumeration via NetExec (nxc)

**Phase control:**
- Interactive phase selection prompt
- `--full-scan` to run all phases without prompting
- `--start-phase` / `--stop-phase` for range execution
- `--resume` to continue from last completed phase, with stop-phase prompt

**Input shortcuts:**
- `--dc-ips` — provide DC IPs directly (comma-separated or file)
- `--subnets` — bring your own subnets, starts at phase 3
- `--live-hosts` — bring your own host list, starts at phase 4

**Output:**
- Reuses `forager_<domain>/` by default; `--new` for timestamped directories
- Per-category host files (web, rdp, ssh, smb, winrm, ldap, etc.)
- `full_summary.csv` with all open ports
- SMB results: signing disabled, relay targets, SMBv1 hosts, per-OS host files
- State file (`.forager_state.json`) for resume support
- Per-phase timing breakdown in final summary

**Other:**
- pyfiglet banner with Unicode block letter fallback
- Colored terminal output
- `--quiet` mode to suppress verbose output
- Early input file validation before directory creation
- Cleanup of empty output directories on error
