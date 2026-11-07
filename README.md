# 📡 NetGuardian

![License](https://img.shields.io/badge/license-MIT-green)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Platform](https://img.shields.io/badge/platform-Windows%2010%20%7C%2011-lightgrey)

**NetGuardian** shows you what's actually connected to your home network,
flags devices you haven't seen before, and checks for one specific,
genuinely common IoT weak point: an open Telnet port.

> ⚠️ **Honest scope:** NetGuardian does **not** detect Wi-Fi encryption
> strength, default credentials, or device-specific vulnerabilities —
> those need either router-level access or deep per-device fingerprinting
> that no simple network-side tool can do reliably. What it *does* do
> honestly: device inventory, new-device alerts, and a real Telnet-open
> check. This tool is for personal use on networks you own or manage.

## Why NetGuardian

- **A real, understandable device inventory** — no more wondering what's
  connected to your Wi-Fi.
- **New-device alerts you control** — mark your own devices as known once,
  and only genuinely new devices get flagged on future scans.
- **One honest security signal** — Telnet transmits credentials in plain
  text and has no legitimate reason to be open on a modern device, so
  flagging it is both accurate and useful, unlike broader claims this tool
  can't actually back up.
- **No terminal needed** — double-click to install, double-click to run.

## How it works

1. A fast parallel ping sweep across your local network (assumes a typical
   /24 home network — see Limitations) populates your PC's ARP cache.
2. `arp -a` is parsed for IP/MAC pairs of everything that responded.
3. Each device gets a best-effort hostname lookup and a quick check for an
   open Telnet port (23).
4. Devices are compared against a local `netguardian-known-devices.json`
   file you build up by clicking "Mark as Known".

## Limitations

- Assumes a /24 home network (covers the vast majority of home routers,
  but not every network layout).
- Hostname lookups often fail on home networks — this is normal and the
  device still shows up by IP/MAC.
- Windows Firewall may prompt to allow network access on first scan.

## Install

**No terminal needed:** unzip the project, then double-click
**`Install NetGuardian.bat`**. It installs the one dependency needed and
opens the app automatically.

The only prerequisite is Python itself — if missing, the installer tells
you and points to python.org (check "Add python.exe to PATH" during setup).

## Usage

Double-click **`NetGuardian.pyw`** any time after installing. Click
**Scan Network** (takes a few seconds), then **Mark as Known** on any
device that's genuinely yours so future scans stop flagging it.

Command line, if you prefer:

```powershell
netguardian demo   # sample data, no real scan
netguardian scan   # scan your real network
netguardian gui    # open the graphical interface
```

## Architecture

```
netguardian/
├── cli.py                 # CLI entry point
├── gui.py                   # Device-card GUI with Mark as Known
├── ui_theme.py                # Shared modern dark UI kit
├── demo_data.py                 # Sample scan results for demo mode & testing
└── core/
    ├── scanner.py                  # Real ping sweep + ARP parsing + Telnet check
    ├── known_devices.py              # Pure logic + JSON persistence for confirmed devices
    ├── checks.py                       # Pure check functions — fully unit-testable
    └── reporter.py                       # Markdown report generation
```

## License

MIT — use it, fork it, extend it.
