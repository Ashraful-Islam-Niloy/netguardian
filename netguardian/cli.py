"""NetGuardian — home network guardian.

Usage:
    netguardian scan [--out DIR] [--known FILE] [--mark-all-known]
    netguardian demo [--out DIR]
    netguardian gui
"""
from __future__ import annotations

import argparse
import sys

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .core.checks import run_all_checks
from .core.known_devices import (
    add_known_devices,
    default_path,
    known_macs_set,
    load_known_devices,
    save_known_devices,
)
from .core.reporter import generate_markdown_report
from .core.scanner import scan_network
from .demo_data import DEMO_DEVICES, DEMO_KNOWN_MACS

__version__ = "0.1.0"
console = Console()

BANNER = r"""
[bold cyan]
 _   _      _   ____                     _ _
| \ | | ___| |_/ ___|_   _  __ _ _ __ __| (_) __ _ _ __
|  \| |/ _ \ __| |  _| | | |/ _` | '__/ _` | |/ _` | '_ \
| |\  |  __/ |_| |_| | |_| | (_| | | | (_| | | (_| | | | |
|_| \_|\___|\__|\____|\__,_|\__,_|_|  \__,_|_|\__,_|_| |_|
[/bold cyan][dim]see what's really on your home network[/dim]
"""


def _print_devices(devices, findings) -> None:  # noqa: ANN001
    new_ips = {f.device_ip for f in findings if f.check_id == "new_device"}
    telnet_ips = {f.device_ip for f in findings if f.check_id == "telnet_open"}

    table = Table(title="Devices on your network")
    table.add_column("IP")
    table.add_column("Hostname")
    table.add_column("MAC")
    table.add_column("Flags")
    for d in devices:
        ip = str(d.get("ip", ""))
        flags = []
        if ip in new_ips:
            flags.append("[yellow]NEW[/yellow]")
        if ip in telnet_ips:
            flags.append("[red]TELNET OPEN[/red]")
        table.add_row(ip, d.get("hostname") or "—", d.get("mac", ""), " ".join(flags) or "-")
    console.print(table)


def cmd_scan(args: argparse.Namespace) -> int:
    console.print(BANNER)
    console.print("[cyan]Scanning your network — this takes a few seconds...[/cyan]")
    try:
        devices = scan_network()
    except RuntimeError as exc:
        console.print(f"[red]{exc}[/red]")
        return 1

    known_path = args.known or default_path()
    known = load_known_devices(known_path)
    if args.mark_all_known:
        known = add_known_devices(known, devices)
        try:
            save_known_devices(known_path, known)
        except OSError as exc:
            console.print(f"[red]Couldn't save the known-devices list ({known_path}): {exc}[/red]")
            return 1
        console.print(f"[green]Marked {len(devices)} device(s) as known ({known_path}).[/green]")

    report = run_all_checks(devices, known_macs_set(known))
    console.print()
    _print_devices(devices, report.findings)
    console.print()
    console.print(Panel.fit(f"{len(devices)} device(s), {len(report.findings)} issue(s)", title="Summary"))
    path = f"{args.out}/netguardian-report.md"
    generate_markdown_report(devices, report, path)
    console.print(f"\nReport saved to {path}")
    if not known:
        console.print(
            "[dim]First scan: nothing is marked as known yet, so every device shows as NEW. If you recognise them "
            "all, run 'netguardian scan --mark-all-known' to set your baseline.[/dim]"
        )
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    console.print(BANNER)
    console.print("[yellow]Running against sample data.[/yellow]\n")
    report = run_all_checks(DEMO_DEVICES, DEMO_KNOWN_MACS)
    _print_devices(DEMO_DEVICES, report.findings)
    console.print()
    console.print(Panel.fit(f"{len(DEMO_DEVICES)} device(s), {len(report.findings)} issue(s)", title="Summary"))
    return 0


def cmd_gui(args: argparse.Namespace) -> int:
    from .gui import launch_gui

    launch_gui()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="netguardian", description="See what's on your home network.")
    parser.add_argument("--version", action="version", version=f"netguardian {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="Scan your local network for devices")
    scan_p.add_argument("--out", default="./netguardian-results")
    scan_p.add_argument("--known", default=None, help="Path of the known-devices list (default: your user profile)")
    scan_p.add_argument(
        "--mark-all-known", action="store_true",
        help="Treat every device found right now as yours (use on a network you trust, to set a baseline)",
    )
    scan_p.set_defaults(func=cmd_scan)

    demo_p = sub.add_parser("demo", help="Run against sample data")
    demo_p.set_defaults(func=cmd_demo)

    sub.add_parser("gui", help="Launch the graphical interface").set_defaults(func=cmd_gui)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
