"""Generate a plain-English report of a network scan."""
from __future__ import annotations

import datetime as _dt
from pathlib import Path
from typing import Any

from .checks import CheckReport

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def generate_markdown_report(devices: list[dict[str, Any]], report: CheckReport, output_path: str) -> str:
    sorted_findings = sorted(
        report.findings,
        key=lambda f: _SEVERITY_ORDER.index(f.severity) if f.severity in _SEVERITY_ORDER else 99,
    )
    lines = [
        "# NetGuardian Report",
        "",
        f"- **Generated:** {_dt.datetime.now().isoformat(timespec='seconds')}",
        f"- **Devices found:** {len(devices)}",
        f"- **Issues found:** {len(report.findings)}",
        "",
        "## Devices",
        "",
        "| IP | Hostname | MAC | Telnet Open |",
        "|---|---|---|---|",
    ]
    for d in devices:
        lines.append(
            f"| {d.get('ip', '')} | {d.get('hostname') or '—'} | {d.get('mac', '')} | "
            f"{'⚠️ Yes' if d.get('telnet_open') else 'No'} |"
        )

    lines += ["", "## Issues", ""]
    if not sorted_findings:
        lines.append("No issues found.")
    for f in sorted_findings:
        lines.append(f"### [{f.severity.upper()}] {f.title}")
        lines.append(f.detail)
        lines.append(f"> 💡 {f.recommendation}")
        lines.append("")

    text = "\n".join(lines) + "\n"
    out_path = Path(output_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(text, encoding="utf-8")
    return text
