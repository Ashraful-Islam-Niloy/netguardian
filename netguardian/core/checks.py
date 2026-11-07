"""NetGuardian checks — pure functions over a list of discovered devices.

Scope is deliberately honest: reliably detecting "weak encryption" or
"default credentials" on an arbitrary device from the network side alone
isn't something that can be done accurately without deep device-specific
fingerprinting most home tools don't actually have either. What IS
reliably detectable: whether a device is new/unrecognized, and whether it
has Telnet open — a genuinely common real-world signal for insecure IoT
gear, since Telnet sends credentials in plain text and modern devices have
no legitimate reason to expose it.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .known_devices import normalize_mac


@dataclass
class Finding:
    check_id: str
    title: str
    severity: str
    detail: str
    recommendation: str
    device_ip: str


@dataclass
class CheckReport:
    findings: list[Finding] = field(default_factory=list)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts


def check_new_devices(devices: list[dict[str, Any]], known_macs: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    known = {normalize_mac(m) for m in known_macs}
    for device in devices:
        mac = normalize_mac(device.get("mac") or "")
        if not mac:
            continue  # can't reliably identify this device without a MAC — say nothing rather than guess
        if mac in known:
            continue
        name = device.get("hostname") or device.get("ip", "unknown")
        findings.append(
            Finding(
                check_id="new_device",
                title=f"A device not seen before joined your network: {name}",
                severity="medium",
                detail=f"IP {device.get('ip')}, MAC {device.get('mac')}.",
                recommendation="If this is a device you recognize, mark it as known. "
                "If not, consider checking your router's connected-devices list.",
                device_ip=str(device.get("ip", "")),
            )
        )
    return findings


def check_telnet_open(devices: list[dict[str, Any]]) -> list[Finding]:
    findings: list[Finding] = []
    for device in devices:
        if not device.get("telnet_open"):
            continue
        name = device.get("hostname") or device.get("ip", "unknown")
        findings.append(
            Finding(
                check_id="telnet_open",
                title=f"Telnet is open on a device: {name}",
                severity="high",
                detail=f"Device at {device.get('ip')} has port 23 (Telnet) open. "
                "Telnet sends credentials in plain text and is a common weak point on IoT devices.",
                recommendation="If you don't need Telnet on this device, disable it in the device's "
                "settings, or replace it with SSH if the device supports that instead.",
                device_ip=str(device.get("ip", "")),
            )
        )
    return findings


def run_all_checks(devices: list[dict[str, Any]], known_macs: set[str]) -> CheckReport:
    report = CheckReport()
    for finding in check_new_devices(devices, known_macs):
        report.add(finding)
    for finding in check_telnet_open(devices):
        report.add(finding)
    return report
