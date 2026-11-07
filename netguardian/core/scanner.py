"""Discovers devices on the local network.

Approach: a fast parallel ping sweep across the local /24 (the overwhelming
majority of home routers use a /24, though this won't catch every network
layout -- see the README) populates the ARP cache, then `arp -a` is parsed
for IP/MAC pairs. Each device found is then checked for an open Telnet port,
and a reverse-DNS name is looked up if one answers quickly (best-effort: many
home networks never return one, and that's fine).

Every step degrades gracefully: a single host's lookup failing never stops
the rest of the scan.
"""
from __future__ import annotations

import os
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, wait
from typing import Any

IS_WINDOWS = os.name == "nt"

# Child processes started from a windowless (pythonw) app each get their own
# console window unless told otherwise -- hundreds of them during a ping sweep.
# The flag only exists on Windows; 0 is the harmless default elsewhere.
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

HOSTNAME_WAIT_SECONDS = 4.0

_IPV4 = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
_MAC = re.compile(r"(?<![0-9A-Fa-f:-])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:-])")
# Entries that show up in every ARP table but are not devices.
_NOT_A_DEVICE_MACS = {"ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"}


def get_local_subnet_prefix() -> str | None:
    """Returns e.g. '192.168.1.' for this machine's local network, or None
    if it can't be determined (no active network connection, etc.)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(1)
            s.connect(("8.8.8.8", 80))  # doesn't actually send anything, just picks a route
            local_ip = s.getsockname()[0]
    except OSError:
        return None
    if local_ip.startswith(("0.", "127.")):
        return None
    return ".".join(local_ip.split(".")[:3]) + "."


def _run_text(cmd: list[str], timeout: int = 10) -> str:
    """Runs a command and returns its text output, or "" if it can't run.
    errors="replace" because Windows console tools print in a legacy code page
    that a strict decoder can choke on."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, errors="replace", timeout=timeout, check=False,
            creationflags=_NO_WINDOW,
        )
    except (subprocess.TimeoutExpired, OSError):
        return ""
    return result.stdout or ""


def _ping_once(ip: str) -> bool:
    cmd = ["ping", "-n", "1", "-w", "300", ip] if IS_WINDOWS else ["ping", "-c", "1", "-W", "1", ip]
    try:
        result = subprocess.run(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3, check=False,
            creationflags=_NO_WINDOW,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def _sweep_subnet(prefix: str, max_workers: int = 64) -> None:
    """Pings every address in the /24 in parallel purely to populate the
    ARP cache -- the return values themselves aren't used for anything."""
    addresses = [f"{prefix}{i}" for i in range(1, 255)]
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        list(pool.map(_ping_once, addresses))


def parse_arp_output(output: str, prefix: str) -> list[dict[str, str]]:
    """Extracts {"ip", "mac"} pairs from `arp -a` (Windows, Linux, macOS) or
    `ip neigh` output.

    Only addresses inside `prefix` are kept, each IP once. Broadcast and
    multicast entries are dropped: Windows lists the subnet broadcast
    (x.x.x.255 -> ff-ff-ff-ff-ff-ff) in every ARP table, and treating it as a
    "new device" would raise a false alarm on every scan.
    """
    devices: dict[str, dict[str, str]] = {}
    for line in output.splitlines():
        ip_match = _IPV4.search(line)
        mac_match = _MAC.search(line)
        if not ip_match or not mac_match:
            continue
        ip = ip_match.group(1)
        if not ip.startswith(prefix):
            continue
        mac = mac_match.group(0).replace("-", ":").lower()
        if mac in _NOT_A_DEVICE_MACS or int(mac[:2], 16) & 1:  # low bit of first octet = multicast
            continue
        devices.setdefault(ip, {"ip": ip, "mac": mac})
    return list(devices.values())


def read_arp_table(prefix: str) -> list[dict[str, str]]:
    devices = parse_arp_output(_run_text(["arp", "-a"]), prefix)
    if not devices and not IS_WINDOWS:
        # Minimal Linux installs ship `ip` but not `arp` (net-tools).
        devices = parse_arp_output(_run_text(["ip", "neigh"]), prefix)
    return devices


def _reverse_dns(ip: str) -> str | None:
    try:
        name = socket.gethostbyaddr(ip)[0]
    except Exception:  # noqa: BLE001 - best effort: any failure just means "no name"
        return None
    return None if not name or name == ip else name


def _resolve_hostnames(ips: list[str], wait_seconds: float = HOSTNAME_WAIT_SECONDS) -> dict[str, str | None]:
    """Reverse-DNS lookups can't be given a timeout (gethostbyaddr ignores
    socket timeouts), so run them in parallel and simply stop waiting after
    `wait_seconds`. Names that didn't arrive in time are reported as None."""
    pool = ThreadPoolExecutor(max_workers=32)
    futures = {ip: pool.submit(_reverse_dns, ip) for ip in ips}
    wait(list(futures.values()), timeout=wait_seconds)
    names = {ip: (fut.result() if fut.done() else None) for ip, fut in futures.items()}
    pool.shutdown(wait=False, cancel_futures=True)
    return names


def _check_telnet_open(ip: str) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.4)
            return s.connect_ex((ip, 23)) == 0
    except OSError:
        return False


def _ip_sort_key(device: dict[str, Any]) -> tuple[int, ...]:
    try:
        return tuple(int(part) for part in str(device["ip"]).split("."))
    except (KeyError, ValueError):
        return (999, 999, 999, 999)


def enrich_devices(raw_devices: list[dict[str, str]]) -> list[dict[str, Any]]:
    """Adds the Telnet check and a hostname (when one answers) to each device."""
    ips = [d["ip"] for d in raw_devices]
    with ThreadPoolExecutor(max_workers=32) as pool:
        telnet = list(pool.map(_check_telnet_open, ips))
    names = _resolve_hostnames(ips)
    enriched = [
        {"ip": d["ip"], "mac": d["mac"], "hostname": names.get(d["ip"]), "telnet_open": is_open}
        for d, is_open in zip(raw_devices, telnet)
    ]
    return sorted(enriched, key=_ip_sort_key)


def scan_network() -> list[dict[str, Any]]:
    prefix = get_local_subnet_prefix()
    if prefix is None:
        raise RuntimeError("Couldn't determine your local network. Make sure you're connected to Wi-Fi or Ethernet.")

    _sweep_subnet(prefix)
    return enrich_devices(read_arp_table(prefix))
