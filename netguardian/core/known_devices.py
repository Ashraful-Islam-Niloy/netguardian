"""Tracks which devices the user has confirmed as their own.

The pure logic (normalizing/adding a MAC to the known set) is separated
from the JSON file I/O so it can be tested without touching disk.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


def _windows_default(appdata: str | None, home: Path) -> str:
    base = appdata or str(home / "AppData" / "Roaming")
    return str(Path(base) / "NetGuardian" / "known-devices.json")


def default_path() -> str:
    """Where the known-devices list lives. A per-user folder rather than the
    current directory, so it doesn't depend on how the app was started (a
    double-click, a shortcut, or "Run as administrator" all start elsewhere)."""
    if os.name == "nt":
        return _windows_default(os.environ.get("APPDATA"), Path.home())
    return str(Path.home() / ".config" / "netguardian" / "known-devices.json")


def normalize_mac(mac: str) -> str:
    return mac.strip().lower().replace("-", ":")


def add_known_device(known: dict[str, Any], mac: str, label: str | None = None) -> dict[str, Any]:
    """Returns a NEW dict with the device added -- never mutates the input,
    so callers control exactly when a change is persisted."""
    updated = dict(known)
    updated[normalize_mac(mac)] = {"label": label or mac}
    return updated


def add_known_devices(known: dict[str, Any], devices: list[dict[str, Any]]) -> dict[str, Any]:
    """Marks every device in `devices` as known. Devices already in the list
    keep the label they have; devices without a MAC can't be tracked and are skipped."""
    updated = dict(known)
    for device in devices:
        mac = device.get("mac")
        if not mac:
            continue
        key = normalize_mac(mac)
        if key not in updated:
            updated[key] = {"label": device.get("hostname") or device.get("ip") or mac}
    return updated


def known_macs_set(known: dict[str, Any]) -> set[str]:
    return {normalize_mac(mac) for mac in known.keys()}


def load_known_devices(path: str) -> dict[str, Any]:
    p = Path(path)
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError, UnicodeDecodeError):
        return {}
    # A hand-edited or damaged file could hold any JSON value; only a mapping is usable.
    return data if isinstance(data, dict) else {}


def save_known_devices(path: str, known: dict[str, Any]) -> None:
    """Writes the list via a temporary file so a crash mid-write can't leave
    a half-written (and therefore unreadable) list behind."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(p.name + ".tmp")
    tmp.write_text(json.dumps(known, indent=2), encoding="utf-8")
    os.replace(tmp, p)
