"""Small Windows helpers shared by the GUI: admin detection, one-click
"restart as Administrator", and a sensible default folder for saved reports.

Nothing here runs at import time and everything degrades to a harmless
answer on non-Windows systems, so the app (and its tests) work anywhere.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path


def is_admin() -> bool:
    """True if this process is running with Administrator rights."""
    if os.name != "nt":
        return False
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001 - any failure just means "assume not admin"
        return False


def relaunch_as_admin(launcher_name: str) -> bool:
    """Asks Windows to start the app again with Administrator rights.

    Windows shows its usual "Do you want to allow this app to make changes?"
    prompt. Returns True if the request was accepted (the caller should then
    close this window), or False if it was declined, cancelled or impossible.
    `launcher_name` is the double-click launcher that sits next to the
    package folder, e.g. "NetGuardian.pyw".
    """
    if os.name != "nt":
        return False
    launcher = Path(__file__).resolve().parent.parent / launcher_name
    if not launcher.exists():
        return False
    exe = Path(sys.executable)
    pythonw = exe.with_name("pythonw.exe")
    interpreter = pythonw if pythonw.exists() else exe
    try:
        import ctypes

        result = ctypes.windll.shell32.ShellExecuteW(  # type: ignore[attr-defined]
            None, "runas", str(interpreter), f'"{launcher}"', str(launcher.parent), 1
        )
        return int(result) > 32
    except Exception:  # noqa: BLE001
        return False


def default_save_dir() -> str:
    """Where the 'Save Report' dialog should open: Documents if it exists."""
    docs = Path.home() / "Documents"
    return str(docs if docs.is_dir() else Path.home())
