"""Double-click launcher for the NetGuardian GUI — no terminal needed."""
import os
import sys
import traceback

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
try:
    os.chdir(_HERE)  # reports and saved data always land next to the app
except OSError:
    pass
_LOG_PATH = os.path.join(_HERE, "netguardian_error.log")


def _report_failure(message: str) -> None:
    try:
        with open(_LOG_PATH, "w", encoding="utf-8") as f:
            f.write(message)
    except OSError:
        pass
    try:
        import tkinter
        from tkinter import messagebox
        root = tkinter.Tk()
        root.withdraw()
        messagebox.showerror(
            "NetGuardian failed to start",
            f"Details were saved to:\n{_LOG_PATH}\n\nFirst line:\n{message.splitlines()[0]}",
        )
        root.destroy()
    except Exception:
        pass


if __name__ == "__main__":
    try:
        from netguardian.gui import launch_gui
        launch_gui()
    except Exception:
        _report_failure(traceback.format_exc())
