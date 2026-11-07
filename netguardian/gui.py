"""NetGuardian GUI — a live map of what's on your network, not just alerts."""
from __future__ import annotations

import threading
import tkinter as tk
from tkinter import filedialog, messagebox

from .core.checks import run_all_checks
from .core.known_devices import (
    add_known_device,
    add_known_devices,
    default_path,
    known_macs_set,
    load_known_devices,
    save_known_devices,
)
from .core.reporter import generate_markdown_report
from .core.scanner import scan_network
from .demo_data import DEMO_DEVICES, DEMO_KNOWN_MACS
from .ui_theme import COLORS, Fonts, ModernButton, ScrollableFrame, build_header
from .winutil import default_save_dir

ACCENT = "#2dd4bf"  # teal — third distinct color in the family, network/connectivity feel


class DeviceCard(tk.Frame):
    def __init__(self, parent, device: dict, is_new: bool, is_telnet_open: bool, on_mark_known=None):  # noqa: ANN001
        super().__init__(parent, bg=COLORS["surface"])
        Fonts.init()
        self.pack(fill="x", pady=5, padx=2)

        # The more serious state wins the stripe colour.
        if is_telnet_open:
            accent = COLORS["critical"]
        elif is_new:
            accent = COLORS["medium"]
        else:
            accent = COLORS["success"]
        tk.Frame(self, bg=accent, width=4).pack(side="left", fill="y")

        content = tk.Frame(self, bg=COLORS["surface"])
        content.pack(side="left", fill="both", expand=True, padx=14, pady=10)

        top = tk.Frame(content, bg=COLORS["surface"])
        top.pack(fill="x", anchor="w")
        name = device.get("hostname") or device.get("ip", "unknown device")
        tk.Label(top, text=name, fg=COLORS["text"], bg=COLORS["surface"], font=Fonts.heading).pack(side="left")
        if is_new:
            tk.Label(top, text="NEW", fg=COLORS["medium"], bg=COLORS["surface"], font=Fonts.small).pack(
                side="left", padx=(8, 0)
            )
        if is_telnet_open:
            tk.Label(top, text="TELNET OPEN", fg=COLORS["critical"], bg=COLORS["surface"], font=Fonts.small).pack(
                side="left", padx=(8, 0)
            )

        tk.Label(
            content, text=f"{device.get('ip', '')}   ·   {device.get('mac', '')}",
            fg=COLORS["text_dim"], bg=COLORS["surface"], font=Fonts.mono,
        ).pack(anchor="w", pady=(4, 0))

        if is_telnet_open:
            tk.Label(
                content,
                text="💡  Telnet sends passwords as plain text. If you can, turn it off in this device's settings.",
                fg=COLORS["low"], bg=COLORS["surface"], font=Fonts.small, wraplength=560, justify="left",
            ).pack(anchor="w", pady=(6, 0))

        if is_new and on_mark_known is not None:
            btn_row = tk.Frame(content, bg=COLORS["surface"])
            btn_row.pack(anchor="w", pady=(8, 0))
            ModernButton(
                btn_row, "Mark as Known", command=lambda: on_mark_known(device), accent=COLORS["success"],
                filled=False, width=130, height=28,
            ).pack()


class NetGuardianApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("NetGuardian — Home Network Guardian")
        self.geometry("820x680")
        self.minsize(720, 520)
        self.configure(bg=COLORS["bg"])
        Fonts.init()

        self._devices: list[dict] = []
        self._known: dict = {}
        self._report = None
        self._demo_mode = False
        self._known_path = default_path()
        self._build_ui()

    def _build_ui(self) -> None:
        _, button_area = build_header(self, "📡", "NetGuardian", ACCENT)

        self.scan_btn = ModernButton(button_area, "Scan Network", command=self._on_scan_clicked, accent=ACCENT, width=130)
        self.scan_btn.pack(side="left", padx=4)

        self.mark_all_btn = ModernButton(
            button_area, "Mark All Known", command=self._on_mark_all_clicked, accent=COLORS["success"],
            filled=False, width=140,
        )
        self.mark_all_btn.pack(side="left", padx=4)
        self.mark_all_btn.set_enabled(False)

        self.demo_btn = ModernButton(
            button_area, "View Demo", command=self._load_demo, accent=COLORS["text_dim"], filled=False, width=110
        )
        self.demo_btn.pack(side="left", padx=4)

        self.save_btn = ModernButton(
            button_area, "Save Report", command=self._on_save_clicked, accent=COLORS["success"], filled=False, width=120
        )
        self.save_btn.pack(side="left", padx=4)
        self.save_btn.set_enabled(False)

        self.status_label = tk.Label(
            self,
            text="Click Scan Network to see what's connected to your Wi-Fi, or View Demo to see an example.",
            fg=COLORS["text_dim"], bg=COLORS["bg"], font=Fonts.body, wraplength=760, justify="left",
        )
        self.status_label.pack(padx=24, pady=(10, 4), anchor="w")

        self.summary_label = tk.Label(self, text="", fg=COLORS["text"], bg=COLORS["bg"], font=Fonts.title)
        self.summary_label.pack(padx=24, pady=(0, 10), anchor="w")

        self.scroll = ScrollableFrame(self)
        self.scroll.pack(fill="both", expand=True, padx=20, pady=(0, 20))

    # -- helpers -------------------------------------------------------

    def _post(self, fn) -> None:  # noqa: ANN001
        """Runs `fn` on the UI thread; quietly does nothing if the window was
        closed while a scan was still running."""
        try:
            self.after(0, fn)
        except (tk.TclError, RuntimeError):
            pass

    def _render(self) -> None:
        self.scroll.clear()
        known_macs = DEMO_KNOWN_MACS if self._demo_mode else known_macs_set(self._known)
        report = run_all_checks(self._devices, known_macs)
        self._report = report
        new_ips = {f.device_ip for f in report.findings if f.check_id == "new_device"}
        telnet_ips = {f.device_ip for f in report.findings if f.check_id == "telnet_open"}

        self.summary_label.config(text=f"{len(self._devices)} device(s) found  ·  {len(report.findings)} issue(s)")
        self.mark_all_btn.set_enabled(bool(new_ips) and not self._demo_mode)
        self.save_btn.set_enabled(bool(self._devices))

        if not self._devices:
            tk.Label(
                self.scroll.body,
                text="No devices found. NetGuardian scans the 254 addresses next to this PC's own address,\n"
                "so networks laid out differently (or a VPN that takes over your connection) can come up empty.",
                fg=COLORS["text_dim"], bg=COLORS["bg"], font=Fonts.body, justify="left",
            ).pack(pady=30, anchor="w")
            return

        on_mark = None if self._demo_mode else self._on_mark_known
        for device in self._devices:
            ip = str(device.get("ip", ""))
            DeviceCard(
                self.scroll.body, device, is_new=ip in new_ips, is_telnet_open=ip in telnet_ips,
                on_mark_known=on_mark,
            ).pack(fill="x")

    # -- actions -------------------------------------------------------

    def _load_demo(self) -> None:
        self._demo_mode = True
        self._devices = DEMO_DEVICES
        self.status_label.config(text="Showing sample data, not your network.")
        self._render()

    def _on_scan_clicked(self) -> None:
        self.status_label.config(text="Scanning your network — this takes a few seconds...")
        self.scan_btn.set_enabled(False)
        self.scan_btn.set_text("Scanning…")
        threading.Thread(target=self._run_live_scan, daemon=True).start()

    def _run_live_scan(self) -> None:
        try:
            devices = scan_network()
            known = load_known_devices(self._known_path)
        except Exception as exc:  # noqa: BLE001
            # Capture the text now: Python deletes `exc` when this block ends,
            # so a lambda that referenced it later would fail with a NameError.
            message = str(exc) or exc.__class__.__name__
            self._post(lambda m=message: self._on_error(m))
            return
        self._post(lambda: self._on_scan_complete(devices, known))

    def _reset_scan_button(self) -> None:
        self.scan_btn.set_text("Scan Network")
        self.scan_btn.set_enabled(True)

    def _on_error(self, message: str) -> None:
        self._reset_scan_button()
        self.status_label.config(text="Scan failed.")
        messagebox.showerror("Couldn't scan network", message)

    def _on_scan_complete(self, devices: list[dict], known: dict) -> None:
        self._reset_scan_button()
        self._demo_mode = False
        self._devices = devices
        self._known = known
        if known:
            note = "Live scan of your network."
        else:
            note = (
                "First scan: nothing is marked as known yet, so every device shows as NEW. Check the list, "
                "then click Mark All Known to make this your baseline — later scans only flag newcomers."
            )
        self.status_label.config(text=note)
        self._render()

    def _save_known(self) -> bool:
        try:
            save_known_devices(self._known_path, self._known)
        except OSError as exc:
            messagebox.showerror("Couldn't save the known-devices list", f"{exc}\n\n({self._known_path})")
            return False
        return True

    def _on_mark_known(self, device: dict) -> None:
        mac = device.get("mac")
        if not mac or self._demo_mode:
            return
        self._known = add_known_device(self._known, mac, device.get("hostname"))
        self._save_known()
        self._render()

    def _on_mark_all_clicked(self) -> None:
        if self._demo_mode or not self._devices:
            return
        if not messagebox.askyesno(
            "Mark all devices as known?",
            f"This tells NetGuardian that all {len(self._devices)} devices listed are yours, so they stop showing "
            "as NEW.\n\nOnly do this if you recognise every one of them. Check your router's device list if you're not sure.",
        ):
            return
        self._known = add_known_devices(self._known, self._devices)
        self._save_known()
        self._render()

    def _on_save_clicked(self) -> None:
        if self._report is None or not self._devices:
            return
        path = filedialog.asksaveasfilename(
            title="Save NetGuardian report",
            defaultextension=".md",
            initialfile="netguardian-report.md",
            initialdir=default_save_dir(),
            filetypes=[("Markdown report", "*.md"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            generate_markdown_report(self._devices, self._report, path)
        except OSError as exc:
            messagebox.showerror("Couldn't save the report", str(exc))
            return
        messagebox.showinfo("Saved", f"Report saved to:\n{path}")


def launch_gui() -> None:
    app = NetGuardianApp()
    app.mainloop()
