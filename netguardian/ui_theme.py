"""A small modern-dark UI kit built on plain Tkinter.

Stock Tkinter/ttk widgets look dated by default. Rather than pull in a
heavy GUI framework for three small desktop tools, this module adds just
enough custom drawing — rounded buttons, flat cards with a severity
stripe, a consistent colour palette, an accent-coloured header — to make
the app feel like a deliberately designed product instead of a
default-styled script window.
"""
from __future__ import annotations

import re
import tkinter as tk
from tkinter import font as tkfont


COLORS = {
    "bg": "#0d1117",
    "surface": "#161b22",
    "surface_hover": "#1c2128",
    "border": "#30363d",
    "text": "#e6edf3",
    "text_dim": "#8b949e",
    "text_faint": "#6e7681",
    "text_disabled": "#484f58",
    "critical": "#f85149",
    "high": "#ff8c42",
    "medium": "#e3b341",
    "low": "#58a6ff",
    "info": "#8b949e",
    "success": "#3fb950",
}

SEVERITY_COLORS = {
    "critical": COLORS["critical"],
    "high": COLORS["high"],
    "medium": COLORS["medium"],
    "low": COLORS["low"],
    "info": COLORS["info"],
}

_HEX_RE = re.compile(r"^#[0-9a-fA-F]{6}$")


def shade(hex_color: str, factor: float) -> str:
    """Lighten (factor > 0) or darken (factor < 0) a #rrggbb colour.

    Anything that isn't a plain #rrggbb value is returned unchanged.
    """
    if not _HEX_RE.match(hex_color):
        return hex_color
    r, g, b = (int(hex_color[i:i + 2], 16) for i in (1, 3, 5))
    if factor >= 0:
        r, g, b = (round(c + (255 - c) * factor) for c in (r, g, b))
    else:
        r, g, b = (round(c * (1 + factor)) for c in (r, g, b))
    return f"#{r:02x}{g:02x}{b:02x}"


def parent_bg(parent) -> str:  # noqa: ANN001
    """The background colour of a widget's parent, so custom-drawn widgets
    blend in instead of sitting in a differently-coloured box."""
    try:
        return str(parent.cget("bg"))
    except Exception:  # noqa: BLE001 - not every widget has a bg option
        return COLORS["bg"]


def rounded_rect(canvas: tk.Canvas, x1, y1, x2, y2, radius=14, **kwargs):  # noqa: ANN001
    """Draws a rounded rectangle on a Canvas using a smoothed polygon.

    Each straight-edge point is listed twice so Tk's spline smoothing only
    rounds the corners and leaves the sides straight.
    """
    points = [
        x1 + radius, y1, x1 + radius, y1,
        x2 - radius, y1, x2 - radius, y1,
        x2, y1,
        x2, y1 + radius, x2, y1 + radius,
        x2, y2 - radius, x2, y2 - radius,
        x2, y2,
        x2 - radius, y2, x2 - radius, y2,
        x1 + radius, y2, x1 + radius, y2,
        x1, y2,
        x1, y2 - radius, x1, y2 - radius,
        x1, y1 + radius, x1, y1 + radius,
        x1, y1,
    ]
    return canvas.create_polygon(points, smooth=True, **kwargs)


class Fonts:
    """Lazily-created fonts (Tkinter fonts need a root window to exist first)."""

    _initialized = False
    title: tkfont.Font
    heading: tkfont.Font
    body: tkfont.Font
    small: tkfont.Font
    mono: tkfont.Font

    @classmethod
    def init(cls) -> None:
        if cls._initialized:
            return
        cls.title = tkfont.Font(family="Segoe UI", size=18, weight="bold")
        cls.heading = tkfont.Font(family="Segoe UI", size=12, weight="bold")
        cls.body = tkfont.Font(family="Segoe UI", size=10)
        cls.small = tkfont.Font(family="Segoe UI", size=9)
        cls.mono = tkfont.Font(family="Consolas", size=9)
        cls._initialized = True


class ModernButton(tk.Canvas):
    """A flat, rounded, accent-coloured button — Tkinter's default button
    style looks like Windows 95, which undercuts everything else here.

    It takes its background from whatever it is placed on, shows a hover
    highlight, and visibly greys out when disabled.
    """

    def __init__(
        self,
        parent,
        text: str,
        command=None,
        accent: str = COLORS["low"],
        filled: bool = True,
        width: int = 150,
        height: int = 34,
        **kwargs,
    ):
        bg = kwargs.pop("bg", None) or parent_bg(parent)
        Fonts.init()
        # Never let a long label get clipped: grow the button to fit its text.
        width = max(width, Fonts.heading.measure(text) + 36)
        super().__init__(parent, width=width, height=height, bg=bg, highlightthickness=0, **kwargs)
        self._bg = bg
        self._text = text
        self._command = command
        self._accent = accent
        self._filled = filled
        self._enabled = True
        self._hover = False
        self._width = width
        self._height = height
        self._draw()
        self.bind("<Button-1>", self._on_click)
        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)

    def _draw(self) -> None:
        self.delete("all")
        if not self._enabled:
            fill = COLORS["surface_hover"] if self._filled else self._bg
            outline = COLORS["border"]
            text_color = COLORS["text_disabled"]
        else:
            outline = self._accent
            if self._filled:
                fill = shade(self._accent, 0.12) if self._hover else self._accent
                text_color = COLORS["bg"]
            else:
                fill = COLORS["surface_hover"] if self._hover else self._bg
                text_color = self._accent
        rounded_rect(self, 2, 2, self._width - 2, self._height - 2, radius=8, fill=fill, outline=outline, width=1)
        self.create_text(self._width / 2, self._height / 2, text=self._text, fill=text_color, font=Fonts.heading)

    def _on_click(self, _event) -> None:  # noqa: ANN001
        if self._enabled and self._command:
            self._command()

    def _on_enter(self, _event) -> None:  # noqa: ANN001
        if self._enabled:
            self._hover = True
            self.config(cursor="hand2")
            self._draw()

    def _on_leave(self, _event) -> None:  # noqa: ANN001
        self._hover = False
        self.config(cursor="arrow")
        self._draw()

    def set_enabled(self, enabled: bool) -> None:
        self._enabled = enabled
        if not enabled:
            self._hover = False
        self.config(cursor="hand2" if enabled and self._hover else "arrow")
        self._draw()

    def set_text(self, text: str) -> None:
        self._text = text
        self._width = max(self._width, Fonts.heading.measure(text) + 36)
        self.config(width=self._width)
        self._draw()


class FindingCard(tk.Frame):
    """A flat card for one finding: severity stripe, title, detail, and
    an optional action button (e.g. 'Fix This'). Text wraps to the width
    of the window."""

    def __init__(self, parent, severity: str, title: str, detail: str, recommendation: str, action=None):
        super().__init__(parent, bg=COLORS["bg"])
        Fonts.init()
        color = SEVERITY_COLORS.get(severity, COLORS["info"])

        card = tk.Frame(self, bg=COLORS["surface"])
        card.pack(fill="x", padx=2, pady=6)

        stripe = tk.Frame(card, bg=color, width=4)
        stripe.pack(side="left", fill="y")

        content = tk.Frame(card, bg=COLORS["surface"])
        content.pack(side="left", fill="both", expand=True, padx=14, pady=12)

        top_row = tk.Frame(content, bg=COLORS["surface"])
        top_row.pack(fill="x")
        tk.Label(top_row, text=severity.upper(), fg=color, bg=COLORS["surface"], font=Fonts.small).pack(side="left")
        title_label = tk.Label(
            top_row, text=title, fg=COLORS["text"], bg=COLORS["surface"], font=Fonts.heading,
            wraplength=560, justify="left", anchor="w",
        )
        title_label.pack(side="left", padx=(10, 0))

        detail_label = tk.Label(
            content, text=detail, fg=COLORS["text_dim"], bg=COLORS["surface"], font=Fonts.body,
            wraplength=620, justify="left", anchor="w",
        )
        detail_label.pack(fill="x", pady=(6, 0), anchor="w")

        bottom_row = tk.Frame(content, bg=COLORS["surface"])
        bottom_row.pack(fill="x", pady=(8, 0))
        rec_label = tk.Label(
            bottom_row, text=f"💡  {recommendation}", fg=COLORS["low"], bg=COLORS["surface"], font=Fonts.small,
            wraplength=480, justify="left", anchor="w",
        )
        rec_label.pack(side="left")

        if action is not None:
            btn = ModernButton(bottom_row, text=action[0], command=action[1], accent=color, filled=False, width=100, height=28)
            btn.pack(side="right")

        # (label, pixels to subtract from the card width for padding/siblings)
        self._wrapped = [(title_label, 130), (detail_label, 60), (rec_label, 190 if action is not None else 60)]
        self.bind("<Configure>", self._on_resize)

    def _on_resize(self, event) -> None:  # noqa: ANN001
        for label, margin in self._wrapped:
            label.configure(wraplength=max(160, event.width - margin))


class ScrollableFrame(tk.Frame):
    """A vertically-scrollable container for stacking cards. The inner
    frame always matches the visible width."""

    def __init__(self, parent):
        super().__init__(parent, bg=COLORS["bg"])
        self._canvas = tk.Canvas(self, bg=COLORS["bg"], highlightthickness=0)
        scrollbar = tk.Scrollbar(self, orient="vertical", command=self._canvas.yview)
        self.body = tk.Frame(self._canvas, bg=COLORS["bg"])
        self._window = self._canvas.create_window((0, 0), window=self.body, anchor="nw")

        self.body.bind("<Configure>", lambda e: self._canvas.configure(scrollregion=self._canvas.bbox("all")))
        self._canvas.bind("<Configure>", lambda e: self._canvas.itemconfigure(self._window, width=e.width))
        self._canvas.configure(yscrollcommand=scrollbar.set)

        self._canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self._canvas.bind_all("<MouseWheel>", self._on_wheel)

    def _on_wheel(self, event) -> None:  # noqa: ANN001
        try:
            if not self._canvas.winfo_exists():
                return
            if self.body.winfo_reqheight() <= self._canvas.winfo_height():
                return  # everything already fits — nothing to scroll
            self._canvas.yview_scroll(-1 if event.delta > 0 else 1, "units")
        except tk.TclError:
            pass

    def clear(self) -> None:
        for widget in self.body.winfo_children():
            widget.destroy()
        self._canvas.yview_moveto(0)


def build_header(parent, icon: str, title: str, accent: str):  # noqa: ANN001
    """A consistent header bar: icon + title on the left, button area on
    the right (caller packs buttons into the returned frame)."""
    Fonts.init()
    header = tk.Frame(parent, bg=COLORS["bg"], height=64)
    header.pack(fill="x", padx=20, pady=(16, 8))

    left = tk.Frame(header, bg=COLORS["bg"])
    left.pack(side="left")
    tk.Label(left, text=icon, bg=COLORS["bg"], font=("Segoe UI", 20)).pack(side="left")
    tk.Label(left, text=title, fg=COLORS["text"], bg=COLORS["bg"], font=Fonts.title).pack(side="left", padx=(10, 0))

    accent_line = tk.Frame(parent, bg=accent, height=2)
    accent_line.pack(fill="x", padx=20)

    button_area = tk.Frame(header, bg=COLORS["bg"])
    button_area.pack(side="right")
    return header, button_area
