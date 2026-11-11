"""How KLONER looks in a terminal: the banner's greens, verdict pills, panels and tables (D-069).

Presentation only. Nothing here decides anything, and nothing here touches JSON output, report files, exit codes or
the database. Every screen degrades on its own: rich drops the colors for ``--no-color``, ``NO_COLOR`` and pipes,
folds long cells on narrow terminals, and keeps plain words next to every color, so no meaning depends on color.
"""

from __future__ import annotations

import contextlib
import os
import sys
from collections.abc import Iterable, Iterator
from typing import Any

from rich import box
from rich.console import Console, RenderableType
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

# The banner's palette (D-067)
GREEN = "#45bf88"  # the accent: rules, panel borders, success
BRIGHT = "#7fe6b3"  # headings, commands, the diamond
PALE = "#c2f5da"  # the values that matter: package names, verdict counts
SOFT = "#a3c7b6"  # explanations
MUTED = "#5f8577"  # keys, captions, hints
BORDER = "#2b7258"  # table borders
RED = "#ff6b6b"
AMBER = "#f0c75e"
VIOLET = "#c792ea"
BLUE = "#7fb3d5"
GREY = "#8a8a8a"

_ON_GREEN = f"bold #0b1f15 on {GREEN}"
_ON_RED = "bold #ffffff on #c94040"
_ON_VIOLET = "bold #ffffff on #8e4fb0"
_ON_AMBER = "bold #1f1800 on #e8b93c"
_ON_BLUE = "bold #0b1622 on #7fb3d5"
_ON_GREY = "bold #e6e6e6 on #4d4d4d"

# verdict: (icon, pill style, text style, class, meaning). Meanings follow docs/VERDICTS.md.
VERDICTS: dict[str, tuple[str, str, str, str, str]] = {
    "TAMPERED": (
        "✗",
        _ON_RED,
        f"bold {RED}",
        "hostile",
        "Claims to be the app, but was modified after signing or carries hidden structure.",
    ),
    "FORGED": (
        "✗",
        _ON_RED,
        f"bold {RED}",
        "hostile",
        "Valid signature, but by a key that is not the official one.",
    ),
    "IMPERSONATOR": (
        "✗",
        _ON_VIOLET,
        f"bold {VIOLET}",
        "hostile",
        "Another package with no trusted signer, wearing the official brand (icon or brand label).",
    ),
    "ANOMALY": (
        "▲",
        _ON_AMBER,
        f"bold {AMBER}",
        "review",
        "Engines or parsers disagree, or KLONER refuses to certify the file. Review it.",
    ),
    "ERROR": (
        "▲",
        _ON_AMBER,
        f"bold {AMBER}",
        "review",
        "The evaluation could not complete (timeout, crash, outdated verifier). Review it.",
    ),
    "MISMATCH": (
        "≠",
        _ON_BLUE,
        f"bold {BLUE}",
        "other",
        "A valid app, but another package and not an impersonator. Not a copy.",
    ),
    "INVALID": (
        "∅",
        _ON_GREY,
        f"bold {GREY}",
        "other",
        "Not an evaluable Android file: not a ZIP, corrupt, an AAB, encrypted or unsafe.",
    ),
    "UNANCHORED": (
        "○",
        _ON_GREY,
        f"bold {GREY}",
        "other",
        "No anchor for this package and no brand match.",
    ),
    "GENUINE": (
        "✓",
        _ON_GREEN,
        f"bold {GREEN}",
        "clean",
        "Exactly the bytes the official identity signed. Safe to trust.",
    ),
}
ORDER = list(VERDICTS)  # severity, highest first (docs/VERDICTS.md)
SCREEN_ORDER = [
    "TAMPERED",
    "FORGED",
    "IMPERSONATOR",
    "ANOMALY",
    "ERROR",
    "GENUINE",
    "MISMATCH",
    "INVALID",
    "UNANCHORED",
]

STATUS = {"PASS": ("✓", _ON_GREEN), "WARN": ("▲", _ON_AMBER), "FAIL": ("✗", _ON_RED)}
SOURCE_STATE = {
    "OK": ("●", GREEN, "OK"),
    "NO_OFFERS": ("○", MUTED, "no offers"),
    "BLOCKED": ("▲", AMBER, "blocked"),
    "ERROR": ("✗", RED, "error"),
    "DISABLED": ("·", GREY, "disabled"),
    "SKIPPED": ("·", GREY, "skipped"),
}
CORROBORATION = {
    "CORROBORATED": (_ON_GREEN, "two or more independent official sources agree"),
    "SINGLE_OFFICIAL": (f"bold #0b1f15 on {BRIGHT}", "one official source"),
    "USER_ASSERTED": (_ON_AMBER, "supplied by you only: not corroborated"),
}
EVIDENCE = {
    "VENDOR_HTTPS": "the vendor's own APK, downloaded over HTTPS from the vendor's domain",
    "VENDOR_PUBLISHED": "fingerprints the vendor publishes (web page or Digital Asset Links)",
    "FDROID_INDEX": "F-Droid's signed repository index",
    "STORE_INSTALL": "installed from an official store on a device",
    "PLAY_API": "downloaded from Google Play",
    "USER": "a file or fingerprint you supplied: provenance not proven",
}
GATES = {
    "G0": ("Format", "is it an Android file at all?"),
    "G1": ("Bundle", "XAPK / APKM / APKS members"),
    "G2": ("Archive", "ZIP integrity and safety limits"),
    "G3": ("Identity", "package name and manifest"),
    "G4": ("Structure", "no hidden or ambiguous ZIP data"),
    "G5": ("Signature", "apksig verifies the signatures"),
    "G6": ("Agreement", "independent engines agree"),
    "G7": ("Trust", "every signer is official"),
}
GATE_STATUS = {
    "pass": ("✓ pass", f"bold {GREEN}"),
    "fail": ("✗ fail", f"bold {RED}"),
    "skip": ("· skip", GREY),
    "info": ("• info", BLUE),
}
SEVERITY_STYLE = {"alert": f"bold {RED}", "notice": AMBER, "info": SOFT}


def verdict_pill(verdict: str) -> Text:
    icon, pill, *_ = VERDICTS.get(verdict, ("•", "bold", "bold", "other", ""))
    return Text(f" {icon} {verdict} ", style=pill)


def verdict_text(verdict: str) -> Text:
    icon, _pill, style, *_ = VERDICTS.get(verdict, ("•", "bold", "bold", "other", ""))
    return Text(f"{icon} {verdict}", style=style)


def meaning(verdict: str) -> str:
    return VERDICTS.get(verdict, ("", "", "", "", ""))[4]


def verdict_class(verdict: str) -> str:
    return VERDICTS.get(verdict, ("", "", "", "other", ""))[3]


def status_pill(status: str) -> Text:
    icon, pill = STATUS.get(status, ("•", "bold"))
    return Text(f" {icon} {status} ", style=pill)


def corroboration_pill(level: str) -> Text:
    style = CORROBORATION.get(level, ("bold", ""))[0]
    return Text(f" {level} ", style=style)


def source_chip(name: str, status: str, extra: str = "") -> Text:
    icon, color, word = SOURCE_STATE.get(status, ("•", SOFT, status))
    t = Text.assemble((f"{icon} ", color), (name, f"bold {PALE}"), (f" {word}", color))
    if extra:
        t.append(f" {extra}", style=MUTED)
    return t


def label_severity(code: str) -> str | None:
    from kloner.labels import LABELS

    entry = LABELS.get(code.split(":", 1)[0])
    return entry[1] if entry else None


def label_meaning(code: str) -> str | None:
    from kloner.labels import LABELS

    entry = LABELS.get(code.split(":", 1)[0])
    return entry[2] if entry else None


def label_text(code: str) -> Text:
    return Text(code, style=SEVERITY_STYLE.get(label_severity(code) or "", SOFT))


def labels_line(codes: Iterable[str]) -> Text:
    return Text(" · ", style=MUTED).join(label_text(c) for c in codes)


def heading(console: Console, command: str, subject: str | None = None) -> None:
    """The first line of a screen: ◆ KLONER · <command> · <subject> ──────."""
    title = Text.assemble(("◆ ", BRIGHT), ("KLONER", f"bold {BRIGHT}"), (" · ", MUTED), (command, f"bold {PALE}"))
    if subject:
        title.append(" · ", style=MUTED)
        title.append(subject, style=f"bold {PALE}")
    console.print(Rule(title, align="left", style=BORDER, characters="─"))


def section(console: Console, title: str, caption: str | None = None) -> None:
    """A section title with one line that says what the section is."""
    t = Text(title, style=f"bold {BRIGHT}")
    if caption:
        t.append("   " + caption, style=MUTED)
    console.print()
    console.print(t)


def table(*columns: str, caption: str | None = None, narrow: bool = False) -> Table:
    """Rounded green borders; ``narrow`` drops the vertical borders to leave the room to the cells."""
    t = Table(
        box=box.SIMPLE_HEAD if narrow else box.ROUNDED,
        border_style=BORDER,
        header_style=f"bold {BRIGHT}",
        pad_edge=not narrow,
        expand=False,
        caption=caption,
        caption_style=MUTED,
        caption_justify="left",
    )
    for c in columns:
        t.add_column(c)
    return t


def grid(key_width: int | None = None) -> Table:
    """Two columns, key and value, without borders."""
    g = Table.grid(padding=(0, 2))
    g.add_column(style=MUTED, no_wrap=True, min_width=key_width)
    g.add_column(overflow="fold")
    return g


def panel(body: RenderableType, title: str | Text | None = None, tone: str = "info") -> Panel:
    border = {"info": GREEN, "hostile": RED, "review": AMBER, "clean": GREEN, "quiet": BORDER}.get(tone, GREEN)
    if isinstance(title, str):
        title = Text(title, style=f"bold {border}")
    return Panel(body, title=title, title_align="left", border_style=border, box=box.ROUNDED, padding=(0, 1))


def bar(value: float, width: int = 24) -> Text:
    """A filled bar for a ratio in [0, 1], with the number."""
    value = max(0.0, min(1.0, value))
    full = round(value * width)
    color = GREEN if value >= 0.5 else (AMBER if value >= 0.2 else RED)
    return Text.assemble(("█" * full, color), ("░" * (width - full), BORDER), (f"  {value:.2f}", f"bold {PALE}"))


def next_steps(console: Console, steps: list[tuple[str, str]]) -> None:
    """What to run next. Commands are never hard-wrapped, so they can be copied as printed."""
    if not steps:
        return
    console.print()
    for cmd, why in steps:
        console.print(
            Text.assemble(("▸ ", GREEN), ("Next: ", f"bold {GREEN}"), (cmd, f"bold {BRIGHT}")), soft_wrap=True
        )
        if why:
            console.print(Text(f"  {why}", style=MUTED))


def note(console: Console, text: str) -> None:
    console.print(Text.assemble(("note ", f"bold {AMBER}"), (text, SOFT)))


def done(console: Console, text: str | Text) -> None:
    body = text if isinstance(text, Text) else Text(text, style=SOFT)
    console.print(Text.assemble(("✓ ", f"bold {GREEN}"), body))


def counts_line(counts: dict[str, int]) -> Text:
    """'● 3 FORGED  ● 4 GENUINE …' in severity order, only the verdicts present."""
    parts = []
    for v in ORDER:
        n = counts.get(v, 0)
        if n:
            style = VERDICTS[v][2]
            parts.append(Text.assemble(("● ", style), (f"{n} ", f"bold {PALE}"), (v, style)))
    return Text("   ").join(parts) if parts else Text("no samples", style=MUTED)


def legend(console: Console, verdicts: Iterable[str], labels: Iterable[str] = ()) -> None:
    """What each verdict and label on the screen means, only those shown."""
    vs = [v for v in ORDER if v in set(verdicts)]
    ls = sorted({c for c in labels if label_meaning(c)})
    if not vs and not ls:
        return
    g = Table.grid(padding=(0, 2))
    g.add_column(no_wrap=True)
    g.add_column(style=SOFT, overflow="fold")
    for v in vs:
        g.add_row(verdict_text(v), meaning(v))
    if vs and ls:
        g.add_row("", "")
    for c in ls:
        g.add_row(label_text(c), label_meaning(c) or "")
    section(console, "What this means")
    console.print(g)


@contextlib.contextmanager
def working(message: str, *, enabled: bool = True) -> Iterator[None]:
    """A spinner on stderr while a long step runs, for a person at a terminal only. Never touches stdout."""
    err = Console(stderr=True, highlight=False)
    if not enabled or not err.is_terminal or os.environ.get("CI") or not sys.stderr.isatty():
        yield
        return
    with err.status(Text(message, style=SOFT), spinner="dots", spinner_style=GREEN):
        yield


def plural(n: int, word: str, many: str | None = None) -> str:
    return f"{n} {word if n == 1 else (many or word + 's')}"


def kv(console: Console, rows: list[tuple[str, Any]], key_width: int | None = None) -> None:
    g = grid(key_width)
    for k, v in rows:
        if v is None or v == "":
            continue
        g.add_row(k, v if isinstance(v, Text) else Text(str(v), style=SOFT))
    console.print(g)
