"""The startup banner (D-067): the KLONER wordmark in a 63-column frame, for people at a terminal only.

It shows on bare ``kloner``, ``--help`` and ``--version``, and at the start of hunt, verify, fetch, survey, doctor
and selftest. It goes to stderr, and only when stdout and stderr are both interactive terminals. It never shows with
``--json`` or ``--quiet``, when output is piped or redirected, in CI, or with ``KLONER_NO_BANNER=1``. Because it
never touches stdout, JSON output, reports, exit codes and reverify results are the same with or without it.

Colors: true color when the terminal says so (``COLORTERM=truecolor``/``24bit``, or Windows Terminal's
``WT_SESSION``), a hand-picked calm ramp when ``TERM`` says 256 colors, otherwise the same layout uncolored, as
with ``--no-color`` or ``NO_COLOR``. A terminal narrower than 65 columns, or a console that cannot encode the block
characters, gets one plain line: ``KLONER v<version>``.
"""

from __future__ import annotations

import io
import os
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal, TextIO

from rich.color import Color
from rich.console import Console
from rich.style import Style
from rich.terminal_theme import TerminalTheme
from rich.text import Text

Mode = Literal["truecolor", "256", "none"]
RGB = tuple[int, int, int]

# ANSI Shadow, 51 columns (the first row's last column is blank).
ART = tuple(
    row.ljust(51)
    for row in (
        "██╗  ██╗██╗      ██████╗ ███╗   ██╗███████╗██████╗",
        "██║ ██╔╝██║     ██╔═══██╗████╗  ██║██╔════╝██╔══██╗",
        "█████╔╝ ██║     ██║   ██║██╔██╗ ██║█████╗  ██████╔╝",
        "██╔═██╗ ██║     ██║   ██║██║╚██╗██║██╔══╝  ██╔══██╗",
        "██║  ██╗███████╗╚██████╔╝██║ ╚████║███████╗██║  ██║",
        "╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝",
    )
)
BLOCK = "█"
SHADOW_CHARS = frozenset("╗╔═║╝╚")
FRAME = 63
INDENT = 2
MIN_WIDTH = INDENT + FRAME
CENTER = FRAME // 2
TAGLINE = "Key-Lineage Oracle for Network-wide Exposure of Repackaging"
ACRONYM_WORDS = ("Key", "Lineage", "Oracle", "Network", "Exposure", "Repackaging")
URL = "github.com/0xKript/kloner"

STOPS = ("#c2f5da", "#98e9c0", "#6cd6a3", "#45bf88", "#2ea371", "#22875c")
SHADOW = "#2b7258"
DIAMOND = "#7fe6b3"
LINE_CENTER = "#45bf88"
LINE_END = "#0c0c0c"
TAGLINE_COLOR = "#a3c7b6"
ACRONYM_COLOR = "#7fe6b3"
VERSION_COLOR = "#5f8577"

# 256-color terminals: xterm palette entries picked by hand. The art keeps one hue family, light mint to deep
# emerald, without the saturated neon greens of the palette. The bands follow the gradient's own t in steps of 0.144
# (0.72/5), so every row changes color once, at the same column: a regular staircase instead of scattered patches.
# The frame fades from a muted green into the grey ramp.
ART_256 = (158, 115, 79, 72, 29, 29)
ART_256_STEP = 0.144
LINE_256 = (72, 65, 239, 238, 237, 236, 235, 234, 233)
SHADOW_256 = 23
DIAMOND_256 = 115
TAGLINE_256 = 145  # a calm grey, so the mint initials stand out as they do in true color
ACRONYM_256 = 115
VERSION_256 = 66

BANNER_COMMANDS = frozenset({"hunt", "verify", "fetch", "survey", "doctor", "selftest"})
_VALUE_OPTIONS = frozenset({"--home", "--workers", "--rate"})
_CI_VARS = ("CI", "GITHUB_ACTIONS", "GITLAB_CI", "TF_BUILD", "BUILDKITE", "JENKINS_URL", "TEAMCITY_VERSION")
_FALSE = ("", "0", "false", "no")
_SAMPLE = BLOCK + "".join(sorted(SHADOW_CHARS)) + "─◆·"


# ---------------------------------------------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------------------------------------------


def hex_rgb(value: str) -> RGB:
    return int(value[1:3], 16), int(value[3:5], 16), int(value[5:7], 16)


def mix(a: RGB, b: RGB, f: float) -> RGB:
    """Linear interpolation in RGB, rounded half up."""
    r, g, bl = (int(x + (y - x) * f + 0.5) for x, y in zip(a, b, strict=True))
    return r, g, bl


def art_rgb(row: int, col: int) -> RGB:
    """Light mint at the top left to deep emerald at the bottom right: t = 0.72 row/5 + 0.28 col/50."""
    t = min(1.0, max(0.0, 0.72 * (row / 5) + 0.28 * (col / 50)))
    seg = t * (len(STOPS) - 1)
    i = min(int(seg), len(STOPS) - 2)
    return mix(hex_rgb(STOPS[i]), hex_rgb(STOPS[i + 1]), seg - i)


def art_256(row: int, col: int) -> int:
    t = 0.72 * (row / 5) + 0.28 * (col / 50)
    return ART_256[min(int(t / ART_256_STEP + 1e-9), len(ART_256) - 1)]


def line_rgb(i: int) -> RGB:
    """The frame lines fade from #45bf88 at the center to #0c0c0c at the ends, eased by the power 1.6."""
    return mix(hex_rgb(LINE_CENTER), hex_rgb(LINE_END), (abs(i - CENTER) / CENTER) ** 1.6)


def xterm_rgb(index: int) -> RGB:
    if index >= 232:
        v = 8 + 10 * (index - 232)
        return v, v, v
    levels = (0, 95, 135, 175, 215, 255)
    n = index - 16
    return levels[n // 36], levels[(n // 6) % 6], levels[n % 6]


def nearest_256(rgb: RGB, palette: Sequence[int]) -> int:
    def dist(index: int) -> int:
        x = xterm_rgb(index)
        return (x[0] - rgb[0]) ** 2 + (x[1] - rgb[1]) ** 2 + (x[2] - rgb[2]) ** 2

    return min(palette, key=dist)


# ---------------------------------------------------------------------------------------------------------------
# Layout
# ---------------------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Cell:
    text: str
    rgb: RGB | None = None
    c256: int | None = None
    bold: bool = False
    block: bool = False


def _pad(width: int) -> int:
    return (FRAME - width) // 2


def _rule() -> list[Cell]:
    cells = []
    for i in range(FRAME):
        if i == CENTER:
            cells.append(Cell("◆", hex_rgb(DIAMOND), DIAMOND_256))
        elif abs(i - CENTER) == 1:
            cells.append(Cell(" "))
        else:
            rgb = line_rgb(i)
            cells.append(Cell("─", rgb, nearest_256(rgb, LINE_256)))
    return cells


def _art_row(row: int) -> list[Cell]:
    cells = []
    for col, ch in enumerate(ART[row]):
        if ch == BLOCK:
            cells.append(Cell(ch, art_rgb(row, col), art_256(row, col), block=True))
        elif ch in SHADOW_CHARS:
            cells.append(Cell(ch, hex_rgb(SHADOW), SHADOW_256))
        else:
            cells.append(Cell(ch))
    return cells


def _tagline() -> list[Cell]:
    starts = {TAGLINE.index(w) for w in ACRONYM_WORDS}
    return [
        Cell(ch, hex_rgb(ACRONYM_COLOR), ACRONYM_256, bold=True)
        if i in starts
        else Cell(ch, hex_rgb(TAGLINE_COLOR), TAGLINE_256)
        for i, ch in enumerate(TAGLINE)
    ]


def version_line(version: str) -> str:
    return f"v{version}  ·  {URL}"


def layout(version: str) -> list[list[Cell]]:
    """Every banner line as cells, without the 2-space indent: rule, blank, art, blank, tagline, version, blank, rule,
    and the blank line that follows the banner."""
    vline = version_line(version)
    rows: list[list[Cell]] = [_rule(), []]
    rows += [[Cell(" " * _pad(len(ART[0]))), *_art_row(r)] for r in range(len(ART))]
    rows.append([])
    rows.append([Cell(" " * _pad(len(TAGLINE))), *_tagline()])
    rows.append([Cell(" " * _pad(len(vline))), Cell(vline, hex_rgb(VERSION_COLOR), VERSION_256)])
    rows += [[], _rule(), []]
    return rows


def plain(version: str) -> str:
    """The same layout without any color."""
    return "".join(((" " * INDENT + "".join(c.text for c in row)) if row else "") + "\n" for row in layout(version))


def _style(cell: Cell, mode: Mode, blocks_as_background: bool) -> Style | None:
    if cell.rgb is None or mode == "none":
        return None
    color = Color.from_rgb(*cell.rgb) if mode == "truecolor" else Color.from_ansi(cell.c256 or 0)
    if cell.block and blocks_as_background:
        return Style(bgcolor=color)
    return Style(color=color, bold=cell.bold or None)


def rich_lines(version: str, mode: Mode, *, blocks_as_background: bool = False) -> list[Text]:
    out = []
    for row in layout(version):
        line = Text(" " * INDENT if row else "", no_wrap=True, end="")
        for cell in row:
            text = " " if (cell.block and blocks_as_background) else cell.text
            line.append(text, style=_style(cell, mode, blocks_as_background))
        out.append(line)
    return out


# ---------------------------------------------------------------------------------------------------------------
# When and how it shows
# ---------------------------------------------------------------------------------------------------------------


def color_mode(env: Mapping[str, str], no_color: bool = False) -> Mode:
    if no_color or env.get("NO_COLOR"):
        return "none"
    if env.get("COLORTERM", "").lower() in ("truecolor", "24bit") or env.get("WT_SESSION"):
        return "truecolor"
    if "256color" in env.get("TERM", "").lower():
        return "256"
    return "none"


def wants_banner(argv: Sequence[str]) -> tuple[bool, bool]:
    """(show, no_color) for a command line, read from the global options before the command."""
    json_out = quiet = no_color = False
    command: str | None = None
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg in _VALUE_OPTIONS:
            i += 2
            continue
        if arg == "--json":
            json_out = True
        elif arg == "--quiet":
            quiet = True
        elif arg == "--no-color":
            no_color = True
        elif not arg.startswith("-"):
            command = arg
            break
        i += 1
    return (command is None or command in BANNER_COMMANDS) and not (json_out or quiet), no_color


def _isatty(stream: object) -> bool:
    try:
        return bool(stream.isatty())  # type: ignore[attr-defined]
    except (AttributeError, ValueError, OSError):
        return False


def enabled(env: Mapping[str, str], stdout: object, stderr: object) -> bool:
    if env.get("KLONER_NO_BANNER", "").lower() not in _FALSE:
        return False
    if any(env.get(v, "").lower() not in _FALSE for v in _CI_VARS):
        return False
    return _isatty(stdout) and _isatty(stderr)


def terminal_width(stream: object, env: Mapping[str, str]) -> int:
    cols = env.get("COLUMNS", "")
    if cols.isdigit():
        return int(cols)
    try:
        columns = os.get_terminal_size(stream.fileno()).columns  # type: ignore[attr-defined]
    except (AttributeError, OSError, ValueError, io.UnsupportedOperation):
        return 80
    # 0 means the size is unknown (a container terminal with no client terminal attached), as in shutil.
    return columns if columns > 0 else 80


def can_encode(stream: object) -> bool:
    encoding = getattr(stream, "encoding", None) or "ascii"
    try:
        _SAMPLE.encode(encoding)
    except (UnicodeEncodeError, LookupError):
        return False
    return True


def write(stream: TextIO, version: str, mode: Mode, width: int) -> None:
    if width < MIN_WIDTH or not can_encode(stream):
        stream.write(f"KLONER v{version}\n")
    elif mode == "none":
        stream.write(plain(version))
    else:
        console = Console(
            file=stream,
            force_terminal=True,
            color_system="truecolor" if mode == "truecolor" else "256",
            width=max(width, MIN_WIDTH),
            highlight=False,
            soft_wrap=True,
            emoji=False,
            markup=False,
        )
        for line in rich_lines(version, mode):
            console.print(line)
    stream.flush()


def show(
    argv: Sequence[str],
    version: str,
    *,
    env: Mapping[str, str] | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> bool:
    """Print the banner to stderr if this invocation and this terminal want it. Returns whether it printed."""
    env = os.environ if env is None else env
    out = sys.stdout if stdout is None else stdout
    err = sys.stderr if stderr is None else stderr
    wanted, no_color = wants_banner(argv)
    if not wanted or not enabled(env, out, err):
        return False
    write(err, version, color_mode(env, no_color), terminal_width(err, env))
    return True


# ---------------------------------------------------------------------------------------------------------------
# SVG for the README (exported with rich)
# ---------------------------------------------------------------------------------------------------------------

_THEME = TerminalTheme(
    (12, 12, 12),
    (163, 199, 182),
    [
        (12, 12, 12),
        (205, 92, 92),
        (69, 191, 136),
        (215, 175, 95),
        (95, 135, 175),
        (175, 135, 175),
        (95, 175, 175),
        (163, 199, 182),
    ],
    [
        (43, 114, 88),
        (240, 128, 128),
        (127, 230, 179),
        (240, 210, 140),
        (135, 175, 215),
        (215, 175, 215),
        (135, 215, 215),
        (194, 245, 218),
    ],
)
_CHAR_HEIGHT = 20
_ASPECT = 0.61
_SVG_COLS = MIN_WIDTH + INDENT  # the 2-column indent mirrored on the right


def svg(version: str) -> str:
    """The banner as SVG, exported by rich. Block cells are drawn as cell-sized background rectangles, so the
    wordmark stays solid whatever monospace font the viewer has; the font stack has no external URLs."""
    lines = rich_lines(version, "truecolor", blocks_as_background=True)[:-1]  # no trailing blank line
    console = Console(
        record=True,
        file=io.StringIO(),
        force_terminal=True,
        color_system="truecolor",
        width=_SVG_COLS,
        highlight=False,
        soft_wrap=True,
        legacy_windows=False,
    )
    for line in lines:
        console.print(line)
    char_width = _CHAR_HEIGHT * _ASPECT
    line_height = _CHAR_HEIGHT * 1.22
    content_w = _SVG_COLS * char_width
    content_h = len(lines) * line_height
    pad_x, pad_y = 4.0, line_height
    width, height = content_w + 2 * pad_x, content_h + 2 * pad_y
    template = (
        _SVG_TEMPLATE.replace("@W@", f"{width:.1f}")
        .replace("@H@", f"{height:.1f}")
        .replace("@CW@", f"{content_w:.1f}")
        .replace("@CH@", f"{content_h:.1f}")
        .replace("@X@", f"{pad_x:.1f}")
        .replace("@Y@", f"{pad_y:.1f}")
    )
    return console.export_svg(
        title="KLONER", theme=_THEME, code_format=template, font_aspect_ratio=_ASPECT, unique_id="kloner"
    )


_SVG_TEMPLATE = """<svg class="rich-terminal" viewBox="0 0 @W@ @H@" xmlns="http://www.w3.org/2000/svg">
    <!-- Generated with Rich https://www.textualize.io by kloner.banner.svg() -->
    <title>KLONER: Key-Lineage Oracle for Network-wide Exposure of Repackaging</title>
    <style>
    .{unique_id}-matrix {{
        font-family: "Cascadia Mono", "Fira Code", "DejaVu Sans Mono", Menlo, Consolas, monospace;
        font-size: {char_height}px;
        line-height: {line_height}px;
        font-variant-east-asian: full-width;
    }}
    {styles}
    </style>
    <defs>
    <clipPath id="{unique_id}-clip-terminal">
      <rect x="0" y="0" width="@CW@" height="@CH@" />
    </clipPath>
    {lines}
    </defs>
    <rect fill="#0c0c0c" x="0" y="0" width="@W@" height="@H@" rx="12" />
    <g transform="translate(@X@, @Y@)" clip-path="url(#{unique_id}-clip-terminal)">
    {backgrounds}
    <g class="{unique_id}-matrix">
    {matrix}
    </g>
    </g>
</svg>
"""
