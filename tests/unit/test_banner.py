"""The startup banner (D-067): exact colors and layout, when it shows, and that it never touches stdout."""

from __future__ import annotations

import io
import itertools
import re
from pathlib import Path

import pytest

from kloner import __version__, cli
from kloner import banner as b

ROOT = Path(__file__).resolve().parents[2]
ANSI = re.compile(r"\x1b\[[0-9;]*m")
ART = (
    "██╗  ██╗██╗      ██████╗ ███╗   ██╗███████╗██████╗",
    "██║ ██╔╝██║     ██╔═══██╗████╗  ██║██╔════╝██╔══██╗",
    "█████╔╝ ██║     ██║   ██║██╔██╗ ██║█████╗  ██████╔╝",
    "██╔═██╗ ██║     ██║   ██║██║╚██╗██║██╔══╝  ██╔══██╗",
    "██║  ██╗███████╗╚██████╔╝██║ ╚████║███████╗██║  ██║",
    "╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝",
)


class Term(io.TextIOWrapper):
    """A text stream that reports itself as a terminal, or not."""

    def __init__(self, encoding: str = "utf-8", tty: bool = True) -> None:
        super().__init__(io.BytesIO(), encoding=encoding, newline="\n", write_through=True)
        self._tty = tty

    def isatty(self) -> bool:
        return self._tty

    def text(self) -> str:
        self.flush()
        raw = self.buffer
        assert isinstance(raw, io.BytesIO)
        return raw.getvalue().decode(self.encoding)


def _render(mode: b.Mode, version: str = "1.0.0", width: int = 100, encoding: str = "utf-8") -> str:
    s = Term(encoding)
    b.write(s, version, mode, width)
    return s.text()


def _sgr(rgb: tuple[int, int, int], bold: bool = False) -> str:
    return f"\x1b[{'1;' if bold else ''}38;2;{rgb[0]};{rgb[1]};{rgb[2]}m"


def test_the_art_is_the_ansi_shadow_wordmark() -> None:
    assert tuple(r.rstrip() for r in b.ART) == ART
    assert all(len(r) == 51 for r in b.ART)
    assert set("".join(b.ART)) == {" ", "█", "╗", "╔", "═", "║", "╝", "╚"}


def test_true_color_codes_carry_the_exact_values() -> None:
    out = _render("truecolor")
    assert "38;5;" not in out
    assert b.art_rgb(0, 0) == (0xC2, 0xF5, 0xDA) and b.art_rgb(5, 50) == (0x22, 0x87, 0x5C)
    for row, line in enumerate(b.ART):
        for col, ch in enumerate(line):
            if ch == "█":
                assert _sgr(b.art_rgb(row, col)) + "█" in out, (row, col)
    assert _sgr((0x2B, 0x72, 0x58)) + "╗" in out and _sgr((0x2B, 0x72, 0x58)) + "╚" in out
    assert out.count(_sgr((0x7F, 0xE6, 0xB3)) + "◆") == 2
    assert b.line_rgb(31) == (0x45, 0xBF, 0x88) and b.line_rgb(0) == b.line_rgb(62) == (0x0C, 0x0C, 0x0C)
    for i in (0, 10, 29, 33, 50, 62):
        assert _sgr(b.line_rgb(i)) + "─" in out, i
    for letter in "KLONER":
        assert _sgr((0x7F, 0xE6, 0xB3), bold=True) + letter in out, letter
    assert _sgr((0xA3, 0xC7, 0xB6)) + "e" in out  # "ey-" after the bold K
    assert _sgr((0x5F, 0x85, 0x77)) + "v1.0.0  ·  github.com/0xKript/kloner" in out


def test_layout_frame_and_centering() -> None:
    lines = b.plain("1.0.0").split("\n")
    rule = "  " + "─" * 30 + " ◆ " + "─" * 30
    assert lines == [
        rule,
        "",
        *("  " + " " * 6 + r for r in b.ART),
        "",
        "  " + " " * 2 + b.TAGLINE,
        "  " + " " * 13 + "v1.0.0  ·  github.com/0xKript/kloner",
        "",
        rule,
        "",
        "",  # the blank line after the banner, then the end of the text
    ]
    long = "10.200.3000rc1"
    vline = next(x for x in b.plain(long).split("\n") if "github.com" in x)
    assert vline == "  " + " " * ((63 - len(f"v{long}  ·  github.com/0xKript/kloner")) // 2) + f"v{long}  ·  " + b.URL
    for mode in ("truecolor", "256"):
        assert ANSI.sub("", _render(mode)) == b.plain("1.0.0"), mode  # the same layout in every mode


def test_the_256_color_path_uses_the_hand_picked_ramps() -> None:
    out = _render("256")
    assert "38;2;" not in out
    used = {int(n) for n in re.findall(r"38;5;(\d+)", out)}
    singles = {b.SHADOW_256, b.DIAMOND_256, b.TAGLINE_256, b.ACRONYM_256, b.VERSION_256}
    allowed = set(b.ART_256) | set(b.LINE_256) | singles
    assert used <= allowed and set(b.ART_256) <= used
    assert all(i not in used for i in (35, 36, 43, 46, 47, 48, 82, 83, 84, 85, 86, 118, 119, 120))  # neon greens
    for row in range(5):  # one color change per row, at the same column: a regular staircase
        colors = [b.art_256(row, c) for c, ch in enumerate(b.ART[row]) if ch == "█"]
        changes = sum(1 for x, y in itertools.pairwise(colors) if x != y)
        assert changes <= 1, row


def test_no_color_prints_the_same_layout_uncolored() -> None:
    assert b.color_mode({"NO_COLOR": "1", "WT_SESSION": "x"}) == "none"
    assert b.color_mode({"COLORTERM": "truecolor"}, no_color=True) == "none"
    out = _render("none")
    assert "\x1b[" not in out and out == b.plain("1.0.0")


def test_color_detection_is_safe() -> None:
    assert b.color_mode({"COLORTERM": "truecolor"}) == "truecolor"
    assert b.color_mode({"COLORTERM": "24bit"}) == "truecolor"
    assert b.color_mode({"WT_SESSION": "4c8e…"}) == "truecolor"  # Windows Terminal, also inside WSL and Docker
    assert b.color_mode({"TERM": "xterm-256color"}) == "256"
    assert b.color_mode({"TERM": "xterm"}) == "none"
    assert b.color_mode({}) == "none"


def test_a_narrow_terminal_gets_one_plain_line(monkeypatch: pytest.MonkeyPatch) -> None:
    assert _render("truecolor", width=64) == "KLONER v1.0.0\n"
    assert _render("truecolor", width=65).count("\n") == 14
    assert b.terminal_width(Term(), {"COLUMNS": "64"}) == 64
    # a size of 0 x 0 means unknown (docker run -t with no client terminal attached), not narrow
    monkeypatch.setattr(b.os, "get_terminal_size", lambda _fd: b.os.terminal_size((0, 0)))
    monkeypatch.setattr(Term, "fileno", lambda self: 2, raising=False)
    assert b.terminal_width(Term(), {}) == 80


@pytest.mark.parametrize("encoding", ["ascii", "cp1252", "cp437"])
def test_a_console_that_cannot_encode_the_banner_gets_one_plain_line(encoding: str) -> None:
    assert _render("truecolor", encoding=encoding) == "KLONER v1.0.0\n"


@pytest.mark.parametrize(
    ("argv", "shown"),
    [
        ([], True),
        (["--help"], True),
        (["--version"], True),
        (["hunt", "org.example"], True),
        (["verify", "a.apk"], True),
        (["fetch", "https://x"], True),
        (["survey", "org.example"], True),
        (["--home", "h", "--workers", "2", "doctor"], True),
        (["selftest", "--full"], True),
        (["hunt", "--help"], True),
        (["--json", "hunt", "org.example"], False),
        (["--quiet", "doctor"], False),
        (["--json"], False),
        (["anchor", "show", "org.example"], False),
        (["anchor", "list"], False),
        (["explain", "abc"], False),
        (["intel", "sources"], False),
        (["report", "run-1"], False),
        (["reverify", "run-1"], False),
        (["setup"], False),
    ],
)
def test_where_it_shows(argv: list[str], shown: bool) -> None:
    assert b.wants_banner(argv)[0] is shown
    assert b.wants_banner(["--no-color", *argv])[1] is True


def test_it_needs_two_terminals_and_no_ci_and_no_opt_out() -> None:
    tty, pipe = Term(), Term(tty=False)
    assert b.enabled({}, tty, tty)
    assert not b.enabled({}, pipe, tty)  # stdout piped or redirected
    assert not b.enabled({}, tty, pipe)  # stderr piped or redirected
    assert not b.enabled({"CI": "true"}, tty, tty)
    assert not b.enabled({"GITHUB_ACTIONS": "true"}, tty, tty)
    assert not b.enabled({"KLONER_NO_BANNER": "1"}, tty, tty)
    assert b.enabled({"KLONER_NO_BANNER": "0"}, tty, tty)


def test_show_writes_only_to_stderr() -> None:
    env = {"WT_SESSION": "x", "COLUMNS": "100"}
    out, err = Term(), Term()
    assert b.show(["hunt", "org.example"], "1.0.0", env=env, stdout=out, stderr=err)
    assert out.text() == "" and "KLONER" not in err.text() and "38;2;194;245;218" in err.text()
    for argv in (["--json", "hunt", "x"], ["--quiet", "doctor"], ["anchor", "list"]):
        out, err = Term(), Term()
        assert not b.show(argv, "1.0.0", env=env, stdout=out, stderr=err)
        assert out.text() == err.text() == ""


@pytest.mark.parametrize("argv", [["--version"], ["--help"]])
def test_main_never_changes_stdout_or_the_exit_code(argv: list[str], monkeypatch: pytest.MonkeyPatch) -> None:
    for var in (*b._CI_VARS, "NO_COLOR", "KLONER_NO_BANNER"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("WT_SESSION", "test")
    monkeypatch.setenv("COLUMNS", "100")
    monkeypatch.setattr("sys.argv", ["kloner", *argv])
    results = []
    for opt_out in ("0", "1"):
        monkeypatch.setenv("KLONER_NO_BANNER", opt_out)
        out, err = Term(), Term()
        monkeypatch.setattr("sys.stdout", out)
        monkeypatch.setattr("sys.stderr", err)
        with pytest.raises(SystemExit) as e:
            cli.main()
        results.append((e.value.code, out.text(), err.text()))
    (code_on, out_on, err_on), (code_off, out_off, err_off) = results
    assert code_on == code_off == 0
    assert out_on == out_off and out_on  # stdout is byte for byte the same with and without the banner
    assert "38;2;194;245;218m█" in err_on and "█" not in err_off
    if argv == ["--version"]:
        assert out_on == f"kloner {__version__}\n"


def test_the_readme_svg_is_the_exported_banner() -> None:
    committed = (ROOT / "docs" / "assets" / "banner.svg").read_text(encoding="utf-8")
    assert committed == b.svg(__version__), "regenerate it: python scripts/export_banner.py"
    assert "https://" not in committed.replace("https://www.textualize.io", "")  # no external fonts
