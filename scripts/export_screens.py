"""Write docs/assets/screens/*.svg: real KLONER screens for the README (D-069).

Every screen is KLONER's own output, run in a throwaway home on the synthetic test corpus that `kloner selftest`
builds. Nothing is downloaded. With --anchor FILE (an anchor exported with `kloner anchor export`), the anchor screen
shows that anchor instead of the corpus one. The corpus keys are random, so hashes differ on every run.

Usage: python scripts/export_screens.py [--out docs/assets/screens] [--anchor FILE] [--width 104]
Needs the toolchain `kloner setup` installs (a JDK 17+ and Android build-tools 36.0.0).
"""

from __future__ import annotations

import argparse
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from rich.console import Console  # noqa: E402
from rich.terminal_theme import TerminalTheme  # noqa: E402
from rich.text import Text  # noqa: E402

P = "dev.kloner.fixture"
# Forces true-color ANSI out of every console, as a modern terminal receives it (on Windows rich would otherwise
# draw colors through the console API, which a capture cannot see). Only the capture changes, not the CLI.
SHIM = """
import sys
import rich.console as rc
_init = rc.Console.__init__
def init(self, *args, **kwargs):
    kwargs.setdefault("force_terminal", True)
    if not kwargs.get("no_color"):
        kwargs["color_system"] = "truecolor"
    kwargs["legacy_windows"] = False
    _init(self, *args, **kwargs)
rc.Console.__init__ = init
sys.path.insert(0, sys.argv[1])
from kloner.cli import main
sys.argv = ["kloner", *sys.argv[2:]]
main()
"""
THEME = TerminalTheme(
    (12, 12, 12),
    (163, 199, 182),
    [
        (12, 12, 12),
        (255, 107, 107),
        (69, 191, 136),
        (240, 199, 94),
        (127, 179, 213),
        (199, 146, 234),
        (127, 230, 179),
        (163, 199, 182),
    ],
    [
        (95, 133, 119),
        (255, 107, 107),
        (127, 230, 179),
        (240, 199, 94),
        (127, 179, 213),
        (199, 146, 234),
        (194, 245, 218),
        (230, 240, 235),
    ],
)
# rich's own template without its web fonts: GitHub serves SVGs under a policy that loads nothing external.
TEMPLATE = """<svg class="rich-terminal" viewBox="0 0 {width} {height}" xmlns="http://www.w3.org/2000/svg">
    <!-- Generated with Rich https://www.textualize.io by scripts/export_screens.py -->
    <style>
    .{unique_id}-matrix {{
        font-family: "Cascadia Mono", "Fira Code", "DejaVu Sans Mono", Menlo, Consolas, monospace;
        font-size: {char_height}px;
        line-height: {line_height}px;
        font-variant-east-asian: full-width;
    }}
    .{unique_id}-title {{
        font-size: 18px;
        font-weight: bold;
        font-family: "Segoe UI", Helvetica, Arial, sans-serif;
    }}
    {styles}
    </style>
    <defs>
    <clipPath id="{unique_id}-clip-terminal">
      <rect x="0" y="0" width="{terminal_width}" height="{terminal_height}" />
    </clipPath>
    {lines}
    </defs>
    {chrome}
    <g transform="translate({terminal_x}, {terminal_y})" clip-path="url(#{unique_id}-clip-terminal)">
    {backgrounds}
    <g class="{unique_id}-matrix">
    {matrix}
    </g>
    </g>
</svg>
"""


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=Path, default=ROOT / "docs" / "assets" / "screens")
    ap.add_argument("--anchor", type=Path, help="an exported anchor to show on the anchor screen")
    ap.add_argument("--width", type=int, default=104)
    args = ap.parse_args()

    from kloner.app import Runtime
    from kloner.selftest.runner import build
    from kloner.toolchain import setup

    args.out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="kloner-screens-") as tmp:
        work = Path(tmp)
        tc = work / "tc"
        tc.mkdir()
        setup(tc, install_apkeep_binary=False, user_agent="kloner-screens")
        rt = Runtime.open(tc, workers=4)
        (work / "corpus").mkdir()
        try:
            _cases, ctx = build(rt, work / "corpus", Console(quiet=True))
        finally:
            rt.close()
        files = {k: Path(v) for k, v in ctx["files"].items()}
        home = work / "home"
        (home / "toolchain").mkdir(parents=True)
        shutil.copy(tc / "toolchain" / "toolchain.json", home / "toolchain" / "toolchain.json")
        (home / "config.toml").write_text('[sources]\nenabled = ["local"]\n[general]\nworkers = 2\n', encoding="utf-8")
        drop = work / "downloads"
        drop.mkdir()
        for cid in ("C-01", "C-02", "C-03", "C-06", "C-15", "C-21", "C-22", "C-24", "C-25", "C-33", "X-02"):
            shutil.copy(files[cid], drop / f"{cid}{files[cid].suffix}")
        shim = work / "shim.py"
        shim.write_text(SHIM, encoding="utf-8")
        hide = sorted(
            {str(work), str(work).replace("\\", "/"), work.as_uri(), "/" + str(work).replace("\\", "/")},
            key=len,
            reverse=True,
        )

        def run(*cli_args: str) -> str:
            env = dict(os.environ)
            env.update({"FORCE_COLOR": "1", "COLUMNS": str(args.width), "TERMINAL_WIDTH": str(args.width)})
            env.update({"KLONER_NO_BANNER": "1", "PYTHONIOENCODING": "utf-8"})
            env.pop("NO_COLOR", None)
            r = subprocess.run(  # noqa: S603 (our own interpreter and arguments)
                [sys.executable, "-X", "utf8", str(shim), str(ROOT / "src"), "--home", str(home), *cli_args],
                capture_output=True,
                env=env,
                timeout=900,
                check=False,
            )
            out = r.stdout.decode("utf-8", "replace").replace("\r\n", "\n").replace("\r", "")
            for h in hide:
                out = out.replace(h, "~/kloner-demo")
            return out

        def shoot(name: str, title: str, *cli_args: str) -> str:
            out = run(*cli_args)
            rec = Console(
                record=True, width=args.width, force_terminal=True, color_system="truecolor", file=io.StringIO()
            )
            rec.print(Text.from_ansi(out.rstrip("\n")))
            svg = rec.export_svg(title=title, theme=THEME, code_format=TEMPLATE, font_aspect_ratio=0.61, unique_id=name)
            (args.out / f"{name}.svg").write_bytes(svg.encode("utf-8"))
            print(f"{args.out / (name + '.svg')}  {title}")
            return out

        shoot("help", "kloner --help", "--help")
        add = ("anchor", "add", P, "--from-apk", str(files["C-01"]), "--brand-label", "Kloner Fixture")
        if args.anchor:
            run(*add)
            package = json.loads(args.anchor.read_text(encoding="utf-8"))["package"]
            run("anchor", "import", str(args.anchor))
            shoot("anchor", f"kloner anchor show {package}", "anchor", "show", package)
        else:
            shoot("anchor", f"kloner anchor add {P} --from-apk …", *add)
        out_dir = work / "runs" / "demo"
        shoot(
            "hunt",
            f"kloner hunt {P}",
            "hunt",
            P,
            "--sources",
            "local",
            "--local",
            str(drop),
            "--out",
            str(out_dir),
            "--format",
            "terminal,json,html",
        )
        doc = json.loads((out_dir / "report.json").read_text(encoding="utf-8"))
        forged = next(s for s in doc["samples"] if s["evaluation"]["verdict"] == "FORGED")["evaluation"][
            "sample_sha256"
        ]
        shoot("explain", "kloner explain <sha256>", "explain", forged)
        shoot(
            "diff",
            "kloner diff <copy> --against <official>",
            "diff",
            str(files["C-33"]),
            "--against",
            str(files["C-01"]),
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
