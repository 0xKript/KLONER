"""Write docs/assets/banner.svg: the startup banner exported by rich (D-067).

Usage: python scripts/export_banner.py [--out docs/assets/banner.svg]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from kloner import __version__  # noqa: E402
from kloner.banner import svg  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=Path, default=ROOT / "docs" / "assets" / "banner.svg")
    args = ap.parse_args()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_bytes(svg(__version__).encode("utf-8"))
    print(f"{args.out}: {args.out.stat().st_size} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
