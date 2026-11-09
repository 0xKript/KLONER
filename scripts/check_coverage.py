#!/usr/bin/env python3
"""Enforce the coverage gates of §18.7 on a coverage JSON report.

>= 90% line coverage for decide.py, verify/, container/ and anchor/; >= 80% overall.

Usage: pytest --cov=kloner --cov-report=json:coverage.json && python scripts/check_coverage.py coverage.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

GATES = {
    "decide.py": (("kloner/decide.py",), 90.0),
    "verify/": (("kloner/verify/",), 90.0),
    "container/": (("kloner/container/",), 90.0),
    "anchor/": (("kloner/anchor/",), 90.0),
}
OVERALL = 80.0


def main(argv: list[str]) -> int:
    path = Path(argv[1] if len(argv) > 1 else "coverage.json")
    data = json.loads(path.read_text(encoding="utf-8"))
    ok = True
    for name, (prefixes, gate) in GATES.items():
        stmts = missing = 0
        for f, v in data["files"].items():
            norm = f.replace("\\", "/")
            if any(p in norm for p in prefixes):
                stmts += v["summary"]["num_statements"]
                missing += v["summary"]["missing_lines"]
        pct = 100.0 * (stmts - missing) / stmts if stmts else 0.0
        status = "PASS" if pct >= gate else "FAIL"
        ok &= pct >= gate
        print(f"{status} {name:12s} {pct:5.1f}% (gate {gate:.0f}%)")
    total = float(data["totals"]["percent_covered"])
    print(f"{'PASS' if total >= OVERALL else 'FAIL'} {'overall':12s} {total:5.1f}% (gate {OVERALL:.0f}%)")
    ok &= total >= OVERALL
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
