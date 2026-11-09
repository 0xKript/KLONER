#!/usr/bin/env python3
"""Generate data/confusables.json from Unicode's official confusables.txt (UTS #39).

The table maps a code point (hex) to its prototype "skeleton" string, as published by the Unicode
Consortium. KLONER uses it for the heuristic LOOKALIKE:CONFUSABLE label only.

Usage: python scripts/build_confusables.py [--out data/confusables.json]
"""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
URL = "https://www.unicode.org/Public/security/latest/confusables.txt"
UA = "kloner-build-confusables/1 (+https://github.com/0xKript/kloner)"


def parse(text: str) -> tuple[dict[str, str], str]:
    version = ""
    table: dict[str, str] = {}
    for line in text.splitlines():
        if line.startswith("# Version:"):
            version = line.split(":", 1)[1].strip()
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = [p.strip() for p in line.split(";")]
        if len(parts) < 2:
            continue
        src = parts[0]
        target = "".join(chr(int(cp, 16)) for cp in parts[1].split())
        table[src.lower()] = target
    return table, version


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=Path, default=ROOT / "data" / "confusables.json")
    args = ap.parse_args(argv)
    r = httpx.get(URL, headers={"User-Agent": UA}, timeout=60, follow_redirects=True)
    r.raise_for_status()
    raw = r.content
    table, version = parse(raw.decode("utf-8-sig"))
    doc = {
        "schema": "kloner.confusables/1",
        "source_url": URL,
        "unicode_version": version,
        "source_file_sha256": hashlib.sha256(raw).hexdigest(),
        "retrieved_utc": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "map": dict(sorted(table.items())),
    }
    args.out.write_text(json.dumps(doc, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    print(f"{len(table)} mappings, Unicode {version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
