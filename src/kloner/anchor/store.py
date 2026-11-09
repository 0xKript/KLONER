"""Anchor store: one canonical JSON record per package under <home>/anchors/, history in SQLite.

Every record carries ``record_sha256`` (SHA-256 over its canonical JSON without that field). A
record whose hash does not match its content is refused (it was edited outside KLONER).
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

from kloner.intel.db import IntelDB
from kloner.models import Anchor
from kloner.util.canonical import canonical_sha256

PACKAGE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$")


class AnchorIntegrityError(Exception):
    pass


def valid_package(name: str) -> bool:
    return bool(PACKAGE_RE.match(name)) and len(name) <= 255


def record_hash(anchor: Anchor) -> str:
    data = anchor.model_dump(mode="json", by_alias=True)
    data.pop("record_sha256", None)
    return canonical_sha256(data)


def seal(anchor: Anchor) -> Anchor:
    anchor.identities.sort(key=lambda i: (i.declared_additional, i.role != "current", i.id))
    anchor.record_sha256 = record_hash(anchor)
    return anchor


class AnchorStore:
    def __init__(self, home: Path, db: IntelDB | None = None) -> None:
        self.dir = home / "anchors"
        self.dir.mkdir(parents=True, exist_ok=True)
        self.db = db

    def path(self, package: str) -> Path:
        if not valid_package(package):
            raise ValueError(f"not a valid Android package name: {package!r}")
        return self.dir / f"{package}.json"

    def get(self, package: str) -> Anchor | None:
        p = self.path(package)
        if not p.is_file():
            return None
        anchor = Anchor.model_validate(json.loads(p.read_text(encoding="utf-8")))
        if record_hash(anchor) != anchor.record_sha256:
            raise AnchorIntegrityError(
                f"anchor {package} was modified outside KLONER (record hash mismatch); restore it with "
                f"kloner anchor import, or recreate it with kloner anchor add"
            )
        return anchor

    def save(self, anchor: Anchor) -> Anchor:
        seal(anchor)
        p = self.path(anchor.package)
        tmp = p.with_suffix(".json.tmp")
        tmp.write_text(
            json.dumps(anchor.model_dump(mode="json", by_alias=True), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        os.replace(tmp, p)
        if self.db is not None:
            self.db.put_anchor(anchor)
        return anchor

    def list(self) -> list[Anchor]:
        out = []
        for p in sorted(self.dir.glob("*.json")):
            a = self.get(p.stem)
            if a is not None:
                out.append(a)
        return out

    def snapshot(self) -> dict[str, Anchor]:
        return {a.package: a for a in self.list()}
