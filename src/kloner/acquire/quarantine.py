"""Content-addressed, read-only, extension-less sample store (§8.4, INV-5).

Layout: <home>/quarantine/ab/cd/<sha256>, files mode 0444, directories 0700. Samples are never
executed, installed, uploaded or written anywhere under their own names.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import stat
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import IO, Any

from kloner.util.fingerprints import is_sha256_hex

CHUNK = 1 << 20


class QuarantineError(Exception):
    pass


class Sink:
    """A write handle into the quarantine that hashes while it writes."""

    def __init__(self, fh: IO[bytes], tmp: Path, max_bytes: int) -> None:
        self._fh = fh
        self.tmp = tmp
        self.max_bytes = max_bytes
        self.size = 0
        self._h = hashlib.sha256()

    def write(self, data: bytes) -> None:
        self.size += len(data)
        if self.size > self.max_bytes:
            raise QuarantineError(f"sample exceeds the {self.max_bytes}-byte limit")
        self._h.update(data)
        self._fh.write(data)

    @property
    def sha256(self) -> str:
        return self._h.hexdigest()


class Quarantine:
    def __init__(self, home: Path) -> None:
        self.root = home / "quarantine"
        self.incoming = self.root / "incoming"
        self.evidence_root = home / "evidence"
        for d in (self.root, self.incoming, self.evidence_root):
            d.mkdir(parents=True, exist_ok=True)
            _private_dir(d)

    def path_for(self, sha256: str) -> Path:
        if not is_sha256_hex(sha256):
            raise QuarantineError(f"not a SHA-256: {sha256!r}")
        return self.root / sha256[:2] / sha256[2:4] / sha256

    def has(self, sha256: str) -> bool:
        return self.path_for(sha256).is_file()

    @contextlib.contextmanager
    def sink(self, max_bytes: int) -> Iterator[Sink]:
        fd, name = tempfile.mkstemp(dir=self.incoming, prefix="in-")
        tmp = Path(name)
        ok = False
        try:
            with os.fdopen(fd, "wb") as fh:
                s = Sink(fh, tmp, max_bytes)
                yield s
            ok = True
        finally:
            if not ok:
                tmp.unlink(missing_ok=True)

    def finalize(self, sink: Sink) -> tuple[str, int]:
        sha = sink.sha256
        dest = self.path_for(sha)
        dest.parent.mkdir(parents=True, exist_ok=True)
        _private_dir(dest.parent)
        _private_dir(dest.parent.parent)
        if dest.exists():
            sink.tmp.unlink(missing_ok=True)
        else:
            os.replace(sink.tmp, dest)
            os.chmod(dest, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
        return sha, sink.size

    def ingest_file(self, src: Path, max_bytes: int) -> tuple[str, int]:
        with self.sink(max_bytes) as s, src.open("rb") as f:
            for block in iter(lambda: f.read(CHUNK), b""):
                s.write(block)
        return self.finalize(s)

    def ingest_bytes(self, data: bytes, max_bytes: int) -> tuple[str, int]:
        with self.sink(max_bytes) as s:
            s.write(data)
        return self.finalize(s)

    def remove(self, sha256: str) -> None:
        p = self.path_for(sha256)
        if p.exists():
            os.chmod(p, stat.S_IRUSR | stat.S_IWUSR)
            p.unlink()

    def write_evidence(self, sha256: str, record: dict[str, Any]) -> Path:
        d = self.evidence_root / sha256
        d.mkdir(parents=True, exist_ok=True)
        n = len(list(d.glob("*.json")))
        path = d / f"sighting-{n + 1:04d}.json"
        path.write_text(json.dumps(record, sort_keys=True, indent=2), encoding="utf-8")
        return path


def _private_dir(path: Path) -> None:
    with contextlib.suppress(OSError):
        os.chmod(path, stat.S_IRWXU)
