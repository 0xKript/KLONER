"""Hashing helpers. SHA-256 is KLONER's identity hash (INV-9).

MD5 and SHA-1 exist only to compare against third-party claims that use them.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import BinaryIO

CHUNK = 1 << 20


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(CHUNK), b""):
            h.update(block)
    return h.hexdigest()


def sha256_stream(f: BinaryIO, length: int) -> str:
    h = hashlib.sha256()
    remaining = length
    while remaining > 0:
        block = f.read(min(CHUNK, remaining))
        if not block:
            break
        h.update(block)
        remaining -= len(block)
    return h.hexdigest()


def third_party_digests(path: Path) -> dict[str, str]:
    """MD5/SHA-1/SHA-256 of a file, for comparison with claims made by sources (labeled as such)."""
    md5 = hashlib.md5(usedforsecurity=False)
    sha1 = hashlib.sha1(usedforsecurity=False)
    sha256 = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(CHUNK), b""):
            md5.update(block)
            sha1.update(block)
            sha256.update(block)
    return {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest()}


def cert_digests(der: bytes) -> dict[str, str]:
    """Certificate digests. SHA-256 is the identity; SHA-1/MD5 are for third-party comparisons only."""
    return {
        "sha256": hashlib.sha256(der).hexdigest(),
        "sha1": hashlib.sha1(der, usedforsecurity=False).hexdigest(),
        "md5": hashlib.md5(der, usedforsecurity=False).hexdigest(),
    }
