"""Certificate fingerprint normalization (§7.5)."""

from __future__ import annotations

import re

_HEX = re.compile(r"^[0-9a-f]+$")
_STRIP = re.compile(r"[\s:\-]")


class FingerprintError(ValueError):
    """A fingerprint is not a 32-byte (SHA-256) hex string."""


def normalize_fingerprint(value: str) -> str:
    """Normalize to lowercase hex; colons, dashes and whitespace are stripped. Must be exactly 32 bytes."""
    s = _STRIP.sub("", value.strip()).lower()
    if not _HEX.match(s):
        raise FingerprintError(f"not a hex fingerprint: {value!r}")
    if len(s) != 64:
        raise FingerprintError(f"a SHA-256 fingerprint has 64 hex digits, got {len(s)}: {value!r}")
    return s


def is_sha256_hex(value: str) -> bool:
    return len(value) == 64 and bool(_HEX.match(value))


def short_fp(value: str | None) -> str:
    """Compact display form: first 4 and last 3 hex digits ("9a1f…c03")."""
    if not value:
        return "—"
    return f"{value[:4]}…{value[-3:]}"


def colon_fp(value: str) -> str:
    """Colon-separated uppercase form, as vendors usually publish it."""
    return ":".join(value[i : i + 2] for i in range(0, len(value), 2)).upper()
