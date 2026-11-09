"""UTC time helpers. Every timestamp KLONER writes is UTC, ISO 8601, second precision, 'Z' suffix."""

from __future__ import annotations

from datetime import UTC, datetime


def utc_now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def iso(dt: datetime) -> str:
    return dt.astimezone(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def now_iso() -> str:
    return iso(utc_now())


def run_id(dt: datetime | None = None) -> str:
    """Filesystem-safe run identifier, e.g. 2026-11-08T09-14-03Z."""
    return iso(dt or utc_now()).replace(":", "-")
