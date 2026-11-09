"""Source plugin contract (§8.1)."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from kloner.acquire.quarantine import Quarantine
from kloner.models import FetchResult, Offer, Sighting
from kloner.util.timeutil import now_iso


class SourceError(Exception):
    """A source-level failure. ``status`` is BLOCKED, ERROR or NO_OFFERS."""

    def __init__(self, status: str, reason: str) -> None:
        super().__init__(f"{status}: {reason}")
        self.status = status
        self.reason = reason


@runtime_checkable
class Source(Protocol):
    name: str
    requires_credentials: bool
    supports_versions: bool
    supports_search: bool

    def discover(self, package: str, *, all_versions: bool, limit: int) -> Iterable[Offer]: ...

    def search(self, query: str, *, limit: int) -> Iterable[Offer]: ...

    def fetch(self, offer: Offer, sink: Quarantine) -> FetchResult: ...


@dataclass
class DisabledSource:
    """A registered source that does not run, with the reason it does not (never faked)."""

    name: str
    reason: str
    requires_credentials: bool = False
    supports_versions: bool = False
    supports_search: bool = False

    def discover(self, package: str, *, all_versions: bool, limit: int) -> Iterable[Offer]:
        raise SourceError("DISABLED", self.reason)

    def search(self, query: str, *, limit: int) -> Iterable[Offer]:
        raise SourceError("DISABLED", self.reason)

    def fetch(self, offer: Offer, sink: Quarantine) -> FetchResult:
        raise SourceError("DISABLED", self.reason)


def sighting_from(offer: Offer, result: FetchResult, labels: list[str] | None = None) -> Sighting:
    assert result.sample_sha256 is not None
    return Sighting(
        sample_sha256=result.sample_sha256,
        size=result.size or 0,
        source=offer.source,
        store=offer.store,
        offer_url=offer.offer_url,
        download_url=offer.download_url,
        final_url=result.final_url,
        http_status=result.http_status,
        content_type=result.content_type,
        retrieved_utc=result.retrieved_utc or now_iso(),
        client_profile=result.client_profile,
        claimed=offer.claimed,
        tls_verified=result.tls_verified,
        labels=sorted(labels or []),
    )
