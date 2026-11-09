"""apkeep-backed helpers used outside a hunt (anchor --from-play)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from kloner.acquire.base import DisabledSource, SourceError
from kloner.models import Offer

if TYPE_CHECKING:
    from kloner.app import Runtime


def play_download(rt: Runtime, package: str) -> tuple[str, str]:
    from kloner.acquire.sources import build_source

    src = build_source(rt, "googleplay")
    if isinstance(src, DisabledSource):
        raise SourceError("DISABLED", src.reason)
    res = src.fetch(Offer(source="googleplay", package=package, handle=package), rt.quarantine)
    if res.status != "OK" or res.sample_sha256 is None:
        raise SourceError(res.status, res.reason or "Google Play download failed")
    return res.sample_sha256, "downloaded through the Google Play API (apkeep) with the owner's credentials"
