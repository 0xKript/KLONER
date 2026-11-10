"""Built-in sources (§8.2): local, url, aptoide, fdroid, apkpure, huawei, googleplay, HTML adapters."""

from __future__ import annotations

import json
import os
import platform
import re
import shutil
import tempfile
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

from kloner.acquire.base import DisabledSource, Source, SourceError
from kloner.acquire.fdroid import FdroidIndex
from kloner.acquire.http import Http, HttpError
from kloner.acquire.quarantine import Quarantine
from kloner.app import Runtime
from kloner.models import Claimed, ClientProfile, FetchResult, Offer
from kloner.toolchain import APKEEP_VERSION, apkeep_asset
from kloner.util import proc
from kloner.util.timeutil import now_iso

APTOIDE_WS = "https://ws75.aptoide.com/api/7"
HUAWEI_REASON = (
    "apkeep 1.1.0 (the pinned release) no longer ships a huawei-app-gallery downloader (it supports "
    "apk-pure, google-play and f-droid only) and AppGallery offers no other documented public API"
)
HTML_REASONS = {
    "uptodown": "HTML adapter not shipped in v1: no stable public API; scraping it reliably is not possible",
    "apkcombo": "HTML adapter not shipped in v1: the site serves bot-protection challenges KLONER must not bypass",
    "apkmirror": "HTML adapter not shipped in v1: the site is behind bot protection KLONER must not bypass",
}
ALL_SOURCES = (
    "local",
    "url",
    "apkpure",
    "aptoide",
    "fdroid",
    "huawei",
    "googleplay",
    "uptodown",
    "apkcombo",
    "apkmirror",
)
SEARCH_LIMIT = 25


def _profile(http: Http) -> ClientProfile:
    return ClientProfile(user_agent=http.user_agent, proxy=http.proxy)


# --------------------------------------------------------------------------------------------
# local
# --------------------------------------------------------------------------------------------


class LocalSource:
    name = "local"
    requires_credentials = False
    supports_versions = False
    supports_search = False

    def __init__(self, paths: list[Path], max_bytes: int) -> None:
        self.paths = paths
        self.max_bytes = max_bytes

    def _files(self) -> Iterator[Path]:
        for p in self.paths:
            if p.is_file():
                yield p
            elif p.is_dir():
                for f in sorted(p.rglob("*")):
                    if f.is_file() and not f.is_symlink():
                        yield f

    def discover(self, package: str, *, all_versions: bool, limit: int) -> Iterable[Offer]:
        for f in self._files():
            yield Offer(
                source="local", local_path=str(f), offer_url=f.resolve().as_uri(), file_type=f.suffix.lower() or None
            )

    def search(self, query: str, *, limit: int) -> Iterable[Offer]:
        return []

    def fetch(self, offer: Offer, sink: Quarantine) -> FetchResult:
        assert offer.local_path is not None
        sha, size = sink.ingest_file(Path(offer.local_path), self.max_bytes)
        return FetchResult(
            status="OK", sample_sha256=sha, size=size, final_url=offer.offer_url, retrieved_utc=now_iso()
        )


# --------------------------------------------------------------------------------------------
# url
# --------------------------------------------------------------------------------------------


class UrlSource:
    name = "url"
    requires_credentials = False
    supports_versions = False
    supports_search = False

    def __init__(self, urls: list[str], http: Http, max_bytes: int) -> None:
        self.urls = urls
        self.http = http
        self.max_bytes = max_bytes

    def discover(self, package: str, *, all_versions: bool, limit: int) -> Iterable[Offer]:
        for u in self.urls:
            yield Offer(source="url", download_url=u, offer_url=u)

    def search(self, query: str, *, limit: int) -> Iterable[Offer]:
        return []

    def fetch(self, offer: Offer, sink: Quarantine) -> FetchResult:
        assert offer.download_url is not None
        return download_offer(self.http, offer.download_url, sink, self.max_bytes, allow_http=True)


def download_offer(http: Http, url: str, q: Quarantine, max_bytes: int, *, allow_http: bool = False) -> FetchResult:
    try:
        with q.sink(max_bytes) as s:
            dl = http.download(url, s, allow_http=allow_http)
        sha, size = q.finalize(s)
    except HttpError as e:
        return FetchResult(
            status="BLOCKED" if e.blocked else "ERROR",
            reason=e.detail,
            http_status=e.status,
            retrieved_utc=now_iso(),
            client_profile=_profile(http),
        )
    return FetchResult(
        status="OK",
        sample_sha256=sha,
        size=size,
        final_url=dl.final_url,
        http_status=dl.status,
        content_type=dl.content_type,
        retrieved_utc=now_iso(),
        client_profile=_profile(http),
        tls_verified=dl.tls_verified,
    )


# --------------------------------------------------------------------------------------------
# aptoide
# --------------------------------------------------------------------------------------------


def _int_or_none(v: Any) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def aptoide_offer(item: dict[str, Any]) -> Offer | None:
    f = item.get("file") or {}
    path = f.get("path") or f.get("path_alt")
    if not path:
        return None
    sig = f.get("signature") or {}
    sha1 = sig.get("sha1")
    return Offer(
        source="aptoide",
        store=(item.get("store") or {}).get("name"),
        package=item.get("package"),
        label=item.get("name"),
        claimed=Claimed(
            version_name=f.get("vername"),
            version_code=_int_or_none(f.get("vercode")),
            md5=(f.get("md5sum") or "").lower() or None,
            signer_sha1=sha1.replace(":", "").lower() if isinstance(sha1, str) else None,
            signer_owner=sig.get("owner"),
            package=item.get("package"),
        ),
        download_url=path,
        offer_url=f"{APTOIDE_WS}/app/getMeta?app_id={item.get('id')}",
        file_type="apk",
        handle=str(item.get("id")),
    )


class AptoideSource:
    """Aptoide public web-services API (ws75, v7): metadata, versions, search, community stores."""

    name = "aptoide"
    requires_credentials = False
    supports_versions = True
    supports_search = True

    def __init__(self, http: Http, max_bytes: int, max_json: int) -> None:
        self.http = http
        self.max_bytes = max_bytes
        self.max_json = max_json

    def _json(self, path: str) -> dict[str, Any]:
        try:
            doc = self.http.get_document(f"{APTOIDE_WS}/{path}", self.max_json)
        except HttpError as e:
            raise SourceError("BLOCKED" if e.blocked else "ERROR", e.detail) from e
        try:
            data = json.loads(doc.content)
        except json.JSONDecodeError as e:
            raise SourceError("ERROR", f"invalid JSON from Aptoide: {e}") from e
        if not isinstance(data, dict):
            raise SourceError("ERROR", "unexpected Aptoide response")
        return data

    def discover(self, package: str, *, all_versions: bool, limit: int) -> Iterable[Offer]:
        pkg = quote(package, safe="")
        if not all_versions:
            data = self._json(f"app/getMeta?package_name={pkg}")
            item = data.get("data")
            if not item:
                return []
            offer = aptoide_offer(item)
            return [offer] if offer else []
        listing = self._json(f"listAppVersions?package_name={pkg}&limit={max(1, limit)}")
        out: list[Offer] = []
        for it in (listing.get("list") or [])[:limit]:
            app_id = it.get("id")
            if app_id is None:
                continue
            meta = self._json(f"app/getMeta?app_id={int(app_id)}").get("data")
            if meta:
                offer = aptoide_offer(meta)
                if offer:
                    out.append(offer)
        return out

    def search(self, query: str, *, limit: int) -> Iterable[Offer]:
        data = self._json(f"apps/search?query={quote(query, safe='')}&limit={max(1, min(limit, 100))}")
        out = []
        for it in ((data.get("datalist") or {}).get("list") or [])[:limit]:
            offer = aptoide_offer(it)
            if offer:
                out.append(offer)
        return out

    def fetch(self, offer: Offer, sink: Quarantine) -> FetchResult:
        assert offer.download_url is not None
        return download_offer(self.http, offer.download_url, sink, self.max_bytes)


# --------------------------------------------------------------------------------------------
# fdroid
# --------------------------------------------------------------------------------------------


class FdroidSource:
    """The official F-Droid repository, read from its index (index-v2, hash-checked via entry.json)."""

    name = "fdroid"
    requires_credentials = False
    supports_versions = True
    supports_search = True

    def __init__(self, rt: Runtime) -> None:
        self.index = FdroidIndex(rt)
        self.http = rt.http()
        self.max_bytes = rt.config.limits.max_file_bytes

    def _offer(self, package: str, v: dict[str, Any], label: str | None = None) -> Offer:
        return Offer(
            source="fdroid",
            store="f-droid.org",
            package=package,
            label=label,
            claimed=Claimed(
                version_name=v["version_name"],
                version_code=v["version_code"],
                sha256=v["sha256"],
                signer_sha256=v["signers"][0] if v["signers"] else None,
                package=package,
            ),
            download_url=v["url"],
            offer_url=f"https://f-droid.org/packages/{package}/",
            file_type="apk",
        )

    def discover(self, package: str, *, all_versions: bool, limit: int) -> Iterable[Offer]:
        try:
            versions = self.index.versions(package)
        except HttpError as e:
            raise SourceError("BLOCKED" if e.blocked else "ERROR", e.detail) from e
        chosen = versions[:limit] if all_versions else versions[:1]
        return [self._offer(package, v) for v in chosen]

    def search(self, query: str, *, limit: int) -> Iterable[Offer]:
        try:
            hits = self.index.search(query, limit)
        except HttpError as e:
            raise SourceError("BLOCKED" if e.blocked else "ERROR", e.detail) from e
        return [self._offer(pkg, v, label) for pkg, label, v in hits]

    def fetch(self, offer: Offer, sink: Quarantine) -> FetchResult:
        assert offer.download_url is not None
        return download_offer(self.http, offer.download_url, sink, self.max_bytes)


# --------------------------------------------------------------------------------------------
# apkeep (apkpure, googleplay)
# --------------------------------------------------------------------------------------------


def parse_apkeep_versions(text: str, package: str) -> list[str]:
    """Parse ``apkeep -l -o output_format=json`` output."""
    start = text.find("{")
    if start < 0:
        return []
    try:
        data = json.loads(text[start:])
    except json.JSONDecodeError:
        return []
    app = (data.get("apps") or {}).get(package) or {}
    return [v["version"] for v in app.get("available_versions", []) if isinstance(v, dict) and v.get("version")]


def _version_key(v: str) -> tuple[Any, ...]:
    return tuple(int(p) if p.isdigit() else p for p in re.split(r"[.\-_]", v))


class ApkeepSource:
    """Downloads through apkeep, the EFF's APK downloader (pinned 1.1.0)."""

    requires_credentials = False
    supports_versions = True
    supports_search = False

    def __init__(self, rt: Runtime, name: str, downloader: str, options: list[str], extra: list[str]) -> None:
        tc = rt.toolchain()
        if not tc.apkeep:
            if apkeep_asset() is None:
                raise SourceError(
                    "DISABLED",
                    f"apkeep {APKEEP_VERSION} publishes no build for {platform.system()} {platform.machine()}",
                )
            raise SourceError("ERROR", "apkeep is not installed; run: kloner setup")
        self.rt = rt
        self.name = name
        self.downloader = downloader
        self.options = options
        self.extra = extra
        self.apkeep = tc.apkeep
        self.max_bytes = rt.config.limits.max_file_bytes

    def _run(self, args: list[str], timeout: float) -> proc.ProcResult:
        return proc.run([self.apkeep, *args], timeout_s=timeout, env=proc.minimal_env())

    def discover(self, package: str, *, all_versions: bool, limit: int) -> Iterable[Offer]:
        if not all_versions:
            return [Offer(source=self.name, package=package, handle=package, claimed=Claimed(package=package))]
        res = self._run(["-l", "-a", package, "-d", self.downloader, "-o", "output_format=json", *self.extra], 300)
        versions = parse_apkeep_versions(res.text(), package)
        if not versions:
            if res.timed_out or res.returncode not in (0, None):
                raise SourceError("ERROR", f"apkeep could not list versions: {res.err_text().strip()[:200]}")
            return []
        versions = sorted(versions, key=_version_key, reverse=True)[:limit]
        return [
            Offer(
                source=self.name,
                package=package,
                handle=f"{package}@{v}",
                claimed=Claimed(version_name=v, package=package),
            )
            for v in versions
        ]

    def search(self, query: str, *, limit: int) -> Iterable[Offer]:
        return []

    def fetch(self, offer: Offer, sink: Quarantine) -> FetchResult:
        assert offer.handle is not None
        out = Path(tempfile.mkdtemp(prefix="apkeep-", dir=sink.incoming))
        try:
            opts = ",".join(self.options)
            args = ["-a", offer.handle, "-d", self.downloader, "-r", "1", *self.extra]
            if opts:
                args += ["-o", opts]
            res = self._run([*args, str(out)], 1800)
            files = sorted(
                f for f in out.rglob("*") if f.is_file() and f.suffix.lower() in (".apk", ".xapk", ".apks", ".apkm")
            )
            if not files:
                text = (res.text() + res.err_text()).strip().replace("\n", " ")[:300]
                return FetchResult(status="ERROR", reason=f"apkeep produced no file: {text}", retrieved_utc=now_iso())
            sha, size = sink.ingest_file(files[0], self.max_bytes)
            return FetchResult(
                status="OK",
                sample_sha256=sha,
                size=size,
                retrieved_utc=now_iso(),
                final_url=f"apkeep:{self.downloader}:{offer.handle}",
            )
        finally:
            shutil.rmtree(out, ignore_errors=True)


def play_credentials(rt: Runtime) -> tuple[str, str] | None:
    s = rt.config.sources
    email, token = os.environ.get(s.googleplay_email_env), os.environ.get(s.googleplay_token_env)
    return (email, token) if email and token else None


def build_source(
    rt: Runtime, name: str, *, local_paths: list[Path] | None = None, urls: list[str] | None = None
) -> Source | DisabledSource:
    limits = rt.config.parse_limits()
    max_bytes = rt.config.limits.max_file_bytes
    if name == "local":
        return LocalSource(local_paths or [], max_bytes)
    if name == "url":
        return UrlSource(urls or [], rt.http(), max_bytes)
    if name == "aptoide":
        return AptoideSource(rt.http(), max_bytes, limits.max_network_json_bytes)
    if name == "fdroid":
        return FdroidSource(rt)
    if name == "huawei":
        return DisabledSource("huawei", HUAWEI_REASON)
    if name in HTML_REASONS:
        return DisabledSource(name, HTML_REASONS[name])
    try:
        if name == "apkpure":
            return ApkeepSource(rt, "apkpure", "apk-pure", ["acknowledge_dangers=true"], [])
        if name == "googleplay":
            creds = play_credentials(rt)
            if creds is None:
                s = rt.config.sources
                return DisabledSource(
                    "googleplay", f"no credentials: set {s.googleplay_email_env} and {s.googleplay_token_env}"
                )
            extra = ["-e", creds[0], "-t", creds[1]]
            if os.environ.get("KLONER_PLAY_ACCEPT_TOS") == "1":
                extra.append("--accept-tos")
            src = ApkeepSource(rt, "googleplay", "google-play", [], extra)
            src.requires_credentials = True
            return src
    except SourceError as e:
        return DisabledSource(name, e.reason)
    return DisabledSource(name, f"unknown source {name!r}")


def host_label(url: str | None) -> str:
    return (urlsplit(url).hostname or "") if url else ""
