"""Fetch discipline and source plugins against recorded HTTP fixtures (§8, P4)."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

import httpx
import pytest

from kloner.acquire.base import DisabledSource, SourceError, sighting_from
from kloner.acquire.http import Http, HttpError, RateLimiter, in_domain, looks_blocked, vendor_domain_policy
from kloner.acquire.sources import (
    AptoideSource,
    FdroidSource,
    LocalSource,
    UrlSource,
    aptoide_offer,
    build_source,
    download_offer,
    parse_apkeep_versions,
)
from kloner.app import Runtime
from tests.integration.conftest import fixture_json, mock_http

pytestmark = pytest.mark.toolchain


def _http(handler: Any) -> Http:
    return Http("kloner-tests", rate_per_host=1000.0, retries=2, transport=httpx.MockTransport(handler))


def test_https_is_required_and_redirect_policy_applies(fresh_rt: Runtime) -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.host == "vendor.example":
            return httpx.Response(302, headers={"location": "https://cdn.attacker.example/app.apk"})
        return httpx.Response(200, content=b"PK\x03\x04data")

    h = _http(handler)
    with pytest.raises(HttpError):
        h.get_document("http://vendor.example/x", 100)
    with pytest.raises(HttpError) as e:
        h.get_document("https://vendor.example/app.apk", 100, redirect_policy=vendor_domain_policy(["vendor.example"]))
    assert "outside the declared vendor domain" in e.value.detail
    with pytest.raises(HttpError):
        h.get_document("https://vendor.example/app.apk", 100, follow=False)
    doc = h.get_document("https://vendor.example/app.apk", 100)
    assert doc.final_url.startswith("https://cdn.attacker.example") and doc.chain[0].startswith("https://vendor")
    assert in_domain("dl.signal.org", "signal.org") and not in_domain("signal.org.evil.example", "signal.org")


def test_blocked_retry_and_size_limits(fresh_rt: Runtime) -> None:
    calls = {"n": 0}

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/blocked":
            return httpx.Response(403, content=b"<title>Just a moment...</title> cf-chl challenge")
        if req.url.path == "/flaky":
            calls["n"] += 1
            return httpx.Response(503) if calls["n"] == 1 else httpx.Response(200, content=b"ok")
        if req.url.path == "/big":
            return httpx.Response(200, content=b"x" * 2048)
        return httpx.Response(404)

    h = _http(handler)
    with pytest.raises(HttpError) as e:
        h.get_document("https://site.example/blocked", 1000)
    assert e.value.blocked
    assert h.get_document("https://site.example/flaky", 1000).content == b"ok"
    with pytest.raises(HttpError):
        h.get_document("https://site.example/big", 1000)
    with pytest.raises(HttpError) as e:
        h.get_document("https://site.example/missing", 1000)
    assert e.value.status == 404 and not e.value.blocked
    res = download_offer(h, "https://site.example/blocked", fresh_rt.quarantine, 1 << 20)
    assert res.status == "BLOCKED"
    assert looks_blocked(200, httpx.Headers({"cf-mitigated": "challenge"}), b"")


def test_rate_limiter_spaces_requests() -> None:
    rl = RateLimiter(20.0)
    t0 = time.monotonic()
    for _ in range(4):
        rl.wait("host.example")
    assert time.monotonic() - t0 >= 0.14
    rl.wait("other.example")


def test_download_streams_into_quarantine(fresh_rt: Runtime, corpus: dict[str, Any]) -> None:
    body = corpus["files"]["C-01"].read_bytes()

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/short":
            return httpx.Response(200, headers={"content-length": str(len(body) + 10)}, content=body)
        return httpx.Response(200, content=body, headers={"content-type": "application/vnd.android.package-archive"})

    h = _http(handler)
    ok = download_offer(h, "https://vendor.example/app.apk", fresh_rt.quarantine, 1 << 30)
    assert ok.status == "OK" and ok.sample_sha256 == hashlib.sha256(body).hexdigest() and ok.tls_verified
    assert fresh_rt.quarantine.has(ok.sample_sha256)
    insecure = download_offer(h, "http://vendor.example/app.apk", fresh_rt.quarantine, 1 << 30, allow_http=True)
    assert insecure.status == "OK" and insecure.tls_verified is False
    too_big = download_offer(h, "https://vendor.example/app.apk", fresh_rt.quarantine, 100)
    assert too_big.status == "ERROR"


APTOIDE = {
    "/api/7/app/getMeta": lambda q: (
        fixture_json(f"aptoide_getmeta_{q['app_id']}.json")
        if "app_id" in q
        else fixture_json("aptoide_getmeta_pkg.json")
    ),
    "/api/7/listAppVersions": lambda q: fixture_json("aptoide_versions.json"),
    "/api/7/apps/search": lambda q: fixture_json("aptoide_search.json"),
}


def aptoide_handler(req: httpx.Request) -> httpx.Response:
    fn = APTOIDE.get(req.url.path)
    if fn is None:
        return httpx.Response(200, content=b"PK\x03\x04apk-bytes")
    return httpx.Response(200, json=fn(dict(req.url.params)))


def test_aptoide_source_against_recorded_responses(fresh_rt: Runtime) -> None:
    src = AptoideSource(_http(aptoide_handler), 1 << 30, 1 << 20)
    latest = list(src.discover("org.thoughtcrime.securesms", all_versions=False, limit=5))
    assert len(latest) == 1
    o = latest[0]
    assert o.store == "appupdater" and o.claimed.signer_sha1 and len(o.claimed.signer_sha1) == 40
    assert o.claimed.md5 and o.claimed.version_code and o.download_url.startswith("https://")
    many = list(src.discover("org.thoughtcrime.securesms", all_versions=True, limit=3))
    assert len(many) == 3 and len({x.store for x in many}) >= 2
    hits = list(src.search("signal private messenger", limit=3))
    assert hits and all(h.package for h in hits)
    res = src.fetch(o, fresh_rt.quarantine)
    assert res.status == "OK" and res.sample_sha256
    s = sighting_from(o, res, ["METADATA_MISMATCH"])
    assert s.source == "aptoide" and s.labels == ["METADATA_MISMATCH"]
    assert aptoide_offer({"file": {}}) is None


def test_aptoide_errors_are_isolated(fresh_rt: Runtime) -> None:
    src = AptoideSource(_http(lambda r: httpx.Response(403, content=b"captcha required")), 1 << 30, 1 << 20)
    with pytest.raises(SourceError) as e:
        list(src.discover("a.b", all_versions=False, limit=1))
    assert e.value.status == "BLOCKED"
    src2 = AptoideSource(_http(lambda r: httpx.Response(200, content=b"not json")), 1 << 30, 1 << 20)
    with pytest.raises(SourceError):
        list(src2.discover("a.b", all_versions=False, limit=1))


def mini_fdroid(package: str, apk: bytes, signer: str) -> tuple[dict[str, Any], dict[str, Any]]:
    sha = hashlib.sha256(apk).hexdigest()
    index = {
        "repo": {"address": "https://f-droid.org/repo"},
        "packages": {
            package: {
                "metadata": {"name": {"en-US": "Kloner Fixture"}},
                "versions": {
                    sha: {
                        "added": 0,
                        "file": {"name": f"/{package}_1.apk", "sha256": sha, "size": len(apk)},
                        "manifest": {
                            "versionName": "1.0",
                            "versionCode": 1,
                            "signer": {"sha256": [signer]},
                            "usesSdk": {"minSdkVersion": 24, "targetSdkVersion": 35},
                        },
                    }
                },
            }
        },
    }
    raw = json.dumps(index).encode()
    entry = {
        "timestamp": 1,
        "version": 30000,
        "index": {"name": "/index-v2.json", "sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)},
    }
    return entry, index


def fdroid_handler(entry: dict[str, Any], index: dict[str, Any], apk: bytes) -> Any:
    raw = json.dumps(index).encode()

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/repo/entry.json":
            return httpx.Response(200, json=entry)
        if req.url.path == "/repo/index-v2.json":
            return httpx.Response(200, content=raw)
        if req.url.path.endswith(".apk"):
            return httpx.Response(200, content=apk)
        return httpx.Response(404)

    return handler


def test_fdroid_source(fresh_rt: Runtime, corpus: dict[str, Any]) -> None:
    apk = corpus["files"]["C-01"].read_bytes()
    entry, index = mini_fdroid("dev.kloner.fixture", apk, corpus["keys"]["vendor"].sha256)
    mock_http(fresh_rt, fdroid_handler(entry, index, apk))
    src = FdroidSource(fresh_rt)
    offers = list(src.discover("dev.kloner.fixture", all_versions=True, limit=5))
    assert len(offers) == 1 and offers[0].claimed.sha256 == hashlib.sha256(apk).hexdigest()
    assert list(src.discover("no.such.package", all_versions=False, limit=5)) == []
    assert [o.package for o in src.search("kloner", limit=5)] == ["dev.kloner.fixture"]
    res = src.fetch(offers[0], fresh_rt.quarantine)
    assert res.status == "OK"
    # cached index is reused (hash-checked) on the next instance
    assert list(FdroidSource(fresh_rt).discover("dev.kloner.fixture", all_versions=False, limit=1))


def test_local_and_url_sources(fresh_rt: Runtime, corpus: dict[str, Any], tmp_path: Path) -> None:
    d = tmp_path / "in"
    (d / "sub").mkdir(parents=True)
    (d / "sub" / "a.apk").write_bytes(corpus["files"]["C-01"].read_bytes())
    (d / "b.apk").write_bytes(corpus["files"]["C-02"].read_bytes())
    src = LocalSource([d], 1 << 30)
    offers = list(src.discover("x.y", all_versions=False, limit=10))
    assert len(offers) == 2
    assert all(src.fetch(o, fresh_rt.quarantine).status == "OK" for o in offers)
    url = UrlSource(["https://x.example/a.apk"], _http(lambda r: httpx.Response(200, content=b"PK")), 1 << 20)
    o = next(iter(url.discover("x", all_versions=False, limit=1)))
    assert url.fetch(o, fresh_rt.quarantine).status == "OK"
    assert list(src.search("q", limit=1)) == [] and list(url.search("q", limit=1)) == []


def test_registry_disables_unavailable_sources(fresh_rt: Runtime) -> None:
    for name in ("huawei", "uptodown", "apkcombo", "apkmirror", "googleplay", "apkpure", "bogus"):
        src = build_source(fresh_rt, name)
        assert isinstance(src, DisabledSource), name
        assert src.reason
        with pytest.raises(SourceError):
            list(src.discover("a.b", all_versions=False, limit=1))
    assert "apkeep 1.1.0" in build_source(fresh_rt, "huawei").reason  # type: ignore[union-attr]


def test_parse_apkeep_versions() -> None:
    text = 'noise {"source":"APKPure","apps":{"a.b":{"available_versions":[{"version":"1.2"},{"version":"1.10"}]}}}'
    assert parse_apkeep_versions(text, "a.b") == ["1.2", "1.10"]
    assert parse_apkeep_versions("no json", "a.b") == []
    assert parse_apkeep_versions('{"apps":{}}', "a.b") == []
