"""Anchor error paths: refused provenance, failing source APKs, device and Play failures, refresh paths."""

from __future__ import annotations

import shutil
from typing import Any

import httpx
import pytest
from rich.console import Console

from kloner.anchor import methods
from kloner.anchor.lifecycle import refresh
from kloner.anchor.methods import AnchorError, merge
from kloner.app import Runtime
from kloner.util import proc
from kloner.util.fingerprints import colon_fp
from tests.integration.conftest import mock_http
from tests.integration.test_http_sources import fdroid_handler, mini_fdroid

pytestmark = pytest.mark.toolchain
P = "dev.kloner.fixture"


def test_apk_evidence_refusals(fresh_rt: Runtime, corpus: dict[str, Any]) -> None:
    f = corpus["files"]
    for cid, why in (("C-24", "not an APK"), ("C-02", None), ("C-06", "not intact"), ("C-22", "not an APK")):
        if why is None:
            continue
        with pytest.raises(AnchorError) as e:
            methods.from_apk(fresh_rt, P, f[cid])
        assert e.value.exit_code == 3 and why in str(e.value), (cid, str(e.value))


def test_network_failures_become_anchor_errors(fresh_rt: Runtime) -> None:
    mock_http(fresh_rt, lambda r: httpx.Response(500))
    with pytest.raises(AnchorError):
        methods.from_url(fresh_rt, P, "https://vendor.example/app.apk", ["vendor.example"])
    with pytest.raises(AnchorError):
        methods.from_fingerprints(fresh_rt, P, ["aa" * 32], "https://vendor.example/fp")
    with pytest.raises(AnchorError):
        methods.from_fingerprints(fresh_rt, P, ["aa" * 32], "http://vendor.example/fp")
    with pytest.raises(AnchorError):
        methods.from_assetlinks(fresh_rt, P, "vendor.example")
    mock_http(fresh_rt, lambda r: httpx.Response(200, content=b"{not json"))
    with pytest.raises(AnchorError):
        methods.from_assetlinks(fresh_rt, P, "vendor.example")


def test_assetlinks_without_dal_confirmation(fresh_rt: Runtime, corpus: dict[str, Any]) -> None:
    V = corpus["keys"]["vendor"]
    statements = [
        {
            "relation": ["delegate_permission/common.handle_all_urls"],
            "target": {
                "namespace": "android_app",
                "package_name": P,
                "sha256_cert_fingerprints": [colon_fp(V.sha256), "bad", 5],
            },
        },
        "junk",
    ]

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.host == "digitalassetlinks.googleapis.com":
            return httpx.Response(503)
        return httpx.Response(200, json=statements)

    mock_http(fresh_rt, handler)
    res = methods.from_assetlinks(fresh_rt, P, "vendor.example")
    assert res.identities[0].evidence[0].detail == "Google Digital Asset Links API cross-check not available"


def test_device_failures(fresh_rt: Runtime, corpus: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    tc = fresh_rt.toolchain()
    tc.adb = None
    with pytest.raises(AnchorError):
        methods.from_device(fresh_rt, P, "SERIAL")
    tc.adb = "adb-fake"
    state = {
        "installer": b"installerPackageName=com.example.sideload\n",
        "paths": b"package:/data/app/base.apk\n",
        "pull_ok": True,
    }

    real = proc.run

    def fake(argv: Any, **kw: Any) -> proc.ProcResult:
        args = [str(a) for a in argv]
        if args[0] != "adb-fake":
            return real(argv, **kw)
        if "pm" in args:
            return proc.ProcResult(tuple(args), 0, state["paths"], b"", False, 0.0)
        if "dumpsys" in args:
            return proc.ProcResult(tuple(args), 0, state["installer"], b"", False, 0.0)
        if "pull" in args:
            if state["pull_ok"]:
                shutil.copyfile(corpus["files"]["C-01"], args[-1])
                return proc.ProcResult(tuple(args), 0, b"", b"", False, 0.0)
            return proc.ProcResult(tuple(args), 1, b"", b"device offline", False, 0.0)
        return proc.ProcResult(tuple(args), 0, b"", b"", False, 0.0)

    monkeypatch.setattr(proc, "run", fake)
    res = methods.from_device(fresh_rt, P, "SERIAL")
    assert res.klass == "USER" and any("not an official store" in n for n in res.notes)
    state["pull_ok"] = False
    with pytest.raises(AnchorError):
        methods.from_device(fresh_rt, P, None)
    state["paths"] = b""
    with pytest.raises(AnchorError):
        methods.from_device(fresh_rt, P, None)


def test_play_without_credentials(fresh_rt: Runtime) -> None:
    with pytest.raises(AnchorError) as e:
        methods.from_play(fresh_rt, P)
    assert e.value.exit_code == 2 and "no credentials" in str(e.value)


def test_refresh_reruns_every_recorded_method(fresh_rt: Runtime, corpus: dict[str, Any]) -> None:
    V = corpus["keys"]["vendor"]
    apk = corpus["files"]["C-01"].read_bytes()
    entry, index = mini_fdroid(P, apk, V.sha256)
    fd = fdroid_handler(entry, index, apk)
    links = [
        {
            "relation": ["x"],
            "target": {"namespace": "android_app", "package_name": P, "sha256_cert_fingerprints": [colon_fp(V.sha256)]},
        }
    ]

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.host == "f-droid.org":
            return fd(req)
        if req.url.path == "/.well-known/assetlinks.json":
            return httpx.Response(200, json=links)
        if req.url.host == "digitalassetlinks.googleapis.com":
            return httpx.Response(404)
        return httpx.Response(200, content=apk)

    mock_http(fresh_rt, handler)
    a, _ = merge(
        None,
        methods.from_url(fresh_rt, P, "https://dl.vendor.example/app.apk", ["vendor.example"]),
        package=P,
        known_keys=fresh_rt.known_keys,
    )
    a, _ = merge(a, methods.from_assetlinks(fresh_rt, P, "vendor.example"), package=P, known_keys=fresh_rt.known_keys)
    a, _ = merge(a, methods.from_fdroid(fresh_rt, P), package=P, known_keys=fresh_rt.known_keys)
    assert a.corroboration == "CORROBORATED"
    fresh_rt.anchors.save(a)
    console = Console(quiet=True)
    assert refresh(fresh_rt, P, accept=True, console=console) is False
    mock_http(fresh_rt, lambda r: httpx.Response(500))
    assert refresh(fresh_rt, P, accept=False, console=console) is True  # a failing method is reported, not merged
    with pytest.raises(AnchorError):
        refresh(fresh_rt, "dev.not.anchored", accept=False, console=console)
