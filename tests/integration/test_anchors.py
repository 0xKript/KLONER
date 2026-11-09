"""Anchors (§7, P3): methods, merging, conflicts, corroboration, hygiene, store, lifecycle."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

import httpx
import pytest
from rich.console import Console

from kloner.anchor import corroborate, methods
from kloner.anchor.hygiene import HygieneError
from kloner.anchor.lifecycle import adopt_rotation, export_anchor, import_anchor, refresh
from kloner.anchor.methods import AnchorConflict, AnchorError, MethodResult, extract_fingerprints, merge, merge_lineage
from kloner.anchor.store import AnchorIntegrityError, AnchorStore, valid_package
from kloner.app import Runtime
from kloner.models import Evidence, Identity, LineageEntry
from kloner.util.fingerprints import colon_fp
from tests.integration.conftest import mock_http
from tests.integration.test_http_sources import fdroid_handler, mini_fdroid

pytestmark = pytest.mark.toolchain
P = "dev.kloner.fixture"


def vendor_server(apk: bytes, redirect_to: str | None = None) -> Any:
    def handler(req: httpx.Request) -> httpx.Response:
        if redirect_to and req.url.path == "/download":
            return httpx.Response(302, headers={"location": redirect_to})
        if req.url.path.endswith(".apk") or req.url.path == "/download":
            return httpx.Response(200, content=apk)
        return httpx.Response(404)

    return handler


def test_from_url_records_vendor_https_identities(fresh_rt: Runtime, corpus: dict[str, Any]) -> None:
    V = corpus["keys"]["vendor"]
    mock_http(fresh_rt, vendor_server(corpus["files"]["C-01"].read_bytes()))
    res = methods.from_url(fresh_rt, P, "https://dl.vendor.example/app.apk", ["vendor.example"])
    assert res.klass == "VENDOR_HTTPS" and [i.cert_sha256 for i in res.identities] == [V.sha256]
    assert res.release_refs[0].version_code == 1 and res.icons
    anchor, _notes = merge(None, res, package=P, known_keys=fresh_rt.known_keys)
    assert anchor.corroboration == "SINGLE_OFFICIAL" and anchor.brand.icon_asset_sha256
    saved = fresh_rt.anchors.save(anchor)
    assert fresh_rt.anchors.get(P) == saved and saved.record_sha256


def test_from_url_refuses_bad_provenance(fresh_rt: Runtime, corpus: dict[str, Any]) -> None:
    apk = corpus["files"]["C-01"].read_bytes()
    mock_http(fresh_rt, vendor_server(apk, redirect_to="https://cdn.other.example/app.apk"))
    with pytest.raises(AnchorError) as e:
        methods.from_url(fresh_rt, P, "https://dl.vendor.example/download", ["vendor.example"])
    assert e.value.exit_code == 3
    with pytest.raises(AnchorError):
        methods.from_url(fresh_rt, P, "http://dl.vendor.example/app.apk", ["vendor.example"])
    with pytest.raises(AnchorError):
        methods.from_url(fresh_rt, P, "https://dl.vendor.example/app.apk", [])
    mock_http(fresh_rt, vendor_server(corpus["files"]["C-21"].read_bytes()))
    with pytest.raises(AnchorError) as e:
        methods.from_url(fresh_rt, P, "https://dl.vendor.example/app.apk", ["vendor.example"])
    assert "dev.kloner.sibling" in str(e.value)


def test_fingerprints_and_corroboration(fresh_rt: Runtime, corpus: dict[str, Any]) -> None:
    V = corpus["keys"]["vendor"]
    page = f"<html><body><p>Signing certificate:</p><code>{colon_fp(V.sha256)}</code></body></html>".encode()

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/fingerprints":
            return httpx.Response(200, content=page)
        return httpx.Response(200, content=corpus["files"]["C-01"].read_bytes())

    mock_http(fresh_rt, handler)
    assert V.sha256 in extract_fingerprints(page)
    fp = colon_fp(V.sha256)
    split = f"<p>{fp[:47]}\n            {fp[48:]}</p>".encode()  # two groups over two lines
    assert V.sha256 in extract_fingerprints(split)
    pub = methods.from_fingerprints(fresh_rt, P, [V.sha256], "https://vendor.example/fingerprints")
    a1, _ = merge(None, pub, package=P, known_keys=fresh_rt.known_keys)
    assert a1.corroboration == "SINGLE_OFFICIAL"
    apk = methods.from_url(fresh_rt, P, "https://vendor.example/app.apk", ["vendor.example"])
    a2, _ = merge(a1, apk, package=P, known_keys=fresh_rt.known_keys)
    assert a2.corroboration == "CORROBORATED" and len(a2.identities) == 1
    assert {e.klass for e in a2.identities[0].evidence} == {"VENDOR_PUBLISHED", "VENDOR_HTTPS"}
    with pytest.raises(AnchorError):
        methods.from_fingerprints(fresh_rt, P, ["11" * 32], "https://vendor.example/fingerprints")
    user = methods.from_fingerprints(fresh_rt, P, [V.sha256], None)
    a3, _ = merge(None, user, package=P, known_keys=fresh_rt.known_keys)
    assert a3.corroboration == "USER_ASSERTED"
    with pytest.raises(AnchorError):
        methods.from_fingerprints(fresh_rt, P, ["xyz"], None)


def test_assetlinks(fresh_rt: Runtime, corpus: dict[str, Any]) -> None:
    V = corpus["keys"]["vendor"]
    statements = [
        {
            "relation": ["delegate_permission/common.handle_all_urls"],
            "target": {"namespace": "android_app", "package_name": P, "sha256_cert_fingerprints": [colon_fp(V.sha256)]},
        },
        {"relation": ["x"], "target": {"namespace": "web", "site": "https://vendor.example"}},
    ]
    api = {
        "statements": [
            {"target": {"androidApp": {"packageName": P, "certificate": {"sha256Fingerprint": colon_fp(V.sha256)}}}}
        ]
    }

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/.well-known/assetlinks.json":
            return httpx.Response(200, json=statements)
        if req.url.host == "digitalassetlinks.googleapis.com":
            return httpx.Response(200, json=api)
        return httpx.Response(404)

    mock_http(fresh_rt, handler)
    res = methods.from_assetlinks(fresh_rt, P, "vendor.example")
    assert [i.cert_sha256 for i in res.identities] == [V.sha256]
    assert "confirmed by the Google" in (res.identities[0].evidence[0].detail or "")
    with pytest.raises(AnchorError):
        methods.from_assetlinks(fresh_rt, "dev.other.app", "vendor.example")
    with pytest.raises(AnchorError):
        methods.from_assetlinks(fresh_rt, P, "https://vendor.example/")
    with pytest.raises(AnchorError):
        methods.parse_assetlinks({"not": "a list"}, P)


def test_fdroid_method(fresh_rt: Runtime, corpus: dict[str, Any]) -> None:
    apk = corpus["files"]["C-01"].read_bytes()
    entry, index = mini_fdroid(P, apk, corpus["keys"]["vendor"].sha256)
    mock_http(fresh_rt, fdroid_handler(entry, index, apk))
    res = methods.from_fdroid(fresh_rt, P)
    assert res.klass == "FDROID_INDEX"
    with pytest.raises(AnchorError):
        methods.from_fdroid(fresh_rt, "no.such.app")


def test_fdroid_signer_mismatch_is_refused(fresh_rt: Runtime, corpus: dict[str, Any]) -> None:
    apk = corpus["files"]["C-01"].read_bytes()
    entry, index = mini_fdroid(P, apk, "22" * 32)
    mock_http(fresh_rt, fdroid_handler(entry, index, apk))
    with pytest.raises(AnchorError) as e:
        methods.from_fdroid(fresh_rt, P)
    assert "does not match the F-Droid index signer" in str(e.value)


def test_conflicts_declared_identities_and_hygiene(fresh_rt: Runtime, corpus: dict[str, Any]) -> None:
    V, F, D = corpus["keys"]["vendor"], corpus["keys"]["foreign"], corpus["keys"]["debug"]
    base = methods.from_apk(fresh_rt, P, corpus["files"]["C-01"])
    a, notes = merge(None, base, package=P, known_keys=fresh_rt.known_keys)
    assert a.corroboration == "USER_ASSERTED" and any("USER" in n for n in notes)
    foreign = methods.from_apk(fresh_rt, P, corpus["files"]["C-02"])
    with pytest.raises(AnchorConflict) as e:
        merge(a, foreign, package=P, known_keys=fresh_rt.known_keys)
    assert e.value.exit_code == 3 and "Nothing was written" in str(e.value)
    with pytest.raises(AnchorError):
        merge(a, foreign, package=P, known_keys=fresh_rt.known_keys, declare_additional=True)
    b, _ = merge(
        a,
        foreign,
        package=P,
        known_keys=fresh_rt.known_keys,
        declare_additional=True,
        reason="store-specific signing key",
        label="store",
    )
    extra = b.identity(F.sha256)
    assert extra is not None and extra.declared_additional and extra.label == "store"
    assert b.decisions and b.decisions[0].action == "declare-additional-identity"
    assert corroborate.level(b) == "USER_ASSERTED"
    dbg = methods.from_apk(fresh_rt, P, corpus["files"]["C-03"])
    _, notes = merge(None, dbg, package=P, known_keys=fresh_rt.known_keys)
    assert any("debug" in n for n in notes)
    testkey = next(k for k, n in fresh_rt.known_keys.items() if n == "AOSP_TESTKEY")
    res = MethodResult(
        klass="USER",
        method="fingerprint",
        identities=[
            Identity(
                id="pending",
                cert_sha256=testkey,
                evidence=[Evidence(klass="USER", method="fingerprint", retrieved_utc="x")],
            )
        ],
    )
    with pytest.raises(HygieneError):
        merge(None, res, package=P, known_keys=fresh_rt.known_keys)
    _ = (V, D)


def test_lineage_merge_rules() -> None:
    a, b, c, x = ("a" * 64, "b" * 64, "c" * 64, "x" * 64)
    L = lambda *cs: [LineageEntry(cert_sha256=v) for v in cs]  # noqa: E731
    assert [e.cert_sha256 for e in merge_lineage(L(a, b), L(a, b, c))] == [a, b, c]
    assert [e.cert_sha256 for e in merge_lineage(L(a, b, c), L(b, c))] == [a, b, c]
    assert [e.cert_sha256 for e in merge_lineage(L(a, b), L(b, c))] == [a, b, c]
    assert [e.cert_sha256 for e in merge_lineage([], L(a))] == [a]
    with pytest.raises(AnchorConflict):
        merge_lineage(L(a, b), L(x, b, a))


def test_rotation_anchor_from_apk_and_adopt(fresh_rt: Runtime, corpus: dict[str, Any]) -> None:
    V, R = corpus["keys"]["vendor"], corpus["keys"]["rotated"]
    res = methods.from_apk(fresh_rt, P, corpus["files"]["C-16"])
    a, _ = merge(None, res, package=P, known_keys=fresh_rt.known_keys)
    assert [e.cert_sha256 for e in a.lineage] == [V.sha256, R.sha256]
    roles = {i.cert_sha256: i.role for i in a.identities}
    assert roles == {V.sha256: "legacy", R.sha256: "current"}
    only_v = merge(
        None, methods.from_apk(fresh_rt, P, corpus["files"]["C-01"]), package=P, known_keys=fresh_rt.known_keys
    )[0]
    fresh_rt.anchors.save(only_v)
    sha, _ = fresh_rt.quarantine.ingest_file(corpus["files"]["C-15"], 1 << 30)
    adopted = adopt_rotation(fresh_rt, P, sha)
    assert R.sha256 in adopted.trusted()
    with pytest.raises(AnchorError):
        adopt_rotation(fresh_rt, P, sha)  # already adopted: nothing to prove
    with pytest.raises(AnchorError):
        adopt_rotation(fresh_rt, P, "ab" * 32)


def test_store_integrity_export_import(fresh_rt: Runtime, corpus: dict[str, Any], tmp_path: Path) -> None:
    res = methods.from_apk(fresh_rt, P, corpus["files"]["C-01"])
    a, _ = merge(None, res, package=P, known_keys=fresh_rt.known_keys)
    store = fresh_rt.anchors
    store.save(a)
    out = tmp_path / "anchor.json"
    export_anchor(fresh_rt, P, out)
    assert json.loads(out.read_text())["package"] == P
    path = store.path(P)
    data = json.loads(path.read_text())
    data["identities"][0]["cert_sha256"] = "33" * 32
    path.write_text(json.dumps(data))
    with pytest.raises(AnchorIntegrityError):
        store.get(P)
    path.unlink()
    imported = import_anchor(fresh_rt, out)
    assert store.get(P) == imported
    other = json.loads(out.read_text())
    other["identities"][0]["cert_sha256"] = "44" * 32
    bad = tmp_path / "other.json"
    bad.write_text(json.dumps(other))
    with pytest.raises(AnchorError):
        import_anchor(fresh_rt, bad)
    assert valid_package("org.thoughtcrime.securesms") and not valid_package("../../etc") and not valid_package("a")
    with pytest.raises(ValueError):
        store.path("../evil")
    assert [x.package for x in AnchorStore(fresh_rt.home).list()] == [P]


def test_refresh_reports_changes(fresh_rt: Runtime, corpus: dict[str, Any]) -> None:
    V, R = corpus["keys"]["vendor"], corpus["keys"]["rotated"]
    pages = {"fp": f"<code>{colon_fp(V.sha256)}</code>"}

    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=pages["fp"].encode())

    mock_http(fresh_rt, handler)
    res = methods.from_fingerprints(fresh_rt, P, [V.sha256], "https://vendor.example/fp")
    a, _ = merge(None, res, package=P, known_keys=fresh_rt.known_keys)
    fresh_rt.anchors.save(a)
    console = Console(quiet=True)
    assert refresh(fresh_rt, P, accept=False, console=console) is False
    pages["fp"] = f"<code>{colon_fp(R.sha256)}</code>"
    assert refresh(fresh_rt, P, accept=False, console=console) is True  # published fingerprint disappeared
    assert fresh_rt.anchors.get(P) == a  # nothing written without --accept
    _ = shutil


def test_device_method_with_fake_adb(
    fresh_rt: Runtime, corpus: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    from kloner.util import proc

    tc = fresh_rt.toolchain()
    tc.adb = "adb-fake"
    real = proc.run
    apk = corpus["files"]["C-01"]

    def fake(argv: Any, **kw: Any) -> proc.ProcResult:
        args = [str(a) for a in argv]
        if args[0] != "adb-fake":
            return real(argv, **kw)
        if args[1:4] == ["shell", "pm", "path"]:
            out = b"package:/data/app/dev.kloner.fixture-1/base.apk\n"
        elif args[1:3] == ["shell", "dumpsys"]:
            out = b"Packages:\n  Package [dev.kloner.fixture]\n    installerPackageName=com.android.vending\n"
        elif args[1] == "pull":
            shutil.copyfile(apk, args[3])
            out = b"1 file pulled"
        else:
            out = b""
        return proc.ProcResult(tuple(args), 0, out, b"", False, 0.01)

    monkeypatch.setattr(proc, "run", fake)
    res = methods.from_device(fresh_rt, P, None)
    assert res.klass == "STORE_INSTALL" and res.identities
    assert methods.parse_installer("installerPackageName=null") is None
    assert methods.parse_pm_path("package:/a\npackage:/b\n") == ["/a", "/b"]
