"""Hunt against a mocked Aptoide-format API serving corpus files (P4): coverage, metadata cross-check,
re-fetch on corrupt downloads (UNSTABLE_SOURCE), impersonation sweep, survey, fetch, reverify."""

from __future__ import annotations

import hashlib
from typing import Any

import httpx
import pytest

from kloner.anchor import methods
from kloner.app import Runtime
from kloner.hunt import explain, reverify, run_fetch, run_hunt, run_survey
from kloner.models import Verdict
from kloner.report import write_reports
from kloner.report.jsonout import build
from kloner.selftest import corpus as c
from kloner.util.hashing import cert_digests
from tests.integration.conftest import mock_http

pytestmark = pytest.mark.toolchain
P = c.FIXTURE_PACKAGE


def item(
    app_id: int,
    store: str,
    path: str,
    data: bytes,
    vercode: int,
    package: str = P,
    name: str = "Kloner Fixture",
    md5: str | None = None,
    signer_der: bytes | None = None,
) -> dict[str, Any]:
    sig = {}
    if signer_der is not None:
        sha1 = cert_digests(signer_der)["sha1"]
        sig = {
            "sha1": ":".join(sha1[i : i + 2] for i in range(0, 40, 2)).upper(),
            "owner": "CN=Kloner Synthetic vendor",
        }
    return {
        "id": app_id,
        "name": name,
        "package": package,
        "store": {"id": 1, "name": store},
        "file": {
            "vername": "1.0",
            "vercode": vercode,
            "md5sum": md5 or hashlib.md5(data).hexdigest(),
            "path": f"https://pool.example/{path}",
            "signature": sig,
        },
    }


@pytest.fixture
def server(fresh_rt: Runtime, corpus: dict[str, Any]) -> dict[str, Any]:
    f = corpus["files"]
    V = corpus["keys"]["vendor"]
    c01, c02, c15, c33 = (f[k].read_bytes() for k in ("C-01", "C-02", "C-15", "C-33"))
    items = {
        1: item(1, "appupdater", "a1.apk", c01, 1, signer_der=V.der),
        2: item(2, "modzone", "a2.apk", c02, 1, md5="0" * 32, signer_der=V.der),
        3: item(3, "mirrorz", "a3.apk", c01, 1),
    }
    lite = item(9, "freeapps", "lite.apk", c33, 1, package="dev.kloner.fixture.lite")
    served = {"a3": 0}

    def handler(req: httpx.Request) -> httpx.Response:
        path, q = req.url.path, dict(req.url.params)
        if req.url.host == "ws75.aptoide.com":
            if path.endswith("/app/getMeta"):
                if "app_id" in q:
                    return httpx.Response(200, json={"info": {"status": "OK"}, "data": items[int(q["app_id"])]})
                return httpx.Response(200, json={"info": {"status": "OK"}, "data": items[1]})
            if path.endswith("/listAppVersions"):
                return httpx.Response(200, json={"info": {"status": "OK"}, "list": [{"id": i} for i in items]})
            if path.endswith("/apps/search"):
                return httpx.Response(
                    200, json={"info": {"status": "OK"}, "datalist": {"total": 1, "count": 1, "list": [lite]}}
                )
        if req.url.host == "pool.example":
            name = path.rsplit("/", 1)[-1]
            if name == "a3.apk":
                served["a3"] += 1
                return httpx.Response(200, content=c01[: len(c01) // 2] if served["a3"] == 1 else c15)
            body = {"a1.apk": c01, "a2.apk": c02, "lite.apk": c33}[name]
            return httpx.Response(200, content=body)
        return httpx.Response(404)

    mock_http(fresh_rt, handler)
    res = methods.from_apk(fresh_rt, P, f["C-01"])
    anchor, _ = methods.merge(None, res, package=P, known_keys=fresh_rt.known_keys, brand_labels=["Kloner Fixture"])
    fresh_rt.anchors.save(anchor)
    return {"items": items}


def test_hunt_with_mocked_aptoide(fresh_rt: Runtime, server: dict[str, Any], tmp_path: Any) -> None:
    rep = run_hunt(fresh_rt, P, sources=["aptoide"], all_versions=True, max_per_source=5, impersonators=True)
    assert rep.exit_code == 10
    st = rep.sources[0]
    assert st.source == "aptoide" and st.status == "OK" and st.offers == 3
    assert set(st.stores) == {"appupdater", "modzone", "mirrorz"}
    verdicts = {e.evaluation.sample_sha256: e for e in rep.samples}
    by_verdict: dict[Verdict, list[Any]] = {}
    for e in verdicts.values():
        by_verdict.setdefault(e.evaluation.verdict, []).append(e)
    assert len(by_verdict[Verdict.FORGED]) == 1
    forged = by_verdict[Verdict.FORGED][0]
    assert "METADATA_MISMATCH" in forged.sightings[0].labels
    assert any("UNSTABLE_SOURCE" in s.labels for e in rep.samples for s in e.sightings)
    assert Verdict.INVALID in by_verdict and len(by_verdict[Verdict.GENUINE]) == 2
    imp = by_verdict[Verdict.IMPERSONATOR][0]
    assert imp.candidate and imp.evaluation.has_label("EXACT_LABEL")
    assert any(x["signal"] == "PACKAGE_AFFIX" for x in imp.lookalikes)
    assert "aptoide OK (3 stores)" in rep.coverage
    doc = build(rep)
    assert doc["summary"]["counts"]["FORGED"] == 1 and doc["coverage"]["sightings"] >= 4
    paths = write_reports(doc, tmp_path, ["json", "md", "html", "csv", "iocs", "stix21"])
    assert all(p.is_file() for p in paths)
    ok, diffs, n = reverify(fresh_rt, rep.run_id)
    assert ok, diffs
    assert n >= 4
    info = explain(fresh_rt, forged.evaluation.sample_sha256, rep.run_id)
    assert info["evaluation"]["verdict"] == "FORGED" and info["sightings"]


def test_survey_and_fetch(fresh_rt: Runtime, server: dict[str, Any], corpus: dict[str, Any]) -> None:
    rows, statuses, n = run_survey(fresh_rt, P, ["aptoide", "huawei"], 5)
    assert n >= 2 and statuses[0].status == "OK" and statuses[1].status == "DISABLED"
    certs = {r.cert_sha256 for r in rows}
    assert corpus["keys"]["vendor"].sha256 in certs and corpus["keys"]["foreign"].sha256 in certs
    assert fresh_rt.anchors.get("dev.kloner.fixture.lite") is None  # a survey never writes an anchor
    rep = run_fetch(fresh_rt, ["https://pool.example/a2.apk"], P)
    assert rep.samples[0].evaluation.verdict == Verdict.FORGED and rep.exit_code == 10
