"""Label paths of decide() (§6.2, §9 G7) on facts derived from the real C-01/C-14/C-16 facts."""

from __future__ import annotations

from typing import Any

import pytest

from kloner.decide import decide
from kloner.models import (
    EvaluationFacts,
    Issue,
    LineageEntry,
    ManifestFacts,
    ReleaseRef,
    SourceStampInfo,
    Verdict,
)
from kloner.selftest import corpus as c

pytestmark = pytest.mark.toolchain
P = c.FIXTURE_PACKAGE


def _anchor(corpus: dict[str, Any], **kw: Any) -> Any:
    a = corpus["anchors"]["v"].model_copy(deep=True)
    for k, v in kw.items():
        setattr(a, k, v)
    return a


def test_version_labels(facts01: EvaluationFacts, corpus: dict[str, Any]) -> None:
    ref = lambda vc: ReleaseRef(version_code=vc, file_sha256=f"{vc:064x}", provenance="VENDOR_HTTPS", observed_utc="x")  # noqa: E731
    ev = decide(facts01, {P: _anchor(corpus, release_refs=[ref(0)])}, {})
    assert ev.verdict == Verdict.GENUINE and ev.has_label("AHEAD_OF_OFFICIAL")
    ev = decide(facts01, {P: _anchor(corpus, release_refs=[ref(5)])}, {})
    assert ev.has_label("OUTDATED") and ev.labels[0].evidence["gap"] == 4
    user_ref = ReleaseRef(version_code=9, file_sha256="1" * 64, provenance="USER", observed_utc="x")
    assert not decide(facts01, {P: _anchor(corpus, release_refs=[user_ref])}, {}).has_label("OUTDATED")


def test_legacy_key_on_new_build(corpus: dict[str, Any], rt: Any) -> None:
    V, R = corpus["keys"]["vendor"], corpus["keys"]["rotated"]
    sha, _ = rt.quarantine.ingest_file(corpus["files"]["C-14"], 1 << 30)
    facts, _ = rt.pipeline().facts(sha, P)
    a = c.anchor_for([V, R], lineage=[V, R])
    a.release_refs = [
        ReleaseRef(
            version_code=1, file_sha256="2" * 64, signers=[R.sha256], provenance="VENDOR_HTTPS", observed_utc="x"
        )
    ]
    ev = decide(facts, {P: a}, {})
    assert ev.verdict == Verdict.GENUINE and ev.has_label("LEGACY_KEY") and ev.has_label("LEGACY_KEY_ON_NEW_BUILD")


def test_source_stamp_and_warnings(facts01: EvaluationFacts, corpus: dict[str, Any]) -> None:
    f = facts01.model_copy(deep=True)
    assert f.verify and f.verify.full_range
    f.verify.full_range.source_stamp = SourceStampInfo(present=True, status="STAMP_VERIFIED", cert_sha256="5" * 64)
    f.verify.full_range.warnings = [Issue(issue="JAR_SIG_UNPROTECTED_ZIP_ENTRY", message="w")]
    ev = decide(f, {P: corpus["anchors"]["v"]}, {})
    assert ev.has_label("PLAY_SOURCE_STAMP") and ev.has_label("VERIFIER_WARNING:JAR_SIG_UNPROTECTED_ZIP_ENTRY")
    f.verify.full_range.source_stamp = SourceStampInfo(present=True, status="CERT_DIGEST_MISMATCH")
    assert decide(f, {P: corpus["anchors"]["v"]}, {}).has_label("SOURCE_STAMP_INVALID")


def test_secondary_identity_and_unreadable_manifest(facts01: EvaluationFacts, corpus: dict[str, Any]) -> None:
    a = _anchor(corpus)
    a.identities[0].declared_additional = True
    a.identities[0].label = "store key"
    assert decide(facts01, {P: a}, {}).has_label("SECONDARY_IDENTITY")
    f = facts01.model_copy(deep=True)
    f.manifest = ManifestFacts(unreadable=True, unreadable_detail="aapt2: failed")
    ev = decide(f, {P: corpus["anchors"]["v"]}, {})
    assert ev.verdict == Verdict.ANOMALY and ev.reasons == ["R-G3-MANIFEST-UNREADABLE"]
    g = facts01.model_copy(deep=True)
    g.structure = None
    assert decide(g, {P: corpus["anchors"]["v"]}, {}).verdict == Verdict.ERROR
    h = facts01.model_copy(deep=True)
    h.verify = None
    assert decide(h, {P: corpus["anchors"]["v"]}, {}).verdict == Verdict.ERROR


def test_rotated_lineage_genuine_with_anchor_lineage(corpus: dict[str, Any], rt: Any) -> None:
    V, R = corpus["keys"]["vendor"], corpus["keys"]["rotated"]
    sha, _ = rt.quarantine.ingest_file(corpus["files"]["C-16"], 1 << 30)
    facts, _ = rt.pipeline().facts(sha, P)
    a = c.anchor_for([R])
    a.lineage = [LineageEntry(cert_sha256=V.sha256), LineageEntry(cert_sha256=R.sha256)]
    ev = decide(facts, {P: a}, {})
    assert ev.verdict == Verdict.GENUINE and ev.has_label("ROTATED_KEY") and ev.has_label("LEGACY_KEY")
    assert {s.cert_sha256: s.trust for s in ev.signers} == {V.sha256: "R1", R.sha256: "T"}


def test_impersonator_requires_presentation_evidence(corpus: dict[str, Any], rt: Any) -> None:
    sha, _ = rt.quarantine.ingest_file(corpus["files"]["C-33"], 1 << 30)
    facts, _ = rt.pipeline().facts(sha, None)
    plain = c.anchor_for([corpus["keys"]["vendor"]])
    assert decide(facts, {P: plain}, {}).verdict == Verdict.UNANCHORED
    labelled = c.anchor_for([corpus["keys"]["vendor"]], brand_labels=["kloner FIXTURE"])
    ev = decide(facts, {P: labelled}, {})
    assert ev.verdict == Verdict.IMPERSONATOR and ev.has_label("EXACT_LABEL") and ev.brand_package == P
