from __future__ import annotations

from typing import Any

import pytest

from kloner.decide import (
    MemberResult,
    OtherMember,
    SignerBlock,
    app_signers,
    closure,
    decide,
    decide_bundle,
    vendor_signed,
    verified_blocks,
)
from kloner.models import (
    ArchiveFacts,
    Evaluation,
    EvaluationFacts,
    IntakeFacts,
    SignerTrust,
    Verdict,
)
from kloner.selftest import corpus as c
from kloner.selftest.runner import facts_cases


def test_closure_rules() -> None:
    a, b, x, z = "a" * 64, "b" * 64, "x" * 64, "z" * 64
    # R1: a trusted signer endorses its whole lineage
    assert closure({b}, [SignerBlock(b, (a, b), (False, True))]) == {b: "T", a: "R1"}
    # R2: a node signed by a trusted predecessor is admitted
    assert closure({a}, [SignerBlock(b, (a, b), (False, True))]) == {a: "T", b: "R2"}
    # R2 requires the node signature to verify
    assert closure({a}, [SignerBlock(b, (a, b), (False, False))]) == {a: "T"}
    # ancestry asserted by an untrusted block proves nothing
    assert closure({b}, [SignerBlock(x, (b, x), (False, False))]) == {b: "T"}
    assert closure({z}, [SignerBlock(x, (a, x), (False, True))]) == {z: "T"}
    # transitive: a -> b -> x
    assert closure({a}, [SignerBlock(x, (a, b, x), (False, True, True))]) == {a: "T", b: "R2", x: "R2"}
    assert closure({a}, []) == {a: "T"}


@pytest.mark.toolchain
def test_facts_level_cases(corpus: dict[str, Any], rt: Any) -> None:
    for case, facts in facts_cases(corpus, rt.known_keys):
        ev = decide(facts, case.anchors, rt.known_keys)
        if case.expected is not None:
            assert ev.verdict == case.expected, (case.id, ev.verdict, ev.reasons)
        if case.one_of:
            assert ev.verdict in case.one_of, case.id
        assert ev.verdict not in case.never, case.id
        for lab in case.labels:
            assert ev.has_label(lab), (case.id, lab, ev.label_codes())
        assert decide(facts, case.anchors, rt.known_keys) == ev  # deterministic


@pytest.mark.toolchain
def test_genuine_explanation_and_trace(facts01: EvaluationFacts, corpus: dict[str, Any]) -> None:
    a = corpus["anchors"]["v"]
    ev = decide(facts01, {c.FIXTURE_PACKAGE: a}, {})
    assert ev.verdict == Verdict.GENUINE
    assert ev.explanation.startswith("Signed by the official identity")
    assert [g.gate for g in ev.gate_trace] == ["G0", "G2", "G3", "G4", "G5", "G6", "G7"]
    assert ev.reasons[-1] == "R-G7-TRUSTED"
    assert ev.anchor_record_sha256 == a.record_sha256
    rng = facts01.verify.full_range
    assert verified_blocks(rng, facts01.native_inventory)
    assert set(app_signers(rng, facts01.native_inventory)) == {corpus["keys"]["vendor"].sha256}
    assert vendor_signed(facts01, a)


@pytest.mark.toolchain
def test_unanchored_mismatch_and_collection_error(facts01: EvaluationFacts) -> None:
    ev = decide(facts01, {}, {})
    assert ev.verdict == Verdict.UNANCHORED and "kloner anchor add" in ev.explanation
    f = facts01.model_copy(deep=True)
    f.expected_package = "dev.kloner.other"
    assert decide(f, {}, {}).verdict == Verdict.MISMATCH
    err = EvaluationFacts(sample_sha256="0" * 64, size=1, collection_error="worker timed out")
    assert decide(err, {}, {}).verdict == Verdict.ERROR
    inv = EvaluationFacts(sample_sha256="0" * 64, size=1, intake=IntakeFacts(failed=True, reason="NOT_ZIP"))
    assert decide(inv, {}, {}).reasons == ["R-G0-NOT-ZIP"]
    bad = EvaluationFacts(
        sample_sha256="0" * 64,
        size=1,
        intake=IntakeFacts(format="apk"),
        archive=ArchiveFacts(failed=True, reason="CORRUPT", detail="crc"),
    )
    assert decide(bad, {}, {}).verdict == Verdict.INVALID


@pytest.mark.toolchain
def test_engine_failure_is_error(facts01: EvaluationFacts, corpus: dict[str, Any]) -> None:
    f = facts01.model_copy(deep=True)
    assert f.verify is not None
    f.verify.engine_failure = True
    f.verify.engine_detail = "bridge timed out"
    assert decide(f, {c.FIXTURE_PACKAGE: corpus["anchors"]["v"]}, {}).verdict == Verdict.ERROR


def _ev(
    sha: str,
    verdict: Verdict,
    package: str = c.FIXTURE_PACKAGE,
    split: str | None = None,
    signers: tuple[str, ...] = ("v" * 64,),
) -> Evaluation:
    return Evaluation(
        sample_sha256=sha,
        size=1,
        format="apk",
        package=package,
        split=split,
        verdict=verdict,
        signers=[SignerTrust(cert_sha256=s, trust="T") for s in signers],
    )


def _bundle(apks: list[MemberResult], others: list[OtherMember] | None = None) -> Evaluation:
    facts = EvaluationFacts(sample_sha256="b" * 64, size=10, intake=IntakeFacts(format="bundle", bundle_kind="xapk"))
    return decide_bundle(facts, c.FIXTURE_PACKAGE, apks, others or [], {})


def test_bundle_rules() -> None:
    base = MemberResult("base.apk", _ev("1" * 64, Verdict.GENUINE))
    split = MemberResult("config.en.apk", _ev("2" * 64, Verdict.GENUINE, split="config.en"))
    assert _bundle([base, split]).verdict == Verdict.GENUINE
    forged = MemberResult("config.en.apk", _ev("3" * 64, Verdict.FORGED, split="config.en"))
    ev = _bundle([base, forged])
    assert ev.verdict == Verdict.FORGED and ev.has_label("BUNDLE_INCONSISTENT")
    tampered = MemberResult("config.en.apk", _ev("4" * 64, Verdict.TAMPERED, split="config.en"))
    assert _bundle([base, forged, tampered]).verdict == Verdict.TAMPERED
    anomaly = MemberResult("config.en.apk", _ev("5" * 64, Verdict.ANOMALY, split="config.en"))
    assert _bundle([base, anomaly]).verdict == Verdict.ANOMALY
    other_signer = MemberResult("config.en.apk", _ev("6" * 64, Verdict.GENUINE, split="config.en", signers=("w" * 64,)))
    ev = _bundle([base, other_signer])
    assert ev.verdict == Verdict.ANOMALY and ev.has_label("SPLIT_SIGNER_DIVERGENCE")
    foreign = MemberResult("update.apk", _ev("7" * 64, Verdict.UNANCHORED, package="com.other.app"))
    ev = _bundle([base, split, foreign])
    assert ev.verdict == Verdict.ANOMALY and ev.has_label("UNEXPECTED_MEMBER")
    ev = _bundle([split])
    assert ev.verdict == Verdict.INVALID and ev.has_label("INCOMPLETE_BUNDLE")
    ev = _bundle(
        [base, split],
        [
            OtherMember("payload.dex", "8" * 64, 10, "payload", "dex"),
            OtherMember("Android/obb/x.obb", "9" * 64, 10, "obb"),
        ],
    )
    assert ev.verdict == Verdict.GENUINE and ev.has_label("UNEXPECTED_PAYLOAD") and ev.has_label("UNVERIFIABLE_OBB")
    assert {m.role for m in ev.members} == {"base", "split", "payload", "obb"}
