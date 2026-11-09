"""``kloner selftest``: rebuild the corpus on this machine and check every expected verdict (§18).

Modes: quick (core verdict paths), standard (every case, P-01/P-02 with N=50), full (N=1000 for
P-01, N=200 for P-02, engine agreement on every file).
"""

from __future__ import annotations

import hashlib
import json
import secrets
import shutil
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from kloner.anchor import methods as anchor_methods
from kloner.anchor.hygiene import HygieneError
from kloner.anchor.methods import AnchorConflict, MethodResult
from kloner.app import Runtime
from kloner.decide import decide
from kloner.forensics.metadata import cross_check
from kloner.intel.db import verdict_json
from kloner.models import Claimed, EvaluationFacts, Evidence, Identity, Issue, Verdict
from kloner.selftest import corpus as c
from kloner.verify.sigblock import locate

_rng = secrets.SystemRandom()


@dataclass
class Outcome:
    case: str
    title: str
    ok: bool
    got: str
    want: str
    detail: str = ""
    seconds: float = 0.0
    # "file": a real file through the whole pipeline; "facts": decide() on real C-01 facts changed
    # only in the data it sees (D-026); "anchor": the anchor merge/hygiene code on evidence records.
    level: str = "file"


def _check(case: c.Case, verdict: Verdict, labels: list[str]) -> tuple[bool, str]:
    if case.expected is not None and verdict != case.expected:
        return False, f"verdict {verdict.value} != {case.expected.value}"
    if case.one_of and verdict not in case.one_of:
        return False, f"verdict {verdict.value} not in {[v.value for v in case.one_of]}"
    if verdict in case.never:
        return False, f"verdict {verdict.value} is forbidden"
    for lab in case.labels:
        if not any(x == lab or x.startswith(lab + ":") or (lab.endswith(":") and x.startswith(lab)) for x in labels):
            return False, f"missing label {lab}"
    return True, ""


def build(rt: Runtime, work: Path, console: Console) -> tuple[list[c.Case], dict[str, Any]]:
    tc = rt.toolchain()
    sg = c.Signer(tc)
    keys = {
        "vendor": c.make_key("vendor", work),
        "rotated": c.make_key("rotated", work, kind="ec"),
        "foreign": c.make_key("foreign", work, kind="rsa4096"),
        "debug": c.make_key("debug", work, debug=True),
    }
    V, R, F, D = keys["vendor"], keys["rotated"], keys["foreign"], keys["debug"]
    fx = {
        n: c.fixture_path(n) for n in ("modern", "legacy", "split_xxhdpi", "split_en", "sibling", "lite", "modern_v2")
    }
    f: dict[str, Path] = {}
    f["C-01"] = sg.sign(fx["modern"], work / "c01.apk", V)
    f["C-02"] = sg.sign(fx["modern"], work / "c02.apk", F)
    f["C-03"] = sg.sign(fx["modern"], work / "c03.apk", D)
    data = f["C-01"].read_bytes()
    (work / "c07.apk").write_bytes(data[: len(data) // 2])
    f["C-07"] = work / "c07.apk"
    f["C-06"] = c.corrupt_deflated(f["C-01"], work / "c06.apk")
    lineage = sg.rotate(V, R, work / "lineage-vr.bin")
    f["C-14"] = sg.sign(fx["modern"], work / "c14.apk", V)
    f["C-15"] = sg.sign(fx["modern"], work / "c15.apk", V, next_key=R, lineage=lineage, rotation_min_sdk=28)
    f["C-16"] = sg.sign(fx["modern"], work / "c16.apk", V, next_key=R, lineage=lineage)
    f["C-21"] = sg.sign(fx["sibling"], work / "c21.apk", V)
    (work / "c22.apk").write_text("<!doctype html><title>Download</title><p>Your APK is ready.</p>", encoding="utf-8")
    f["C-22"] = work / "c22.apk"
    import zipfile

    with zipfile.ZipFile(fx["modern"]) as z:
        manifest = z.read("AndroidManifest.xml")
    f["C-23"] = c.write_aab_shaped(work / "c23.aab", manifest)
    base = f["C-01"]
    sx = sg.sign(fx["split_xxhdpi"], work / "split_xxhdpi.apk", V)
    se = sg.sign(fx["split_en"], work / "split_en.apk", V)
    se_f = sg.sign(fx["split_en"], work / "split_en_foreign.apk", F)
    sib_f = sg.sign(fx["sibling"], work / "sibling_foreign.apk", F)
    f["C-24"] = c.write_xapk(work / "c24.xapk", {"base.apk": base, "config.xxhdpi.apk": sx, "config.en.apk": se})
    f["C-25"] = c.write_xapk(work / "c25.xapk", {"base.apk": base, "config.xxhdpi.apk": sx, "config.en.apk": se_f})
    f["C-26"] = c.write_xapk(work / "c26.xapk", {"base.apk": base, "config.en.apk": se, "update.apk": sib_f})
    f["C-33"] = sg.sign(fx["lite"], work / "c33.apk", F)
    f["C-34"] = sg.sign(fx["lite"], work / "c34.apk", V)
    f["X-01"] = sg.sign(fx["legacy"], work / "x01.apk", V, v2=False, v3=False)
    f["X-02"] = sg.sign(fx["modern_v2"], work / "x02.apk", V)

    # Brand icons of the vendor app, from the facts of C-01.
    pipe = rt.pipeline()
    sha01, _ = rt.quarantine.ingest_file(f["C-01"], 1 << 30)
    facts01, _ = pipe.facts(sha01, c.FIXTURE_PACKAGE)
    icons = facts01.brand.icon_hashes if facts01.brand else []

    a_v = c.anchor_for([V], brand_icons=icons)
    a_vr = c.anchor_for([V, R], lineage=[V, R], brand_icons=icons)
    a_r = c.anchor_for([R], brand_icons=icons)
    P = c.FIXTURE_PACKAGE

    def A(a: Any) -> dict[str, Any]:  # noqa: N802 - mirrors the spec's anchor notation
        return {P: a}

    cases = [
        c.Case("C-01", "Vendor-signed modern fixture (v1+v2+v3)", Verdict.GENUINE, file=f["C-01"], anchors=A(a_v)),
        c.Case("C-02", "Signed with a fresh RSA-4096 key", Verdict.FORGED, file=f["C-02"], anchors=A(a_v)),
        c.Case(
            "C-03", "Signed with a debug-DN certificate", Verdict.FORGED, ("DEBUG_DN",), file=f["C-03"], anchors=A(a_v)
        ),
        c.Case("C-06", "DEFLATED entry bytes corrupted (CRC broken)", Verdict.INVALID, file=f["C-06"], anchors=A(a_v)),
        c.Case("C-07", "Truncated file", Verdict.INVALID, file=f["C-07"], anchors=A(a_v)),
        c.Case(
            "C-14",
            "Lineage A→B; signed by A only; anchor {A,B}",
            Verdict.GENUINE,
            ("LEGACY_KEY",),
            file=f["C-14"],
            anchors=A(a_vr),
        ),
        c.Case(
            "C-15",
            "Signed by B with lineage A→B; anchor {A} (R2)",
            Verdict.GENUINE,
            ("ROTATED_KEY",),
            file=f["C-15"],
            anchors=A(a_v),
        ),
        c.Case(
            "C-16",
            "v3.1 rotation: A in v2/v3, B in v3.1; anchor {B} (R1)",
            Verdict.GENUINE,
            ("ROTATED_KEY",),
            file=f["C-16"],
            anchors=A(a_r),
        ),
        c.Case(
            "C-21",
            "Different package signed by the vendor",
            Verdict.MISMATCH,
            ("SAME_VENDOR",),
            file=f["C-21"],
            anchors=A(a_v),
        ),
        c.Case("C-22", "HTML page saved as .apk", Verdict.INVALID, file=f["C-22"], anchors=A(a_v)),
        c.Case("C-23", "AAB", Verdict.INVALID, file=f["C-23"], anchors=A(a_v)),
        c.Case("C-24", "XAPK, base + splits all vendor-signed", Verdict.GENUINE, file=f["C-24"], anchors=A(a_v)),
        c.Case(
            "C-25",
            "XAPK with one split re-signed",
            Verdict.FORGED,
            ("BUNDLE_INCONSISTENT",),
            file=f["C-25"],
            anchors=A(a_v),
        ),
        c.Case(
            "C-26",
            "XAPK with an extra APK of another package",
            Verdict.ANOMALY,
            ("UNEXPECTED_MEMBER",),
            file=f["C-26"],
            anchors=A(a_v),
        ),
        c.Case(
            "C-33",
            "Other package, byte-identical icon, foreign signer",
            Verdict.IMPERSONATOR,
            ("EXACT_ICON",),
            file=f["C-33"],
            anchors=A(a_v),
        ),
        c.Case(
            "C-34",
            "Other package with the same icon, signed by the vendor",
            Verdict.MISMATCH,
            ("SAME_VENDOR",),
            file=f["C-34"],
            anchors=A(a_v),
        ),
        c.Case(
            "X-01",
            "Legacy fixture, v1-only, vendor-signed",
            Verdict.GENUINE,
            ("V1_ONLY",),
            file=f["X-01"],
            anchors=A(a_v),
        ),
        c.Case("X-02", "Newer vendor build (versionCode 2)", Verdict.GENUINE, file=f["X-02"], anchors=A(a_v)),
    ]
    reasons_by_case = {
        "C-06": "R-G2-CORRUPT",
        "C-07": "R-G2-CORRUPT",
        "C-22": "R-G0-NOT-ZIP",
        "C-23": "R-G0-AAB-NOT-DISTRIBUTABLE",
    }
    ctx = {
        "keys": keys,
        "files": f,
        "facts01": facts01,
        "anchors": {"v": a_v, "vr": a_vr, "r": a_r},
        "reasons": reasons_by_case,
        "icons": icons,
    }
    return cases, ctx


def facts_cases(ctx: dict[str, Any], known_keys: dict[str, str]) -> list[tuple[c.Case, EvaluationFacts]]:
    """Facts-level cases: real C-01 facts, changed only in the data decide() sees."""
    f01: EvaluationFacts = ctx["facts01"]
    V, F = ctx["keys"]["vendor"], ctx["keys"]["foreign"]
    a_v = ctx["anchors"]["v"]
    P = c.FIXTURE_PACKAGE
    testkey = next(k for k, n in known_keys.items() if n == "AOSP_TESTKEY")
    out: list[tuple[c.Case, EvaluationFacts]] = []

    def add(case: c.Case, facts: EvaluationFacts) -> None:
        case.level = "facts"
        case.anchors = case.anchors or {P: a_v}
        out.append((case, facts))

    add(
        c.Case(
            "C-04", "Signer is the AOSP testkey (from the registry)", Verdict.FORGED, ("KNOWN_PUBLIC_KEY:AOSP_TESTKEY",)
        ),
        c.replace_cert(
            f01, V.sha256, testkey, subject="CN=Android,OU=Android,O=Android,L=Mountain View,ST=California,C=US"
        ),
    )
    add(
        c.Case(
            "C-05",
            "STORED entry modified, CRCs recomputed",
            Verdict.TAMPERED,
            ("CONTENT_MODIFIED_UNDER_OFFICIAL_SIGNATURE",),
        ),
        c.with_unverified(f01, "V2_SIG_APK_DIGEST_DID_NOT_VERIFY", "V3_SIG_APK_DIGEST_DID_NOT_VERIFY"),
    )
    f08 = c.with_unverified(f01, "JAR_SIG_ZIP_ENTRY_DIGEST_DID_NOT_VERIFY", "V2_SIG_APK_DIGEST_DID_NOT_VERIFY")
    add(
        c.Case(
            "C-08",
            "Signature transplant (naive cert read still shows the vendor)",
            Verdict.TAMPERED,
            ("CONTENT_MODIFIED_UNDER_OFFICIAL_SIGNATURE",),
            note="the androguard inventory reports the vendor certificate"
            if f08.androguard_inventory and V.sha256 in f08.androguard_inventory.all()
            else "androguard did not report the vendor cert",
        ),
        f08,
    )
    add(
        c.Case("C-09", "DEX prepended before the ZIP (v1-only)", Verdict.TAMPERED, ("POLYGLOT",)),
        c.with_violation(f01, "S1", "POLYGLOT", "DATA-BEFORE-FIRST-ENTRY", "first local header at offset 112"),
    )
    add(
        c.Case("C-10", "Duplicate entry name", Verdict.TAMPERED, ("ZIP_AMBIGUITY",)),
        c.with_violation(
            f01, "S2", "ZIP_AMBIGUITY", "DUPLICATE-ENTRY", "entry name 'classes.dex' appears more than once"
        ),
    )
    add(
        c.Case("C-11", "Local/central filename mismatch", Verdict.TAMPERED, ("ZIP_AMBIGUITY",)),
        c.with_violation(
            f01, "S3", "ZIP_AMBIGUITY", "LOCAL-CENTRAL-NAME-MISMATCH", "central 'classes.dex' -> local 'classex.dex'"
        ),
    )
    add(
        c.Case("C-12", "v2/v3 stripped, targetSdk >= 30", Verdict.TAMPERED, ("SCHEME_STRIPPED",)),
        c.with_unverified(f01, "MIN_SIG_SCHEME_FOR_TARGET_SDK_NOT_MET", "JAR_SIG_MISSING_APK_SIG_REFERENCED"),
    )
    f13 = c.replace_cert(f01, V.sha256, F.sha256)
    assert f13.verify and f13.verify.full_range
    for s in f13.verify.full_range.signers:  # v2 signed by the attacker, v3 still by the vendor
        if s.scheme == "v3":
            s.cert_sha256 = V.sha256
    nat = f13.native_inventory
    assert nat is not None
    for pair in nat.pairs:
        if pair.name == "v3":
            for ns in pair.signers:
                ns.signer_cert, ns.cert_chain = V.sha256, [V.sha256]
    nat.v1 = []
    if f13.androguard_inventory:
        f13.androguard_inventory.v1 = []
        f13.androguard_inventory.v3 = [V.sha256]
    nat.certs[V.sha256] = f01.native_inventory.certs[V.sha256] if f01.native_inventory else nat.certs[F.sha256]
    add(
        c.Case(
            "C-13",
            "Attacker v2 block grafted, content unchanged",
            None,
            ("MIXED_SIGNERS",),
            one_of=(Verdict.FORGED, Verdict.TAMPERED),
            never=(Verdict.GENUINE,),
        ),
        f13,
    )
    f17 = c.with_unverified(f01, "V3_SIG_POR_DID_NOT_VERIFY")
    add(c.Case("C-17", "Lineage A→C with an invalid node signature", Verdict.TAMPERED), f17)
    f18 = c.replace_cert(f01, V.sha256, F.sha256)
    add(
        c.Case(
            "C-18",
            "v2/v3 replaced by attacker blocks over the same content",
            None,
            (),
            one_of=(Verdict.FORGED, Verdict.TAMPERED),
            never=(Verdict.GENUINE,),
        ),
        f18,
    )
    add(
        c.Case("C-19", "Unsigned channel-style pair in the signing block", Verdict.GENUINE, ("UNSIGNED_BLOCK_DATA",)),
        c.with_extra_pair(f01, c.unsigned_pair()),
    )
    f20 = c.with_extra_pair(f01, c.sniffed_pair(F.sha256))
    add(c.Case("C-20", "Attacker v2 block copied under an unknown ID", Verdict.FORGED, ("UNKNOWN_SIGNER_BLOCK",)), f20)
    f27 = f01.model_copy(deep=True)
    assert f27.archive is not None
    f27.archive.failed, f27.archive.reason, f27.archive.detail = (
        True,
        "UNSAFE_ARCHIVE",
        "compression ratio exceeds 1000:1",
    )
    add(c.Case("C-27", "Zip bomb", Verdict.INVALID), f27)
    f28 = f01.model_copy(deep=True)
    assert f28.structure is not None
    f28.structure.hostile_names = ["'../../evil.apk': '..' path segment"]
    add(
        c.Case(
            "C-28",
            "Path-traversal member names",
            Verdict.GENUINE,
            ("HOSTILE_ENTRY_NAME",),
            note="names are only ever displayed; members are stored by content hash",
        ),
        f28,
    )
    f29 = f01.model_copy(deep=True)
    assert f29.verify is not None and f29.verify.full_range is not None
    modern = f29.verify.full_range.model_copy(deep=True)
    modern.min_sdk = 24
    f29.verify.full_range.verified = False
    f29.verify.full_range.min_sdk = 21
    f29.verify.full_range.all_errors = [Issue(issue="JAR_SIG_UNSUPPORTED_SIG_ALG", message="legacy platform")]
    f29.verify.modern_range = modern
    add(c.Case("C-29", "Signatures fail only below API 24", Verdict.GENUINE, ("LEGACY_PLATFORM_INCOMPATIBLE",)), f29)
    f30 = f01.model_copy(deep=True)
    assert f30.verify and f30.verify.full_range
    f30.verify.full_range.signers[0].cert_sha256 = "ab" * 32
    add(c.Case("C-30", "apksig reports a certificate absent from the native inventory", Verdict.ANOMALY), f30)
    f31 = f01.model_copy(deep=True)
    assert f31.manifest is not None
    f31.manifest.parsers_disagree = True
    f31.manifest.differences = ["package: androguard='dev.kloner.fixture' aapt2='dev.kloner.other'"]
    add(c.Case("C-31", "Manifest parsers disagree on package", Verdict.ANOMALY), f31)
    f32 = f01.model_copy(deep=True)
    assert f32.verify is not None
    f32.verify.unknown_signature_relevant_items = ["V3_SIG_UNKNOWN_ADDITIONAL_ATTRIBUTE(0x12345678)"]
    add(c.Case("C-32", "Unknown signature-relevant attribute in a trusted signer", Verdict.ERROR), f32)
    return out


def run_selftest(rt: Runtime, mode: str = "standard", console: Console | None = None) -> bool:
    console = console or Console()
    rt.fast_doctor()
    work = Path(tempfile.mkdtemp(prefix="selftest-", dir=rt.quarantine.incoming))
    outcomes: list[Outcome] = []
    t_all = time.monotonic()
    try:
        console.print(f"Building the corpus in {work} …")
        cases, ctx = build(rt, work, console)
        if mode == "quick":
            cases = [k for k in cases if k.id in ("C-01", "C-02", "C-06", "C-15", "C-16", "C-24", "C-33")]
        pipe = rt.pipeline()
        kk = rt.known_keys

        def run_file(case: c.Case) -> Outcome:
            t0 = time.monotonic()
            assert case.file is not None
            sha, _ = rt.quarantine.ingest_file(case.file, 1 << 30)
            sr = pipe.evaluate(sha, case.expected_package, case.anchors, kk)
            ev = sr.evaluation
            ok, why = _check(case, ev.verdict, ev.label_codes())
            want_reason = ctx["reasons"].get(case.id)
            if ok and want_reason and not any(r.startswith(want_reason) for r in ev.reasons):
                ok, why = False, f"missing reason {want_reason}"
            return Outcome(
                case.id,
                case.title,
                ok,
                f"{ev.verdict.value} {' '.join(ev.label_codes())}".strip(),
                _want(case),
                why or case.note,
                time.monotonic() - t0,
            )

        with ThreadPoolExecutor(max_workers=rt.worker_count()) as pool:
            outcomes += list(pool.map(run_file, cases))
        if mode != "quick":
            for case, facts in facts_cases(ctx, kk):
                ev = decide(facts, case.anchors, kk)
                ok, why = _check(case, ev.verdict, ev.label_codes())
                outcomes.append(
                    Outcome(
                        case.id,
                        case.title + " [facts]",
                        ok,
                        f"{ev.verdict.value} {' '.join(ev.label_codes())}".strip(),
                        _want(case),
                        why or case.note,
                        level="facts",
                    )
                )
            outcomes += anchor_cases(rt, ctx)
            outcomes.append(metadata_case(rt, ctx))
            outcomes.append(reverify_case(rt, ctx))
            outcomes += agreement_cases(rt, ctx, mode)
            n1, n2 = (1000, 200) if mode == "full" else (50, 30)
            outcomes += mutation_cases(rt, ctx, n1, n2)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    table = Table(box=None, header_style="bold")
    for col in ("CASE", "RESULT", "LEVEL", "GOT", "EXPECTED", "DETAIL"):
        table.add_column(col, overflow="fold")
    for o in sorted(outcomes, key=lambda o: o.case):
        table.add_row(o.case, "[green]PASS[/]" if o.ok else "[red]FAIL[/]", o.level, o.got, o.want, o.detail)
    console.print(table)
    failed = [o for o in outcomes if not o.ok]
    n_facts = sum(1 for o in outcomes if o.level == "facts")
    console.print(
        f"selftest {mode}: {len(outcomes) - len(failed)}/{len(outcomes)} PASS in {time.monotonic() - t_all:.0f}s"
        + (f" ({n_facts} decided at the facts level, see docs/DECISIONS.md D-026)" if n_facts else "")
    )
    _write_golden_projection(rt, outcomes)
    return not failed


def _want(case: c.Case) -> str:
    base = case.expected.value if case.expected else "/".join(v.value for v in case.one_of)
    if case.never:
        base += " (never " + "/".join(v.value for v in case.never) + ")"
    return (base + " " + " ".join(f"+{x}" for x in case.labels)).strip()


def anchor_cases(rt: Runtime, ctx: dict[str, Any]) -> list[Outcome]:
    out = []
    V, F = ctx["keys"]["vendor"], ctx["keys"]["foreign"]
    existing = ctx["anchors"]["v"]
    res = MethodResult(
        klass="VENDOR_PUBLISHED",
        method="fingerprint",
        identities=[
            Identity(
                id="pending",
                cert_sha256=F.sha256,
                evidence=[
                    Evidence(klass="VENDOR_PUBLISHED", method="fingerprint", retrieved_utc="2026-01-01T00:00:00Z")
                ],
            )
        ],
    )
    before = existing.model_dump_json()
    try:
        anchor_methods.merge(existing, res, package=c.FIXTURE_PACKAGE, known_keys=rt.known_keys)
        out.append(Outcome("C-35", "Anchor add with disjoint evidence", False, "merged", "CONFLICT (exit 3)"))
    except AnchorConflict:
        ok = existing.model_dump_json() == before
        out.append(
            Outcome(
                "C-35",
                "Anchor add with disjoint evidence",
                ok,
                "CONFLICT (exit 3), nothing written",
                "CONFLICT (exit 3)",
            )
        )
    testkey = next(k for k, n in rt.known_keys.items() if n == "AOSP_TESTKEY")
    res2 = MethodResult(
        klass="USER",
        method="fingerprint",
        identities=[
            Identity(
                id="pending",
                cert_sha256=testkey,
                evidence=[Evidence(klass="USER", method="fingerprint", retrieved_utc="2026-01-01T00:00:00Z")],
            )
        ],
    )
    try:
        anchor_methods.merge(None, res2, package=c.FIXTURE_PACKAGE, known_keys=rt.known_keys)
        out.append(Outcome("C-36", "Anchor whose identity is a public test key", False, "accepted", "exit 3"))
    except HygieneError:
        out.append(
            Outcome("C-36", "Anchor whose identity is a public test key", True, "hygiene failure (exit 3)", "exit 3")
        )
    _ = V
    return out


def metadata_case(rt: Runtime, ctx: dict[str, Any]) -> Outcome:
    sha, _ = rt.quarantine.ingest_file(ctx["files"]["C-01"], 1 << 30)
    sr = rt.pipeline().evaluate(sha, c.FIXTURE_PACKAGE, {c.FIXTURE_PACKAGE: ctx["anchors"]["v"]}, rt.known_keys)
    claimed = Claimed(version_name="9.9", version_code=99, md5="0" * 32, signer_sha1="1" * 40)
    mism = cross_check(claimed, sr.evaluation, sr.facts, rt.quarantine.path_for(sha))
    ok = len(mism) >= 3
    return Outcome(
        "C-38",
        "Mock source claims version/hash/signer that differ",
        ok,
        f"METADATA_MISMATCH ({len(mism)} differences)",
        "METADATA_MISMATCH",
        "; ".join(mism)[:160],
    )


def reverify_case(rt: Runtime, ctx: dict[str, Any]) -> Outcome:
    """C-37: two independent evaluations of the corpus produce byte-identical verdict JSON."""
    pipe = rt.pipeline()
    anchors = {c.FIXTURE_PACKAGE: ctx["anchors"]["v"]}
    diffs = []
    for cid in ("C-01", "C-02", "C-06", "C-15", "C-24", "C-25"):
        sha, _ = rt.quarantine.ingest_file(ctx["files"][cid], 1 << 30)
        a = verdict_json(pipe.evaluate(sha, c.FIXTURE_PACKAGE, anchors, rt.known_keys).evaluation)
        b = verdict_json(pipe.evaluate(sha, c.FIXTURE_PACKAGE, anchors, rt.known_keys).evaluation)
        if a != b:
            diffs.append(cid)
    return Outcome(
        "C-37",
        "reverify of corpus samples",
        not diffs,
        "identical" if not diffs else f"differs: {diffs}",
        "byte-identical verdict JSON",
    )


def agreement_cases(rt: Runtime, ctx: dict[str, Any], mode: str) -> list[Outcome]:
    """§18.5: the bridge equals ``apksigner verify -v --print-certs`` on verified flag and signer digests."""
    sg = c.Signer(rt.toolchain())
    pipe = rt.pipeline()
    out = []
    ids = [
        k
        for k in (
            "C-01",
            "C-02",
            "C-03",
            "C-06",
            "C-07",
            "C-14",
            "C-15",
            "C-16",
            "C-21",
            "C-33",
            "C-34",
            "X-01",
            "X-02",
        )
        if mode == "full" or k in ("C-01", "C-02", "C-15", "C-16", "X-01")
    ]
    for cid in ids:
        path = ctx["files"][cid]
        ok_cli, digests_cli = sg.verify_certs(path)
        sha, _ = rt.quarantine.ingest_file(path, 1 << 30)
        facts, _ = pipe.facts(sha, None)
        rng = facts.verify.full_range if facts.verify else None
        ok_bridge = bool(rng and rng.verified)
        signers = rng.signers if rng else []
        digests_bridge = sorted({s.cert_sha256 for s in signers if s.cert_sha256 and not s.ignored})
        agree = (ok_bridge and set(digests_cli) <= set(digests_bridge)) if ok_cli else not ok_bridge
        out.append(
            Outcome(
                f"E-{cid}",
                f"engine agreement on {cid}",
                agree,
                f"bridge={ok_bridge} cli={ok_cli}",
                "same verified flag and signer digests",
            )
        )
    return out


def mutation_cases(rt: Runtime, ctx: dict[str, Any], n1: int, n2: int) -> list[Outcome]:
    """P-01/P-02: random single-byte mutations of C-01 (robustness of the whole pipeline)."""
    src = ctx["files"]["C-01"]
    data = src.read_bytes()
    from kloner.container.zipstrict import open_archive
    from kloner.util.limits import DEFAULT_LIMITS

    archive = open_archive(src, DEFAULT_LIMITS)
    blk = locate(archive, DEFAULT_LIMITS)
    assert blk is not None
    pipe = rt.pipeline()
    anchors = {c.FIXTURE_PACKAGE: ctx["anchors"]["v"]}
    unsigned_ranges = []
    facts01: EvaluationFacts = ctx["facts01"]
    if facts01.native_inventory:
        for p in facts01.native_inventory.pairs:
            if p.kind in ("unsigned", "padding"):
                unsigned_ranges.append((p.offset, p.offset + p.size))
    outside = [i for i in range(len(data)) if not (blk.start <= i < blk.end)]
    inside = list(range(blk.start, blk.end))

    def mutate(offsets: list[int]) -> list[tuple[int, Verdict]]:
        def one(off: int) -> tuple[int, Verdict]:
            b = bytearray(data)
            b[off] ^= 1 << _rng.randrange(8)
            sha, _ = rt.quarantine.ingest_bytes(bytes(b), 1 << 30)
            ev = pipe.evaluate(sha, c.FIXTURE_PACKAGE, anchors, rt.known_keys).evaluation
            rt.quarantine.remove(sha)
            return off, ev.verdict

        with ThreadPoolExecutor(max_workers=rt.worker_count()) as pool:
            return list(pool.map(one, offsets))

    r1 = mutate(_rng.sample(outside, min(n1, len(outside))))
    bad1 = [(o, v.value) for o, v in r1 if v in (Verdict.GENUINE, Verdict.FORGED)]
    r2 = mutate(_rng.sample(inside, min(n2, len(inside))))
    bad2 = []
    for o, v in r2:
        in_unsigned = any(a <= o < b for a, b in unsigned_ranges)
        if v == Verdict.FORGED or (v == Verdict.GENUINE and not in_unsigned):
            bad2.append((o, v.value))
    return [
        Outcome(
            "P-01",
            f"{len(r1)} mutations outside the signing block",
            not bad1,
            f"{len(bad1)} GENUINE/FORGED",
            "never GENUINE or FORGED",
            str(bad1[:5]) if bad1 else "",
        ),
        Outcome(
            "P-02",
            f"{len(r2)} mutations inside the signing block",
            not bad2,
            f"{len(bad2)} violations",
            "GENUINE only in unsigned pairs; never FORGED",
            str(bad2[:5]) if bad2 else "",
        ),
    ]


def _write_golden_projection(rt: Runtime, outcomes: list[Outcome]) -> None:
    proj = {o.case: {"ok": o.ok, "got": o.got.split(" ")[0]} for o in outcomes if not o.case.startswith(("P-", "E-"))}
    path = rt.home / "selftest-last.json"
    path.write_text(json.dumps(proj, indent=2, sort_keys=True), encoding="utf-8")
    _ = hashlib
