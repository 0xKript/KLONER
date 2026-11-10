"""The decision procedure (§6.3), trust closure (§6.4) and bundle rules (§6.5).

``decide()`` is a pure function of (facts, anchors, known keys). All I/O happens before it. Only
this module assigns verdicts (INV-4): heuristics elsewhere add labels, never verdicts.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field

from kloner import __version__
from kloner.impersonation.labels import normalize_label
from kloner.labels import make_label
from kloner.models import (
    SEVERITY_ORDER,
    Anchor,
    Evaluation,
    EvaluationFacts,
    GateStep,
    Label,
    MemberRef,
    NativeInventory,
    SignerTrust,
    TrustPath,
    Verdict,
    VerifyRange,
)
from kloner.util.fingerprints import short_fp
from kloner.verify.inventory import disagreements

MAX_SDK = 2_147_483_647
EN_DASH = "\u2013"

# apksig issues that mean a stronger scheme was stripped or required but absent (docs/DECISIONS.md).
STRIP_ISSUES = frozenset(
    {
        "JAR_SIG_MISSING_APK_SIG_REFERENCED",
        "V2_SIG_MISSING_APK_SIG_REFERENCED",
        "MIN_SIG_SCHEME_FOR_TARGET_SDK_NOT_MET",
        "V31_BLOCK_MISSING",
        "JAR_SIG_NO_APK_SIG_STRIP_PROTECTION",
        "NO_SIG_FOR_TARGET_SANDBOX_VERSION",  # targetSandboxVersion 2+ requires v2 or higher (found in D-057)
    }
)
UNKNOWN_ATTRIBUTE_ISSUES = frozenset({"V2_SIG_UNKNOWN_ADDITIONAL_ATTRIBUTE", "V3_SIG_UNKNOWN_ADDITIONAL_ATTRIBUTE"})
STRONG_PROVENANCE = frozenset({"VENDOR_HTTPS", "PLAY_API", "STORE_INSTALL", "FDROID_INDEX", "VENDOR_PUBLISHED"})


# --------------------------------------------------------------------------------------------
# Trust closure
# --------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class SignerBlock:
    """A signer block apksig verified: its signer and its lineage (oldest first).

    ``node_valid[i]`` says whether lineage node i verifies under node i-1 (index 0 is unused).
    """

    signer: str
    lineage: tuple[str, ...] = ()
    node_valid: tuple[bool, ...] = ()


def closure(trusted: Iterable[str], blocks: Sequence[SignerBlock]) -> dict[str, TrustPath]:
    """T*: the anchor set plus certificates admitted by R1 (endorsement) and R2 (rotation proof)."""
    paths: dict[str, TrustPath] = dict.fromkeys(trusted, "T")
    changed = True
    while changed:
        changed = False
        for b in blocks:
            if not b.lineage:
                continue
            if b.signer in paths:
                for c in b.lineage:
                    if c not in paths:
                        paths[c] = "R1"
                        changed = True
            for i in range(1, len(b.lineage)):
                prev, node = b.lineage[i - 1], b.lineage[i]
                valid = b.node_valid[i] if i < len(b.node_valid) else False
                if valid and prev in paths and node not in paths:
                    paths[node] = "R2"
                    changed = True
    return paths


def verified_blocks(rng: VerifyRange, native: NativeInventory | None) -> list[SignerBlock]:
    """v3/v3.1 signer blocks apksig verified, with lineage node validity from the native parser."""
    out: list[SignerBlock] = []
    for s in rng.signers:
        if s.scheme not in ("v3", "v31") or not s.cert_sha256:
            continue
        lineage = tuple(c.cert_sha256 for c in (s.lineage or []))
        valid: tuple[bool, ...] = ()
        if native is not None:
            pairs = native.scheme_pairs(s.scheme)
            if pairs and s.index < len(pairs[0].signers):
                nl = pairs[0].signers[s.index].lineage or []
                if [n.cert_sha256 for n in nl] == list(lineage):
                    valid = tuple(n.signature_valid is True for n in nl)
        out.append(SignerBlock(s.cert_sha256, lineage, valid))
    return out


def app_signers(rng: VerifyRange | None, native: NativeInventory | None) -> dict[str, list[str]]:
    """Every app-signer certificate: native signers of every block united with apksig's signers."""
    out: dict[str, set[str]] = {}
    if native is not None:
        for cert, schemes in native.app_signer_certs().items():
            out.setdefault(cert, set()).update(schemes)
    if rng is not None:
        for s in rng.signers:
            if s.cert_sha256:
                out.setdefault(s.cert_sha256, set()).add(s.scheme)
    return {c: sorted(v) for c, v in sorted(out.items())}


def apksig_signers(rng: VerifyRange) -> set[str]:
    return {s.cert_sha256 for s in rng.signers if s.cert_sha256 and not s.ignored}


# --------------------------------------------------------------------------------------------
# Decision
# --------------------------------------------------------------------------------------------


@dataclass
class _Ctx:
    facts: EvaluationFacts
    anchors: Mapping[str, Anchor]
    known_keys: Mapping[str, str]
    kloner_version: str
    labels: dict[str, Label] = field(default_factory=dict)
    reasons: list[str] = field(default_factory=list)
    trace: list[GateStep] = field(default_factory=list)

    def label(self, code: str, detail: str | None = None, **evidence: object) -> None:
        if code not in self.labels:
            self.labels[code] = make_label(code, detail, **evidence)

    def step(self, gate: str, status: str, detail: str) -> None:
        self.trace.append(GateStep(gate=gate, status=status, detail=detail))  # type: ignore[arg-type]

    def result(
        self,
        verdict: Verdict,
        explanation: str,
        *,
        anchor: Anchor | None = None,
        signers: list[SignerTrust] | None = None,
        brand_package: str | None = None,
    ) -> Evaluation:
        f = self.facts
        m = f.manifest
        return Evaluation(
            sample_sha256=f.sample_sha256,
            size=f.size,
            format=f.intake.format,
            package=m.package if m and not m.unreadable else None,
            version_code=m.version_code if m and not m.unreadable else None,
            version_name=m.version_name if m and not m.unreadable else None,
            split=m.split if m and not m.unreadable else None,
            verdict=verdict,
            labels=sorted(self.labels.values(), key=lambda lab: lab.code),
            reasons=list(self.reasons),
            explanation=explanation,
            signers=signers or [],
            gate_trace=list(self.trace),
            anchor_package=anchor.package if anchor else None,
            anchor_record_sha256=anchor.record_sha256 if anchor else None,
            brand_package=brand_package,
            kloner_version=self.kloner_version,
            apksig_version=f.verify.apksig_version if f.verify else None,
        )


def _signer_records(signers: Mapping[str, list[str]], paths: Mapping[str, TrustPath], ctx: _Ctx) -> list[SignerTrust]:
    out = []
    certs = ctx.facts.native_inventory.certs if ctx.facts.native_inventory else {}
    for cert, schemes in signers.items():
        info = certs.get(cert)
        out.append(
            SignerTrust(
                cert_sha256=cert,
                schemes=list(schemes),
                trust=paths.get(cert, "none"),
                subject=info.subject if info else None,
                issuer=info.issuer if info else None,
                key_algorithm=info.key_algorithm if info else None,
                key_bits=info.key_bits if info else None,
                known_key=ctx.known_keys.get(cert),
                debug_dn=bool(info and info.debug_dn),
            )
        )
    return out


def _effective_range(facts: EvaluationFacts) -> VerifyRange | None:
    v = facts.verify
    if v is None or v.engine_failure or v.full_range is None:
        return None
    if v.full_range.verified:
        return v.full_range
    if v.modern_range is not None and v.modern_range.verified:
        return v.modern_range
    return None


def vendor_signed(facts: EvaluationFacts, anchor: Anchor) -> bool:
    """apksig verified the file and at least one apksig-verified signer is in the anchor's T*."""
    rng = _effective_range(facts)
    if rng is None or (facts.structure is not None and facts.structure.violations):
        return False
    tstar = closure(anchor.trusted(), verified_blocks(rng, facts.native_inventory))
    return bool(apksig_signers(rng) & set(tstar))


def brand_check(ctx: _Ctx) -> Evaluation | None:
    """IMPERSONATOR ⇔ package ≠ P, no signer in P's T*, and EXACT_ICON or EXACT_LABEL (§11)."""
    f = ctx.facts
    if f.brand is None or f.manifest is None:
        return None
    pkg = f.manifest.package
    icons = set(f.brand.icon_hashes)
    labels = {normalize_label(lab) for lab in f.brand.labels}
    matches: list[tuple[str, list[str]]] = []
    for brand_pkg in sorted(ctx.anchors):
        a = ctx.anchors[brand_pkg]
        if brand_pkg == pkg:
            continue
        evidence: list[str] = []
        if icons & set(a.brand.icon_asset_sha256):
            evidence.append("EXACT_ICON")
        declared = {normalize_label(b) for b in a.brand.brand_labels}
        if declared and labels & declared:
            evidence.append("EXACT_LABEL")
        if evidence and not vendor_signed(f, a):
            matches.append((brand_pkg, evidence))
    if not matches:
        if f.brand.icon_resolution_error:
            ctx.label("ICON_UNRESOLVED", f.brand.icon_resolution_error)
        return None
    brand_pkg, evidence = matches[0]
    for ev in evidence:
        ctx.label(ev, brand=brand_pkg)
    rng = _effective_range(f)
    signers = app_signers(rng or (f.verify.full_range if f.verify else None), f.native_inventory)
    foreign = next(iter(signers), None)
    ctx.reasons.extend(f"R-IMP-{e.replace('_', '-')}" for e in evidence)
    ctx.step("IMP", "fail", f"presents the brand of {brand_pkg} ({', '.join(evidence)}) without its identity")
    what = " and ".join({"EXACT_ICON": "launcher icon", "EXACT_LABEL": "brand label"}[e] for e in evidence)
    return ctx.result(
        Verdict.IMPERSONATOR,
        f"Package {pkg} presents the official {what} of {brand_pkg} but is signed by {short_fp(foreign)}.",
        anchor=ctx.anchors[brand_pkg],
        signers=_signer_records(signers, {}, ctx),
        brand_package=brand_pkg,
    )


def _common_labels(ctx: _Ctx, rng: VerifyRange | None) -> None:
    f = ctx.facts
    st = f.structure
    if st is not None:
        if st.unreferenced:
            ctx.label(
                "UNREFERENCED_BYTES",
                f"{len(st.unreferenced)} region(s)",
                regions=[g.model_dump() for g in st.unreferenced],
            )
        if st.hostile_names:
            ctx.label("HOSTILE_ENTRY_NAME", f"{len(st.hostile_names)} name(s)", names=st.hostile_names[:50])
    nat = f.native_inventory
    if nat is not None and not nat.error:
        unsigned = [p for p in nat.pairs if p.kind == "unsigned"]
        if unsigned:
            ctx.label(
                "UNSIGNED_BLOCK_DATA",
                ", ".join(f"{p.id_hex} ({p.name}, {p.size} B)" for p in unsigned),
                pairs=[{"id": p.id_hex, "name": p.name, "size": p.size, "sha256": p.sha256} for p in unsigned],
            )
        sniffed = [p for p in nat.pairs if p.kind == "sniffed_signature"]
        if sniffed:
            ctx.label("UNKNOWN_SIGNER_BLOCK", ", ".join(p.id_hex for p in sniffed), ids=[p.id_hex for p in sniffed])
        has_v2plus = any(nat.has_scheme(s) for s in ("v2", "v3", "v31"))
        if nat.v1 and not has_v2plus:
            ctx.label("V1_ONLY")
    if rng is not None:
        stamp = rng.source_stamp
        if stamp.present and stamp.status == "STAMP_VERIFIED":
            ctx.label("PLAY_SOURCE_STAMP", short_fp(stamp.cert_sha256), stamp_cert_sha256=stamp.cert_sha256)
        elif stamp.present and stamp.status not in (None, "STAMP_MISSING"):
            ctx.label("SOURCE_STAMP_INVALID", stamp.status, status=stamp.status)
        for w in rng.warning_names():
            if w not in UNKNOWN_ATTRIBUTE_ISSUES:
                ctx.label(f"VERIFIER_WARNING:{w}")


def _version_labels(ctx: _Ctx, anchor: Anchor, signers: Mapping[str, list[str]]) -> None:
    f = ctx.facts
    vc = f.manifest.version_code if f.manifest else None
    lineage = [e.cert_sha256 for e in anchor.lineage]
    strong = [r for r in anchor.release_refs if r.provenance in STRONG_PROVENANCE]
    if vc is not None and strong:
        top = max(r.version_code for r in strong)
        if vc > top:
            ctx.label("AHEAD_OF_OFFICIAL", f"{vc} > {top}", highest_official=top)
        elif vc < top:
            ctx.label("OUTDATED", f"{top - vc} version code(s) behind {top}", latest_official=top, gap=top - vc)
    legacy = set(lineage[:-1]) if len(lineage) > 1 else set()
    if signers and legacy and all(c in legacy for c in signers) and vc is not None:
        idx = {c: i for i, c in enumerate(lineage)}
        oldest = min(idx[c] for c in signers)
        successors = set(lineage[oldest + 1 :])
        rotated = [r.version_code for r in anchor.release_refs if successors & set(r.signers)]
        if rotated and vc >= min(rotated):
            ctx.label(
                "LEGACY_KEY_ON_NEW_BUILD",
                f"versionCode {vc} >= {min(rotated)}, the first release signed by a successor key",
            )


def decide(
    facts: EvaluationFacts,
    anchors: Mapping[str, Anchor],
    known_keys: Mapping[str, str] | None = None,
    kloner_version: str = __version__,
) -> Evaluation:
    ctx = _Ctx(facts, anchors, known_keys or {}, kloner_version)
    f = facts

    if f.collection_error:
        ctx.reasons.append("R-PIPELINE-FACTS-INCOMPLETE")
        ctx.step("G0", "fail", f.collection_error)
        return ctx.result(Verdict.ERROR, f"Evaluation could not complete: {f.collection_error}.")

    # G0-G2: intake and archive integrity
    if f.intake.failed:
        reason = f.intake.reason or "UNKNOWN"
        ctx.reasons.append(f"R-G0-{reason.replace('_', '-')}")
        ctx.step("G0", "fail", f"{reason}: {f.intake.detail or ''}".strip())
        return ctx.result(
            Verdict.INVALID, f"Not an evaluable Android distribution artifact: {reason} ({f.intake.detail})."
        )
    ctx.step("G0", "pass", f"format {f.intake.format}")
    if f.archive is None or f.archive.failed:
        reason = (f.archive.reason if f.archive else None) or "CORRUPT"
        detail = f.archive.detail if f.archive else "archive facts missing"
        ctx.reasons.append(f"R-G2-{reason.replace('_', '-')}")
        ctx.step("G2", "fail", f"{reason}: {detail}")
        return ctx.result(Verdict.INVALID, f"Not an evaluable Android distribution artifact: {reason} ({detail}).")
    ctx.step("G2", "pass", f"{f.archive.entry_count} entries, CRC-32 consistent")

    # G3: identity
    m = f.manifest
    if m is None or m.unreadable:
        cause = m.unreadable_detail if m else "manifest facts missing"
        ctx.reasons.append("R-G3-MANIFEST-UNREADABLE")
        ctx.step("G3", "fail", f"manifest unreadable: {cause}")
        return ctx.result(
            Verdict.ANOMALY,
            f"KLONER refuses to certify this file: manifest unreadable ({cause}). Manual review required.",
        )
    if m.parsers_disagree:
        ctx.reasons.append("R-G3-PARSER-DIFFERENTIAL")
        ctx.step("G3", "fail", "; ".join(m.differences))
        return ctx.result(
            Verdict.ANOMALY,
            "KLONER refuses to certify this file: the manifest parsers disagree "
            f"({'; '.join(m.differences)}). Manual review required.",
        )
    pkg = m.package or ""
    ctx.step("G3", "pass", f"package {pkg} versionCode {m.version_code}")

    rng_any = _effective_range(f)
    if f.expected_package and pkg != f.expected_package:
        imp = brand_check(ctx)
        if imp is not None:
            return imp
        exp = anchors.get(f.expected_package)
        if exp is not None and vendor_signed(f, exp):
            ctx.label("SAME_VENDOR", f"signed by the official identity of {f.expected_package}")
        ctx.reasons.append("R-G3-PACKAGE-MISMATCH")
        signers = app_signers(rng_any or (f.verify.full_range if f.verify else None), f.native_inventory)
        return ctx.result(
            Verdict.MISMATCH,
            f"Valid file of package {pkg}, not {f.expected_package}.",
            signers=_signer_records(signers, {}, ctx),
        )
    anchor = anchors.get(pkg)
    if anchor is None:
        imp = brand_check(ctx)
        if imp is not None:
            return imp
        ctx.reasons.append("R-G3-UNANCHORED")
        signers = app_signers(rng_any or (f.verify.full_range if f.verify else None), f.native_inventory)
        return ctx.result(
            Verdict.UNANCHORED,
            f"No anchor exists for {pkg}. Create one through an official method: kloner anchor add {pkg} --from-url …",
            signers=_signer_records(signers, {}, ctx),
        )

    # G4: structure (decisive on its own)
    st = f.structure
    if st is None:
        ctx.reasons.append("R-G4-FACTS-MISSING")
        return ctx.result(Verdict.ERROR, "Evaluation could not complete: structure facts missing.", anchor=anchor)
    if st.violations:
        for viol in st.violations:
            ctx.reasons.append(f"R-G4-{viol.code}")
            ctx.label(viol.kind, f"{viol.rule}: {viol.detail}", rule=viol.rule)
        first = st.violations[0]
        ctx.step("G4", "fail", "; ".join(f"{x.rule} {x.detail}" for x in st.violations))
        _common_labels(ctx, None)
        signers = app_signers(f.verify.full_range if f.verify else None, f.native_inventory)
        return ctx.result(
            Verdict.TAMPERED,
            f"Structural attack pattern {first.rule}: {first.detail}.",
            anchor=anchor,
            signers=_signer_records(signers, {}, ctx),
        )
    ctx.step("G4", "pass", "structural gate S1/S2/S3/S5 satisfied")

    # G5: cryptographic verification
    v = f.verify
    if v is None or v.engine_failure or v.full_range is None:
        cause = (v.engine_detail if v else None) or "verifier result missing"
        ctx.reasons.append("R-G5-VERIFIER-FAILURE")
        ctx.step("G5", "fail", cause)
        return ctx.result(Verdict.ERROR, f"Evaluation could not complete: apksig failed ({cause}).", anchor=anchor)
    rng = v.full_range
    if not rng.verified:
        if v.modern_range is not None and v.modern_range.verified:
            ctx.label(
                "LEGACY_PLATFORM_INCOMPATIBLE",
                f"fails for API {rng.min_sdk}+, verifies for API {v.modern_range.min_sdk}+",
                failing_issues=rng.issue_names(),
            )
            ctx.step("G5", "info", f"full range failed ({', '.join(rng.issue_names())}); modern range verified")
            rng = v.modern_range
        else:
            issues = rng.issue_names() or ["UNVERIFIED"]
            for i in issues:
                ctx.reasons.append(f"R-G5-APKSIG:{i}")
            claimed = app_signers(rng, f.native_inventory)
            official = anchor.trusted()
            stripped = sorted(STRIP_ISSUES & set(issues))
            if stripped and set(issues) <= STRIP_ISSUES:
                # Every failure is a missing stronger scheme: the signatures that are present verify, so the
                # content was not changed under them (D-058).
                explanation = (
                    f"A signature scheme this file requires or names is missing ({stripped[0]}). The signatures "
                    "that are present verify, but apksig rejects the file without the missing scheme."
                )
            elif set(claimed) & official:
                ctx.label("CONTENT_MODIFIED_UNDER_OFFICIAL_SIGNATURE", issues[0], issues=issues)
                explanation = (
                    f"The file was modified after it was signed: {issues[0]}. The official certificate is "
                    "present, but it does not validate this content."
                )
            else:
                ctx.label("SIGNATURE_INVALID", issues[0], issues=issues)
                explanation = f"The signatures do not verify: {issues[0]}."
            if stripped:
                ctx.label("SCHEME_STRIPPED", ", ".join(stripped))
            ctx.step("G5", "fail", f"apksig rejects the file: {', '.join(issues)}")
            _common_labels(ctx, None)
            return ctx.result(Verdict.TAMPERED, explanation, anchor=anchor, signers=_signer_records(claimed, {}, ctx))
    else:
        schemes = ", ".join(s for s, ok in sorted(rng.schemes.items()) if ok) or "none"
        ctx.step("G5", "pass", f"apksig verified {schemes} for API {rng.min_sdk}+")

    # G6: inventory agreement
    diffs = disagreements(rng, f.native_inventory, f.androguard_inventory)
    if diffs:
        ctx.reasons.append("R-G6-ENGINE-DISAGREEMENT")
        ctx.step("G6", "fail", "; ".join(diffs))
        return ctx.result(
            Verdict.ANOMALY,
            f"KLONER refuses to certify this file: the signer inventories disagree ({diffs[0]}). "
            "Manual review required.",
            anchor=anchor,
        )
    ctx.step("G6", "pass", "apksig, native and androguard inventories agree")

    # G7: trust
    paths = closure(anchor.trusted(), verified_blocks(rng, f.native_inventory))
    signers = app_signers(rng, f.native_inventory)
    records = _signer_records(signers, paths, ctx)
    foreign = [c for c in signers if c not in paths]
    _common_labels(ctx, rng)
    if foreign:
        trusted_present = [c for c in signers if c in paths]
        if trusted_present:
            ctx.label("MIXED_SIGNERS", f"{len(trusted_present)} trusted, {len(foreign)} foreign")
        certs = f.native_inventory.certs if f.native_inventory else {}
        for c in foreign:
            if c in ctx.known_keys:
                ctx.label(f"KNOWN_PUBLIC_KEY:{ctx.known_keys[c]}", short_fp(c), cert_sha256=c)
            info = certs.get(c)
            if info and info.debug_dn:
                ctx.label("DEBUG_DN", info.subject, cert_sha256=c)
        ctx.reasons.append("R-G7-FOREIGN-SIGNER")
        ctx.step("G7", "fail", f"signer(s) outside the official identity: {', '.join(short_fp(c) for c in foreign)}")
        info = certs.get(foreign[0])
        dn = info.subject if info else "unknown"
        official_fps = ", ".join(short_fp(c) for c in sorted(anchor.trusted()))
        return ctx.result(
            Verdict.FORGED,
            f"Valid signature by a key that is not the official one: {short_fp(foreign[0])} (subject '{dn}'). "
            f"Official identities: {official_fps}.",
            anchor=anchor,
            signers=records,
        )
    unknown = v.unknown_signature_relevant_items
    if unknown:
        ctx.reasons.append("R-G7-VERIFIER-OUTDATED")
        ctx.step("G7", "fail", f"signature-relevant items the verifier does not understand: {', '.join(unknown)}")
        return ctx.result(
            Verdict.ERROR,
            "Evaluation could not complete: the official signer uses signature features the pinned apksig does "
            f"not understand ({', '.join(unknown)}). Upgrade the toolchain: kloner setup --upgrade.",
            anchor=anchor,
            signers=records,
        )

    for c, path in paths.items():
        if c not in signers:
            continue
        ident = anchor.identity(c)
        if path in ("R1", "R2"):
            ctx.label("ROTATED_KEY", f"{short_fp(c)} admitted by {path}", cert_sha256=c, rule=path)
        if ident is not None and ident.declared_additional:
            ctx.label("SECONDARY_IDENTITY", ident.label, identity=ident.id)
    lineage = [e.cert_sha256 for e in anchor.lineage]
    if len(lineage) > 1 and any(c in lineage[:-1] for c in signers):
        ctx.label("LEGACY_KEY", ", ".join(short_fp(c) for c in signers if c in lineage[:-1]))
    _version_labels(ctx, anchor, signers)
    ctx.reasons.append("R-G7-TRUSTED")
    ctx.step("G7", "pass", "every signer is in the trust closure T*")
    anchored = [i for i in anchor.identities if i.cert_sha256 in signers]
    anchored.sort(key=lambda i: (i.role != "current", i.declared_additional, i.id))
    primary = (
        anchored[0].cert_sha256
        if anchored
        else next((c for c in reversed(lineage) if c in signers), None) or next(iter(signers))
    )
    ident = anchor.identity(primary)
    schemes = ", ".join(s for s, ok in sorted(rng.schemes.items()) if ok) or "none"
    return ctx.result(
        Verdict.GENUINE,
        f"Signed by the official identity {short_fp(primary)} ({ident.label if ident else 'lineage'}). "
        f"apksig {v.apksig_version} verified schemes {schemes} for API {rng.min_sdk}"
        f"{EN_DASH}{'max' if rng.max_sdk == MAX_SDK else rng.max_sdk}.",
        anchor=anchor,
        signers=records,
    )


# --------------------------------------------------------------------------------------------
# Bundles (§6.5)
# --------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class MemberResult:
    name: str
    evaluation: Evaluation


@dataclass(frozen=True)
class OtherMember:
    name: str
    sha256: str
    size: int
    kind: str  # payload | obb | metadata
    payload_type: str | None = None


def _worst(verdicts: Iterable[Verdict]) -> Verdict:
    vs = set(verdicts)
    return next(v for v in SEVERITY_ORDER if v in vs)


def decide_bundle(
    facts: EvaluationFacts,
    package: str | None,
    apks: Sequence[MemberResult],
    others: Sequence[OtherMember],
    anchors: Mapping[str, Anchor],
    kloner_version: str = __version__,
) -> Evaluation:
    """Aggregate per-member verdicts into the container verdict (§6.5)."""
    ctx = _Ctx(facts, anchors, {}, kloner_version)
    ctx.step("G1", "info", f"{facts.intake.bundle_kind or 'zip'} bundle with {len(apks)} APK member(s)")
    refs: list[MemberRef] = []
    own: list[MemberResult] = []
    foreign: list[MemberResult] = []
    for mr in apks:
        ev = mr.evaluation
        is_own = package is not None and ev.package == package
        role = "base" if is_own and ev.split is None else ("split" if is_own else "foreign")
        refs.append(
            MemberRef(
                name=mr.name,
                sample_sha256=ev.sample_sha256,
                role=role,
                verdict=ev.verdict,
                package=ev.package,
                split=ev.split,
                size=ev.size,
            )
        )
        (own if is_own else foreign).append(mr)
    for o in others:
        refs.append(
            MemberRef(name=o.name, sample_sha256=o.sha256, role=o.kind, size=o.size, payload_type=o.payload_type)
        )
    refs.sort(key=lambda r: (r.role, r.name))

    def finish(verdict: Verdict, explanation: str) -> Evaluation:
        ev = ctx.result(verdict, explanation, anchor=anchors.get(package or ""))
        base = next((mr.evaluation for mr in own if mr.evaluation.split is None), None)
        return ev.model_copy(
            update={
                "package": package,
                "version_code": base.version_code if base else None,
                "version_name": base.version_name if base else None,
                "split": None,
                "members": refs,
                "signers": _merge_signers(mr.evaluation for mr in own),
                "apksig_version": base.apksig_version if base else None,
            }
        )

    payloads = [o for o in others if o.kind == "payload"]
    obbs = [o for o in others if o.kind == "obb"]
    if payloads:
        types = sorted({o.payload_type or "unknown" for o in payloads})
        ctx.label("UNEXPECTED_PAYLOAD", ", ".join(o.name for o in payloads[:10]), types=types)
    if obbs:
        ctx.label(
            "UNVERIFIABLE_OBB", f"{len(obbs)} file(s)", files=[{"name": o.name, "sha256": o.sha256} for o in obbs]
        )
    if foreign:
        ctx.label(
            "UNEXPECTED_MEMBER",
            ", ".join(f"{mr.name} ({mr.evaluation.package})" for mr in foreign),
            members=[mr.evaluation.sample_sha256 for mr in foreign],
        )
    if package is None or not any(mr.evaluation.split is None for mr in own):
        ctx.label("INCOMPLETE_BUNDLE")
        ctx.reasons.append("R-G1-INCOMPLETE-BUNDLE")
        return finish(Verdict.INVALID, "Not an evaluable bundle: no base APK of the package.")

    verdicts = [mr.evaluation.verdict for mr in own]
    for mr in own:
        ctx.reasons.append(f"R-G1-MEMBER-{mr.evaluation.verdict.value}:{mr.name}")
    if Verdict.TAMPERED in verdicts:
        return finish(Verdict.TAMPERED, _member_expl(own, Verdict.TAMPERED, "was modified after signing"))
    if Verdict.FORGED in verdicts:
        if Verdict.GENUINE in verdicts:
            ctx.label("BUNDLE_INCONSISTENT", "genuine and forged members of the same package")
        return finish(Verdict.FORGED, _member_expl(own, Verdict.FORGED, "is signed by a foreign key"))
    for review in (Verdict.ANOMALY, Verdict.ERROR):
        if review in verdicts:
            return finish(review, _member_expl(own, review, "could not be certified"))
    non_genuine = [v for v in verdicts if v != Verdict.GENUINE]
    if non_genuine:
        worst = _worst(non_genuine)
        return finish(worst, _member_expl(own, worst, f"is {worst.value}"))
    signer_sets = {tuple(sorted(s.cert_sha256 for s in mr.evaluation.signers)) for mr in own}
    if len(signer_sets) > 1:
        ctx.label("SPLIT_SIGNER_DIVERGENCE", f"{len(signer_sets)} distinct signer sets")
        ctx.reasons.append("R-G1-SPLIT-SIGNER-DIVERGENCE")
        return finish(Verdict.ANOMALY, "KLONER refuses to certify this bundle: its members have different signer sets.")
    if foreign:
        ctx.reasons.append("R-G1-UNEXPECTED-MEMBER")
        return finish(
            Verdict.ANOMALY,
            "KLONER refuses to certify this bundle: it carries an APK of another package "
            f"({', '.join(sorted({mr.evaluation.package or '?' for mr in foreign}))}).",
        )
    ctx.reasons.append("R-G1-ALL-MEMBERS-GENUINE")
    return finish(Verdict.GENUINE, f"All {len(own)} APK member(s) of {package} are GENUINE.")


def _member_expl(own: Sequence[MemberResult], verdict: Verdict, what: str) -> str:
    names = [mr.name for mr in own if mr.evaluation.verdict == verdict]
    first = next(mr.evaluation for mr in own if mr.evaluation.verdict == verdict)
    return f"Bundle member {names[0]} {what}: {first.explanation}"


def _merge_signers(evals: Iterable[Evaluation]) -> list[SignerTrust]:
    merged: dict[str, SignerTrust] = {}
    for ev in evals:
        for s in ev.signers:
            if s.cert_sha256 not in merged:
                merged[s.cert_sha256] = s
    return [merged[k] for k in sorted(merged)]
