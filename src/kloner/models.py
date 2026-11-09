"""KLONER data model (pydantic v2).

Facts are what the pipeline observes; ``decide()`` turns facts into an Evaluation. Everything a
verdict depends on lives in these models, so a verdict can be reproduced offline (INV-6).
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


# --------------------------------------------------------------------------------------------
# Verdicts and labels
# --------------------------------------------------------------------------------------------


class Verdict(StrEnum):
    TAMPERED = "TAMPERED"
    FORGED = "FORGED"
    IMPERSONATOR = "IMPERSONATOR"
    ANOMALY = "ANOMALY"
    ERROR = "ERROR"
    MISMATCH = "MISMATCH"
    INVALID = "INVALID"
    UNANCHORED = "UNANCHORED"
    GENUINE = "GENUINE"


SEVERITY_ORDER: tuple[Verdict, ...] = (
    Verdict.TAMPERED,
    Verdict.FORGED,
    Verdict.IMPERSONATOR,
    Verdict.ANOMALY,
    Verdict.ERROR,
    Verdict.MISMATCH,
    Verdict.INVALID,
    Verdict.UNANCHORED,
    Verdict.GENUINE,
)
HOSTILE: frozenset[Verdict] = frozenset({Verdict.TAMPERED, Verdict.FORGED, Verdict.IMPERSONATOR})
REVIEW: frozenset[Verdict] = frozenset({Verdict.ANOMALY, Verdict.ERROR})
NOT_APPLICABLE: frozenset[Verdict] = frozenset({Verdict.MISMATCH, Verdict.INVALID, Verdict.UNANCHORED})

VERDICT_CLASS: dict[Verdict, str] = {
    Verdict.TAMPERED: "Hostile",
    Verdict.FORGED: "Hostile",
    Verdict.IMPERSONATOR: "Hostile",
    Verdict.ANOMALY: "Review",
    Verdict.ERROR: "Review",
    Verdict.MISMATCH: "Not applicable",
    Verdict.INVALID: "Not applicable",
    Verdict.UNANCHORED: "Not applicable",
    Verdict.GENUINE: "Clean",
}

Severity = Literal["info", "notice", "alert"]


class Label(Model):
    code: str
    category: str
    severity: Severity
    detail: str | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)


# --------------------------------------------------------------------------------------------
# Facts
# --------------------------------------------------------------------------------------------


class IntakeFacts(Model):
    failed: bool = False
    reason: str | None = None
    detail: str | None = None
    format: str | None = None  # apk | bundle | aab | zip
    bundle_kind: str | None = None  # xapk | apkm | apks | zip


class ArchiveFacts(Model):
    failed: bool = False
    reason: str | None = None  # CORRUPT | UNSAFE_ARCHIVE | UNSUPPORTED_ZIP64 | ENCRYPTED
    detail: str | None = None
    entry_count: int = 0
    total_uncompressed: int = 0


class ManifestView(Model):
    package: str | None = None
    version_code: int | None = None
    version_name: str | None = None
    split: str | None = None
    min_sdk: int | None = None
    target_sdk: int | None = None


class ManifestFacts(Model):
    unreadable: bool = False
    unreadable_detail: str | None = None
    parsers_disagree: bool = False
    differences: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    androguard: ManifestView | None = None
    aapt2: ManifestView | None = None
    package: str | None = None
    version_code: int | None = None
    version_name: str | None = None
    split: str | None = None
    min_sdk: int | None = None
    target_sdk: int | None = None


class StructureViolation(Model):
    rule: Literal["S1", "S2", "S3", "S5"]
    kind: Literal["POLYGLOT", "ZIP_AMBIGUITY"]
    code: str  # reason-code suffix, e.g. DUPLICATE-ENTRY
    detail: str


class ByteGap(Model):
    start: int
    end: int
    sha256: str


class StructureFacts(Model):
    violations: list[StructureViolation] = Field(default_factory=list)
    unreferenced: list[ByteGap] = Field(default_factory=list)
    hostile_names: list[str] = Field(default_factory=list)


class Issue(Model):
    issue: str
    params: list[str | None] = Field(default_factory=list)
    message: str = ""


class LineageCert(Model):
    cert_sha256: str
    cert_der_b64: str | None = None
    capabilities: dict[str, bool] = Field(default_factory=dict)


class BridgeSigner(Model):
    scheme: Literal["v1", "v2", "v3", "v31"]
    index: int
    ignored: bool = False
    name: str | None = None
    signature_block_file: str | None = None
    signature_file: str | None = None
    cert_sha256: str | None = None
    cert_der_b64: str | None = None
    chain: list[str] = Field(default_factory=list)
    min_sdk: int | None = None
    max_sdk: int | None = None
    rotation_targets_dev_release: bool | None = None
    lineage: list[LineageCert] | None = None
    errors: list[Issue] = Field(default_factory=list)
    warnings: list[Issue] = Field(default_factory=list)


class SourceStampInfo(Model):
    present: bool = False
    status: str | None = None
    cert_sha256: str | None = None
    cert_der_b64: str | None = None
    timestamp_epoch_s: int | None = None
    errors: list[Issue] = Field(default_factory=list)
    warnings: list[Issue] = Field(default_factory=list)
    verified: bool = False


class BridgeInput(Model):
    path: str
    min_sdk: int
    max_sdk: int


class BridgeResult(Model):
    """Exactly what the Java bridge prints for one verification request (§9.1)."""

    id: str | None = None
    bridge_version: str
    apksig_jar_sha256: str | None = None
    input: BridgeInput | None = None
    verified: bool = False
    schemes: dict[str, bool] = Field(default_factory=dict)
    signers: list[BridgeSigner] = Field(default_factory=list)
    lineage: list[LineageCert] | None = None
    signer_certificates: list[str] = Field(default_factory=list)
    source_stamp: SourceStampInfo = Field(default_factory=SourceStampInfo)
    errors: list[Issue] = Field(default_factory=list)
    warnings: list[Issue] = Field(default_factory=list)
    all_errors: list[Issue] = Field(default_factory=list)
    fatal: str | None = None


class VerifyRange(Model):
    """One apksig run over a platform range, stripped of paths (part of the reproducible facts)."""

    min_sdk: int
    max_sdk: int
    verified: bool
    schemes: dict[str, bool] = Field(default_factory=dict)
    signers: list[BridgeSigner] = Field(default_factory=list)
    lineage: list[LineageCert] | None = None
    source_stamp: SourceStampInfo = Field(default_factory=SourceStampInfo)
    errors: list[Issue] = Field(default_factory=list)
    warnings: list[Issue] = Field(default_factory=list)
    all_errors: list[Issue] = Field(default_factory=list)

    @classmethod
    def from_bridge(cls, r: BridgeResult) -> VerifyRange:
        assert r.input is not None
        return cls(
            min_sdk=r.input.min_sdk,
            max_sdk=r.input.max_sdk,
            verified=r.verified,
            schemes=r.schemes,
            signers=r.signers,
            lineage=r.lineage,
            source_stamp=r.source_stamp,
            errors=r.errors,
            warnings=r.warnings,
            all_errors=r.all_errors,
        )

    def issue_names(self) -> list[str]:
        names = [i.issue for i in self.all_errors]
        for s in self.signers:
            names.extend(i.issue for i in s.errors)
        return sorted(set(names))

    def warning_names(self) -> list[str]:
        names = [i.issue for i in self.warnings]
        for s in self.signers:
            names.extend(i.issue for i in s.warnings)
        return sorted(set(names))


class VerifyFacts(Model):
    engine_failure: bool = False
    engine_detail: str | None = None
    apksig_version: str = ""
    full_range: VerifyRange | None = None
    modern_range: VerifyRange | None = None
    unknown_signature_relevant_items: list[str] = Field(default_factory=list)


class CertInfo(Model):
    sha256: str
    sha1: str
    md5: str
    subject: str
    issuer: str
    serial: str
    not_before: str | None = None
    not_after: str | None = None
    key_algorithm: str
    key_bits: int | None = None
    signature_hash: str | None = None
    debug_dn: bool = False
    der_b64: str


class NativeLineageNode(Model):
    cert_sha256: str
    flags: int
    signed_sig_alg: int
    next_sig_alg: int
    signature_valid: bool | None = None  # None for the first node (nothing signs it)
    capabilities: dict[str, bool] = Field(default_factory=dict)


class NativeSigner(Model):
    index: int
    cert_chain: list[str] = Field(default_factory=list)
    signer_cert: str | None = None
    min_sdk: int | None = None
    max_sdk: int | None = None
    attribute_ids: list[int] = Field(default_factory=list)
    unknown_attribute_ids: list[int] = Field(default_factory=list)
    lineage: list[NativeLineageNode] | None = None
    lineage_error: str | None = None
    rotation_min_sdk: int | None = None
    stripping_protection_scheme: int | None = None


SigPairKind = Literal["signature", "source_stamp", "padding", "unsigned", "sniffed_signature"]


class SigBlockPair(Model):
    id: int
    id_hex: str
    name: str
    kind: SigPairKind
    offset: int
    size: int
    sha256: str
    preview: str = ""
    signers: list[NativeSigner] = Field(default_factory=list)
    parse_error: str | None = None


class V1SignatureFile(Model):
    name: str
    certs: list[str] = Field(default_factory=list)
    signer_certs: list[str] = Field(default_factory=list)
    parse_error: str | None = None


class NativeInventory(Model):
    error: str | None = None
    has_signing_block: bool = False
    signing_block_offset: int | None = None
    signing_block_size: int | None = None
    pairs: list[SigBlockPair] = Field(default_factory=list)
    v1: list[V1SignatureFile] = Field(default_factory=list)
    certs: dict[str, CertInfo] = Field(default_factory=dict)

    def scheme_pairs(self, name: str) -> list[SigBlockPair]:
        return [p for p in self.pairs if p.name == name]

    def has_scheme(self, scheme: str) -> bool:
        if scheme == "v1":
            return bool(self.v1)
        return bool(self.scheme_pairs(scheme))

    def all_cert_digests(self) -> set[str]:
        out: set[str] = set()
        for f in self.v1:
            out.update(f.certs)
        for p in self.pairs:
            for s in p.signers:
                out.update(s.cert_chain)
                if s.lineage:
                    out.update(n.cert_sha256 for n in s.lineage)
        return out

    def app_signer_certs(self) -> dict[str, set[str]]:
        """cert -> schemes, for every app-signer certificate in every signature block.

        Source-stamp signers and lineage-only certificates are excluded (§9 G6). For sniffed
        unknown signer blocks every certificate joins the union rule (fail closed).
        """
        out: dict[str, set[str]] = {}
        for f in self.v1:
            for c in f.signer_certs:
                out.setdefault(c, set()).add("v1")
        for p in self.pairs:
            if p.kind == "signature":
                for s in p.signers:
                    if s.signer_cert:
                        out.setdefault(s.signer_cert, set()).add(p.name)
            elif p.kind == "sniffed_signature":
                for s in p.signers:
                    for c in s.cert_chain:
                        out.setdefault(c, set()).add(f"sniffed:{p.id_hex}")
        return out

    def unsigned_pairs(self) -> list[SigBlockPair]:
        return [p for p in self.pairs if p.kind in ("unsigned", "padding")]


class AndroguardInventory(Model):
    error: str | None = None
    v1: list[str] = Field(default_factory=list)
    v2: list[str] = Field(default_factory=list)
    v3: list[str] = Field(default_factory=list)
    v31: list[str] = Field(default_factory=list)

    def all(self) -> set[str]:
        return set(self.v1) | set(self.v2) | set(self.v3) | set(self.v31)


class BrandFacts(Model):
    default_label: str | None = None
    labels: list[str] = Field(default_factory=list)
    icon_hashes: list[str] = Field(default_factory=list)
    icon_paths: list[str] = Field(default_factory=list)
    icon_dhashes: list[str] = Field(default_factory=list)
    icon_resolution_error: str | None = None


class EvaluationFacts(Model):
    sample_sha256: str
    size: int
    expected_package: str | None = None
    collection_error: str | None = None
    intake: IntakeFacts = Field(default_factory=IntakeFacts)
    archive: ArchiveFacts | None = None
    manifest: ManifestFacts | None = None
    structure: StructureFacts | None = None
    verify: VerifyFacts | None = None
    native_inventory: NativeInventory | None = None
    androguard_inventory: AndroguardInventory | None = None
    brand: BrandFacts | None = None


# --------------------------------------------------------------------------------------------
# Evaluation
# --------------------------------------------------------------------------------------------

TrustPath = Literal["T", "R1", "R2", "none"]


class SignerTrust(Model):
    cert_sha256: str
    schemes: list[str] = Field(default_factory=list)
    trust: TrustPath = "none"
    subject: str | None = None
    issuer: str | None = None
    key_algorithm: str | None = None
    key_bits: int | None = None
    known_key: str | None = None
    debug_dn: bool = False


class GateStep(Model):
    gate: str
    status: Literal["pass", "fail", "skip", "info"]
    detail: str


class MemberRef(Model):
    name: str
    sample_sha256: str
    role: str  # base | split | foreign | payload | obb | metadata
    verdict: Verdict | None = None
    package: str | None = None
    split: str | None = None
    size: int = 0
    payload_type: str | None = None


class Evaluation(Model):
    """The verdict object. Its canonical JSON is what ``kloner reverify`` reproduces byte-for-byte."""

    schema_: str = Field(default="kloner.verdict/1", alias="schema")
    sample_sha256: str
    size: int
    format: str | None = None
    package: str | None = None
    version_code: int | None = None
    version_name: str | None = None
    split: str | None = None
    verdict: Verdict
    labels: list[Label] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    explanation: str = ""
    signers: list[SignerTrust] = Field(default_factory=list)
    gate_trace: list[GateStep] = Field(default_factory=list)
    anchor_package: str | None = None
    anchor_record_sha256: str | None = None
    brand_package: str | None = None
    members: list[MemberRef] = Field(default_factory=list)
    kloner_version: str = ""
    apksig_version: str | None = None

    def label_codes(self) -> list[str]:
        return [lab.code for lab in self.labels]

    def has_label(self, prefix: str) -> bool:
        return any(lab.code == prefix or lab.code.startswith(prefix + ":") for lab in self.labels)


# --------------------------------------------------------------------------------------------
# Anchors (§7.6)
# --------------------------------------------------------------------------------------------


class Evidence(Model):
    klass: str = Field(alias="class")
    method: str
    url: str | None = None
    final_url: str | None = None
    file_sha256: str | None = None
    retrieved_utc: str
    observed: str | None = None
    detail: str | None = None


class Identity(Model):
    id: str
    label: str = "current"
    cert_sha256: str
    cert_der_b64: str | None = None
    subject: str | None = None
    issuer: str | None = None
    serial: str | None = None
    not_before: str | None = None
    not_after: str | None = None
    key_algorithm: str | None = None
    key_bits: int | None = None
    role: str = "current"  # current | legacy | additional
    declared_additional: bool = False
    declared_reason: str | None = None
    evidence: list[Evidence] = Field(default_factory=list)


class LineageEntry(Model):
    cert_sha256: str
    capabilities: dict[str, bool] = Field(default_factory=dict)


class ReleaseRef(Model):
    version_code: int
    version_name: str | None = None
    file_sha256: str
    signers: list[str] = Field(default_factory=list)
    provenance: str
    observed_utc: str


class Brand(Model):
    labels: list[str] = Field(default_factory=list)
    brand_labels: list[str] = Field(default_factory=list)
    keywords: list[str] = Field(default_factory=list)
    icon_asset_sha256: list[str] = Field(default_factory=list)
    icon_dhash: list[str] = Field(default_factory=list)


class AnchorDecision(Model):
    utc: str
    action: str
    identity: str | None = None
    reason: str


class Anchor(Model):
    schema_: str = Field(default="kloner.anchor/1", alias="schema")
    package: str
    created_utc: str
    refreshed_utc: str
    identities: list[Identity] = Field(default_factory=list)
    lineage: list[LineageEntry] = Field(default_factory=list)
    release_refs: list[ReleaseRef] = Field(default_factory=list)
    brand: Brand = Field(default_factory=Brand)
    corroboration: str = "USER_ASSERTED"
    decisions: list[AnchorDecision] = Field(default_factory=list)
    record_sha256: str = ""

    def trusted(self) -> set[str]:
        return {i.cert_sha256 for i in self.identities}

    def identity(self, cert: str) -> Identity | None:
        for i in self.identities:
            if i.cert_sha256 == cert:
                return i
        return None


# --------------------------------------------------------------------------------------------
# Acquisition (§8)
# --------------------------------------------------------------------------------------------


class Claimed(Model):
    version_name: str | None = None
    version_code: int | None = None
    md5: str | None = None
    sha1: str | None = None
    sha256: str | None = None
    signer_sha1: str | None = None
    signer_sha256: str | None = None
    signer_owner: str | None = None
    package: str | None = None


class Offer(Model):
    source: str
    store: str | None = None
    package: str | None = None
    label: str | None = None
    claimed: Claimed = Field(default_factory=Claimed)
    download_url: str | None = None
    offer_url: str | None = None
    variant: str | None = None
    file_type: str | None = None
    local_path: str | None = None
    handle: str | None = None  # source-specific opaque fetch handle (e.g. apkeep "pkg@version")


class ClientProfile(Model):
    user_agent: str
    proxy: str | None = None


FetchStatus = Literal["OK", "NO_OFFERS", "BLOCKED", "ERROR"]


class FetchResult(Model):
    status: FetchStatus
    reason: str | None = None
    sample_sha256: str | None = None
    size: int | None = None
    final_url: str | None = None
    http_status: int | None = None
    content_type: str | None = None
    retrieved_utc: str | None = None
    client_profile: ClientProfile | None = None
    tls_verified: bool | None = None


class Sighting(Model):
    sample_sha256: str
    size: int
    source: str
    store: str | None = None
    offer_url: str | None = None
    download_url: str | None = None
    final_url: str | None = None
    http_status: int | None = None
    content_type: str | None = None
    retrieved_utc: str
    client_profile: ClientProfile | None = None
    claimed: Claimed = Field(default_factory=Claimed)
    tls_verified: bool | None = None
    labels: list[str] = Field(default_factory=list)


SourceRunStatus = Literal["OK", "NO_OFFERS", "BLOCKED", "ERROR", "DISABLED", "SKIPPED"]


class SourceStatus(Model):
    source: str
    status: SourceRunStatus
    reason: str | None = None
    offers: int = 0
    fetched: int = 0
    failed: int = 0
    stores: list[str] = Field(default_factory=list)
