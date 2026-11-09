"""Label registry (§6.2): code -> category, severity, explanation template.

A label characterizes a result. It never changes a verdict unless §6.3 or §6.5 says so.
"""

from __future__ import annotations

from typing import Any

from kloner.models import Label, Severity

LABELS: dict[str, tuple[str, Severity, str]] = {
    # Identity & provenance
    "LEGACY_KEY": ("identity", "info", "Signed by a legacy key of the official lineage."),
    "ROTATED_KEY": ("identity", "info", "Signed by a key admitted through proof-of-rotation (R1/R2)."),
    "SECONDARY_IDENTITY": ("identity", "info", "Signed by an explicitly declared additional identity."),
    "PLAY_SOURCE_STAMP": ("identity", "info", "Carries a valid source stamp (stamp signer recorded)."),
    "SOURCE_STAMP_INVALID": ("identity", "notice", "Carries a source stamp that does not verify."),
    "AHEAD_OF_OFFICIAL": ("identity", "notice", "versionCode is above every strong-provenance release reference."),
    "OUTDATED": ("identity", "info", "versionCode is below the latest official reference."),
    "LEGACY_KEY_ON_NEW_BUILD": (
        "identity",
        "alert",
        "Only a superseded key signed a build at or above the rotation point.",
    ),
    "LEGACY_PLATFORM_INCOMPATIBLE": (
        "identity",
        "info",
        "Signatures verify for API 24+ but not for every declared older platform.",
    ),
    "V1_ONLY": ("identity", "notice", "Only the v1 (JAR) scheme protects this APK; ZIP metadata is unsigned."),
    "SAME_VENDOR": ("identity", "info", "Signed by the official identity of the expected package (a sibling app)."),
    # Forgery characterization
    "KNOWN_PUBLIC_KEY": ("forgery", "alert", "Signed with a publicly known test/platform key."),
    "DEBUG_DN": ("forgery", "notice", "Signer certificate uses the Android debug subject DN."),
    "MIXED_SIGNERS": ("forgery", "alert", "Trusted and foreign signers appear in the same file."),
    "UNKNOWN_SIGNER_BLOCK": ("forgery", "alert", "A signer block under an ID apksig does not recognize."),
    "REPACKAGED": ("forgery", "notice", "Heuristic: most of the official code is present (class overlap)."),
    "IMPOSTOR": ("forgery", "notice", "Heuristic: little of the official code is present (class overlap)."),
    "SHARED_FOREIGN_SIGNER": ("forgery", "alert", "The foreign key also signed other hostile copies."),
    "SHARED_PAYLOAD": ("forgery", "alert", "The injected payload also appears in other hostile copies."),
    # Tamper characterization
    "CONTENT_MODIFIED_UNDER_OFFICIAL_SIGNATURE": (
        "tamper",
        "alert",
        "The official certificate is present but does not validate this content.",
    ),
    "SIGNATURE_INVALID": ("tamper", "alert", "The signatures do not verify."),
    "POLYGLOT": ("tamper", "alert", "Data precedes the ZIP structure (Janus class, CVE-2017-13156)."),
    "ZIP_AMBIGUITY": ("tamper", "alert", "ZIP structure readable in more than one way (Master Key class)."),
    "SCHEME_STRIPPED": ("tamper", "alert", "A stronger signature scheme was removed (stripping protection)."),
    # Container
    "BUNDLE_INCONSISTENT": ("container", "alert", "Bundle members disagree: some are genuine, some are not."),
    "UNEXPECTED_MEMBER": ("container", "alert", "The bundle carries an APK of another package."),
    "UNEXPECTED_PAYLOAD": ("container", "notice", "The bundle carries files that are neither APKs nor metadata."),
    "UNVERIFIABLE_OBB": ("container", "info", "Expansion (OBB) files are not covered by APK signatures."),
    "INCOMPLETE_BUNDLE": ("container", "notice", "The bundle has no base APK."),
    "SPLIT_SIGNER_DIVERGENCE": ("container", "alert", "Bundle members of the package have different signer sets."),
    # Unsigned regions & structure
    "UNSIGNED_BLOCK_DATA": ("unsigned", "notice", "Unsigned data inside the APK Signing Block."),
    "UNREFERENCED_BYTES": ("unsigned", "notice", "Non-zero bytes not referenced by the ZIP structure."),
    "HOSTILE_ENTRY_NAME": ("unsigned", "notice", "Entry names with absolute paths, '..' or control characters."),
    # Source & transport
    "METADATA_MISMATCH": ("source", "notice", "The source's claims differ from the file."),
    "UNSTABLE_SOURCE": ("source", "alert", "The source served different bytes for the same offer."),
    "INSECURE_TRANSPORT": ("source", "notice", "Fetched over plain HTTP."),
    # Impersonation evidence
    "EXACT_ICON": ("impersonation", "alert", "A launcher icon asset is byte-identical to an official one."),
    "EXACT_LABEL": ("impersonation", "alert", "The label equals a declared brand label."),
    "LOOKALIKE": ("impersonation", "notice", "Heuristic similarity to the brand (score attached)."),
    "ICON_UNRESOLVED": ("impersonation", "info", "Launcher icons could not be resolved."),
    # Engine
    "VERIFIER_WARNING": ("engine", "info", "apksig reported a warning."),
    "FORENSICS_INCOMPLETE": ("engine", "notice", "Forensic analysis did not complete; the verdict is unaffected."),
    "NO_REFERENCE": ("engine", "info", "No genuine reference was available for a forensic diff."),
    "CROSS_VERSION_DIFF": ("engine", "info", "The forensic diff uses a reference of another version."),
}


def make_label(code: str, detail: str | None = None, **evidence: Any) -> Label:
    base = code.split(":", 1)[0]
    category, severity, _template = LABELS[base]
    return Label(code=code, category=category, severity=severity, detail=detail, evidence=evidence)


def describe(code: str) -> str:
    return LABELS[code.split(":", 1)[0]][2]
