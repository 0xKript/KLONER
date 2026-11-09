"""Static-facts worker (§16.3): every hostile-file parser runs here, in a separate bounded process.

Protocol: one JSON request on stdin, one JSON response on stdout.

    {"op": "facts", "path": "...", "sha256": "...", "expected_package": null,
     "aapt2": "...", "limits": {...}, "home": "..."}

The parent supervises the process with a timeout and, on POSIX, address-space and CPU limits.
"""

from __future__ import annotations

import json
import sys
import traceback
from dataclasses import asdict, fields
from pathlib import Path
from typing import Any

from kloner.container.detect import KNOWN_METADATA, detect, sniff_type
from kloner.container.zipstrict import (
    ZipArchive,
    ZipFailure,
    entry_head,
    open_archive,
    structural_gate,
    verify_crcs,
)
from kloner.models import (
    AndroguardInventory,
    ArchiveFacts,
    BrandFacts,
    CertInfo,
    EvaluationFacts,
    IntakeFacts,
    ManifestView,
)
from kloner.util.limits import Limits

INTAKE_REASONS = frozenset({"NOT_ZIP", "EMPTY", "TOO_LARGE", "ENCRYPTED"})


def limits_to_dict(limits: Limits) -> dict[str, int]:
    return asdict(limits)


def limits_from_dict(data: dict[str, Any]) -> Limits:
    known = {f.name for f in fields(Limits)}
    return Limits(**{k: int(v) for k, v in data.items() if k in known})


def apk_facts(path: Path, facts: EvaluationFacts, archive: ZipArchive, aapt2: Path, limits: Limits) -> EvaluationFacts:
    from kloner.impersonation.icons import resolve_icon_assets
    from kloner.impersonation.labels import extract_labels
    from kloner.util.logging import quiet_third_party
    from kloner.verify.inventory import androguard_inventory, native_inventory
    from kloner.verify.manifest import aapt2_view, androguard_view, manifest_facts

    native, block = native_inventory(archive, limits)
    facts.native_inventory = native
    facts.structure = structural_gate(archive, (block.start, block.end) if block else None)

    errors: list[str] = []
    apk: Any = None
    ag_view: ManifestView | None = None
    try:
        quiet_third_party()
        from androguard.core.apk import APK

        apk = APK(str(path))
        ag_view = androguard_view(apk)
    except Exception as e:
        errors.append(f"androguard: {type(e).__name__}: {e}")
    aapt_view: ManifestView | None = None
    try:
        aapt_view = aapt2_view(path, aapt2)
    except Exception as e:
        errors.append(f"aapt2: {e}")
    facts.manifest = manifest_facts(ag_view, aapt_view, errors)

    if apk is not None:
        scratch: dict[str, CertInfo] = {}
        facts.androguard_inventory = androguard_inventory(apk, scratch)
        default_label, labels = extract_labels(apk)
        icon_paths, icon_hashes, icon_dhashes, icon_error = resolve_icon_assets(apk, archive)
        facts.brand = BrandFacts(
            default_label=default_label,
            labels=labels,
            icon_hashes=icon_hashes,
            icon_paths=icon_paths,
            icon_dhashes=icon_dhashes,
            icon_resolution_error=icon_error,
        )
    else:
        facts.androguard_inventory = AndroguardInventory(error="androguard could not open the APK")
    return facts


def bundle_members(archive: ZipArchive, home: Path, limits: Limits) -> list[dict[str, Any]]:
    """Copy APK and payload members into the quarantine by content hash; hash OBB files in place."""
    import hashlib

    from kloner.acquire.quarantine import Quarantine
    from kloner.container.zipstrict import stream_entry

    if len(archive.entries) > limits.max_bundle_members:
        raise ZipFailure("UNSAFE_ARCHIVE", f"{len(archive.entries)} bundle members exceed the limit")
    q = Quarantine(home)
    out: list[dict[str, Any]] = []
    for e in archive.entries:
        if e.is_dir:
            continue
        name = e.name
        typ = sniff_type(entry_head(archive, e, 8))
        if name.startswith("Android/obb/"):
            role = "obb"
        elif typ == "zip":
            role = "apk"
        elif name in KNOWN_METADATA:
            role = "metadata"
        else:
            role = "payload"
        rec: dict[str, Any] = {"name": name, "type": typ, "role_hint": role, "size": e.central.uncompressed_size}
        if role in ("apk", "payload"):
            with q.sink(limits.max_member_bytes) as s, archive.path.open("rb") as f:
                for block in stream_entry(f, e, e.central.uncompressed_size):
                    s.write(block)
            rec["sha256"], rec["size"] = q.finalize(s)
        else:
            h = hashlib.sha256()
            with archive.path.open("rb") as f:
                for block in stream_entry(f, e, e.central.uncompressed_size):
                    h.update(block)
            rec["sha256"] = h.hexdigest()
        out.append(rec)
    return out


def collect(req: dict[str, Any]) -> dict[str, Any]:
    path = Path(req["path"])
    limits = limits_from_dict(req.get("limits", {}))
    size = path.stat().st_size
    facts = EvaluationFacts(sample_sha256=req["sha256"], size=size, expected_package=req.get("expected_package"))
    try:
        archive = open_archive(path, limits)
    except ZipFailure as e:
        if e.reason in INTAKE_REASONS:
            facts.intake = IntakeFacts(failed=True, reason=e.reason, detail=e.detail)
        else:
            facts.intake = IntakeFacts(format="zip")
            facts.archive = ArchiveFacts(failed=True, reason=e.reason, detail=e.detail)
        return {"ok": True, "facts": facts.model_dump(mode="json", by_alias=True), "members": None}

    det = detect(archive)
    if det.format == "aab":
        facts.intake = IntakeFacts(
            failed=True, reason="AAB_NOT_DISTRIBUTABLE", detail="Android App Bundle (BundleConfig.pb)", format="aab"
        )
        return {"ok": True, "facts": facts.model_dump(mode="json", by_alias=True), "members": None}
    if det.format == "zip":
        facts.intake = IntakeFacts(
            failed=True,
            reason="NOT_ANDROID",
            detail="ZIP archive without an Android manifest or APK members",
            format="zip",
        )
        return {"ok": True, "facts": facts.model_dump(mode="json", by_alias=True), "members": None}

    facts.intake = IntakeFacts(format=det.format, bundle_kind=det.bundle_kind)
    try:
        verify_crcs(archive)
    except ZipFailure as e:
        facts.archive = ArchiveFacts(failed=True, reason=e.reason, detail=e.detail)
        return {"ok": True, "facts": facts.model_dump(mode="json", by_alias=True), "members": None}
    facts.archive = ArchiveFacts(entry_count=len(archive.entries), total_uncompressed=archive.total_uncompressed)

    members = None
    if det.format == "bundle":
        try:
            members = bundle_members(archive, Path(req["home"]), limits)
        except ZipFailure as e:
            facts.archive = ArchiveFacts(failed=True, reason=e.reason, detail=e.detail)
            return {"ok": True, "facts": facts.model_dump(mode="json", by_alias=True), "members": None}
    else:
        facts = apk_facts(path, facts, archive, Path(req["aapt2"]), limits)
    return {"ok": True, "facts": facts.model_dump(mode="json", by_alias=True), "members": members}


def main() -> int:
    raw = sys.stdin.buffer.read(1 << 20)
    try:
        req = json.loads(raw)
        if req.get("op") == "facts":
            resp = collect(req)
        elif req.get("op") == "forensics":
            from kloner.forensics.extract import extract_view

            resp = {"ok": True, "view": extract_view(req)}
        else:
            resp = {"ok": False, "error": f"unknown op {req.get('op')!r}"}
    except Exception as e:
        resp = {"ok": False, "error": f"{type(e).__name__}: {e}", "trace": traceback.format_exc()[-4000:]}
    sys.stdout.write(json.dumps(resp))
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
