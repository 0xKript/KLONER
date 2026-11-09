"""v1 (JAR) signature inventory: every META-INF/*.RSA|*.DSA|*.EC PKCS#7 SignedData (§9 G6 step 5)."""

from __future__ import annotations

from asn1crypto import cms
from asn1crypto import x509 as ax509

from kloner.container.zipstrict import ZipArchive, ZipFailure, read_entry
from kloner.models import CertInfo, V1SignatureFile
from kloner.util.limits import Limits
from kloner.verify.certs import cert_info

SIGNATURE_EXTENSIONS = (".RSA", ".DSA", ".EC")


def is_v1_signature_name(name: str) -> bool:
    """META-INF/<name>.RSA|DSA|EC directly under META-INF (case-insensitive: a superset is safer)."""
    if not name.upper().startswith("META-INF/"):
        return False
    rest = name[len("META-INF/") :]
    return "/" not in rest and rest.upper().endswith(SIGNATURE_EXTENSIONS)


def parse_signed_data(data: bytes) -> tuple[list[bytes], list[bytes]]:
    """Return (all certificate DERs, signer certificate DERs). Raises ValueError on malformed input."""
    ci = cms.ContentInfo.load(data)
    if ci["content_type"].native != "signed_data":
        raise ValueError(f"content type is {ci['content_type'].native!r}, not signed_data")
    sd = ci["content"]
    certs: list[ax509.Certificate] = []
    for choice in sd["certificates"] or []:
        if choice.name == "certificate":
            certs.append(choice.chosen)
    signer_ders: list[bytes] = []
    for si in sd["signer_infos"]:
        sid = si["sid"]
        match: ax509.Certificate | None = None
        if sid.name == "issuer_and_serial_number":
            issuer = sid.chosen["issuer"]
            serial = sid.chosen["serial_number"].native
            for c in certs:
                if c.serial_number == serial and (c.issuer == issuer or c.issuer.dump() == issuer.dump()):
                    match = c
                    break
        elif sid.name == "subject_key_identifier":
            ski = sid.chosen.native
            for c in certs:
                if c.key_identifier == ski:
                    match = c
                    break
        if match is not None:
            signer_ders.append(match.dump())
    return [c.dump() for c in certs], signer_ders


def inventory_v1(archive: ZipArchive, certs: dict[str, CertInfo], limits: Limits) -> list[V1SignatureFile]:
    out: list[V1SignatureFile] = []
    sig_entries = [e for e in archive.entries if is_v1_signature_name(e.name)]
    if len(sig_entries) > limits.max_v1_signature_files:
        raise ValueError(f"{len(sig_entries)} v1 signature files exceed the limit")
    for e in sig_entries:
        rec = V1SignatureFile(name=e.name)
        try:
            data = read_entry(archive, e, limits.max_v1_signature_bytes)
            all_der, signer_der = parse_signed_data(data)
        except (ValueError, TypeError, KeyError, ZipFailure) as exc:
            rec.parse_error = f"{type(exc).__name__}: {exc}"
            out.append(rec)
            continue
        for der in all_der:
            info = cert_info(der)
            certs.setdefault(info.sha256, info)
            rec.certs.append(info.sha256)
        for der in signer_der:
            info = cert_info(der)
            certs.setdefault(info.sha256, info)
            if info.sha256 not in rec.signer_certs:
                rec.signer_certs.append(info.sha256)
        out.append(rec)
    return out
