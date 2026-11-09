"""Signer inventories and the engine-agreement rules (§9 G6)."""

from __future__ import annotations

from typing import Any

from kloner.container.zipstrict import ZipArchive
from kloner.models import AndroguardInventory, CertInfo, NativeInventory, VerifyRange
from kloner.util.hashing import sha256_bytes
from kloner.util.limits import Limits
from kloner.verify import sigblock
from kloner.verify.certs import cert_info
from kloner.verify.v1pkcs7 import inventory_v1


def native_inventory(archive: ZipArchive, limits: Limits) -> tuple[NativeInventory, sigblock.SigningBlock | None]:
    certs: dict[str, CertInfo] = {}
    try:
        block = sigblock.locate(archive, limits)
    except sigblock.SigBlockFormatError as e:
        return NativeInventory(error=f"APK Signing Block: {e}"), None
    pairs = sigblock.inventory_pairs(block, certs, limits) if block else []
    try:
        v1 = inventory_v1(archive, certs, limits)
    except ValueError as e:
        return NativeInventory(error=f"v1 signatures: {e}"), block
    return (
        NativeInventory(
            has_signing_block=block is not None,
            signing_block_offset=block.start if block else None,
            signing_block_size=(block.end - block.start) if block else None,
            pairs=pairs,
            v1=v1,
            certs=certs,
        ),
        block,
    )


def androguard_inventory(apk: Any, certs: dict[str, CertInfo]) -> AndroguardInventory:
    try:
        v1 = []
        for name in apk.get_signature_names():
            der = apk.get_certificate_der(name)
            if der:
                v1.append(sha256_bytes(der))
                certs.setdefault(v1[-1], cert_info(der))
        v2 = [sha256_bytes(d) for d in apk.get_certificates_der_v2()]
        v3 = [sha256_bytes(d) for d in apk.get_certificates_der_v3()]
        v31 = [sha256_bytes(d) for d in apk.get_certificates_der_v31()]
    except Exception as e:
        return AndroguardInventory(error=f"{type(e).__name__}: {e}")
    return AndroguardInventory(v1=sorted(set(v1)), v2=sorted(set(v2)), v3=sorted(set(v3)), v31=sorted(set(v31)))


def disagreements(v: VerifyRange, native: NativeInventory | None, ag: AndroguardInventory | None) -> list[str]:
    """Rules (a)-(d) of §9 G6. An empty list means the engines agree."""
    out: list[str] = []
    if native is None or native.error:
        out.append(f"native inventory unavailable: {native.error if native else 'missing'}")
        return out
    if ag is None or ag.error:
        out.append(f"androguard inventory unavailable: {ag.error if ag else 'missing'}")
    for p in native.pairs:
        if p.kind == "signature" and p.parse_error:
            out.append(f"native parser rejected the {p.name} block: {p.parse_error}")
    native_all = native.all_cert_digests()
    for s in v.signers:
        if s.cert_sha256 and s.cert_sha256 not in native_all:
            out.append(f"(a) apksig {s.scheme} signer {s.cert_sha256} absent from the native inventory")
    if ag is not None and not ag.error:
        for c in sorted(ag.all() - native_all):
            out.append(f"(b) androguard certificate {c} absent from the native inventory")
    for scheme, ok in sorted(v.schemes.items()):
        if ok and scheme != "v4" and not native.has_scheme(scheme):
            out.append(f"(c) apksig verified {scheme} but no {scheme} signature exists natively")
    for s in v.signers:
        if s.scheme not in ("v3", "v31"):
            continue
        blocks = native.scheme_pairs(s.scheme)
        nsigner = None
        if blocks and s.index < len(blocks[0].signers):
            nsigner = blocks[0].signers[s.index]
        apk_lineage = [c.cert_sha256 for c in (s.lineage or [])]
        nat_lineage = [n.cert_sha256 for n in (nsigner.lineage or [])] if nsigner else []
        if nsigner is None:
            out.append(f"(d) no native {s.scheme} signer #{s.index}")
        elif apk_lineage != nat_lineage:
            out.append(f"(d) {s.scheme} signer #{s.index} lineage differs: apksig={apk_lineage} native={nat_lineage}")
        elif nsigner.lineage and any(n.signature_valid is False for n in nsigner.lineage):
            out.append(f"(d) {s.scheme} signer #{s.index} lineage node signature fails native verification")
    return out
