"""Native proof-of-rotation (signing certificate lineage) parsing and verification (§6.4, §9 G6).

Layout, confirmed against AOSP apksig ``V3SigningCertificateLineage.readSigningCertificateLineage``
(see docs/DECISIONS.md), little endian:

    uint32 version (= 1)
    sequence of uint32-length-prefixed nodes:
        uint32-length-prefixed signed data:
            uint32-length-prefixed X.509 certificate (DER)
            uint32 signature algorithm ID (must equal the previous node's "next" algorithm)
        uint32 flags (capabilities granted to this certificate)
        uint32 signature algorithm ID (used by this node's key to sign the next node)
        uint32-length-prefixed signature over the signed data, made by the previous node's key

The first node carries no meaningful signature. Node i (i >= 1) must verify under node i-1's
public key with node i-1's "next" algorithm.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, padding, rsa

from kloner.verify.certs import load_public_key

LINEAGE_VERSION = 1

CAP_INSTALLED_DATA = 1
CAP_SHARED_UID = 2
CAP_PERMISSION = 4
CAP_ROLLBACK = 8
CAP_AUTH = 16

# Signature algorithm IDs (AOSP apksig SignatureAlgorithm).
SIG_ALGORITHMS: dict[int, str] = {
    0x0101: "RSA_PSS_WITH_SHA256",
    0x0102: "RSA_PSS_WITH_SHA512",
    0x0103: "RSA_PKCS1_V1_5_WITH_SHA256",
    0x0104: "RSA_PKCS1_V1_5_WITH_SHA512",
    0x0201: "ECDSA_WITH_SHA256",
    0x0202: "ECDSA_WITH_SHA512",
    0x0301: "DSA_WITH_SHA256",
    0x0421: "VERITY_RSA_PKCS1_V1_5_WITH_SHA256",
    0x0423: "VERITY_ECDSA_WITH_SHA256",
    0x0425: "VERITY_DSA_WITH_SHA256",
}


class LineageFormatError(ValueError):
    pass


@dataclass(frozen=True)
class RawNode:
    cert_der: bytes
    cert_sha256: str
    signed_data: bytes
    signed_sig_alg: int
    flags: int
    next_sig_alg: int
    signature: bytes


def capabilities(flags: int) -> dict[str, bool]:
    return {
        "installed_data": bool(flags & CAP_INSTALLED_DATA),
        "shared_uid": bool(flags & CAP_SHARED_UID),
        "permission": bool(flags & CAP_PERMISSION),
        "rollback": bool(flags & CAP_ROLLBACK),
        "auth": bool(flags & CAP_AUTH),
    }


def _take(buf: bytes, pos: int, n: int) -> tuple[bytes, int]:
    if n < 0 or pos + n > len(buf):
        raise LineageFormatError("length prefix exceeds the available bytes")
    return buf[pos : pos + n], pos + n


def _u32(buf: bytes, pos: int) -> tuple[int, int]:
    raw, pos = _take(buf, pos, 4)
    return int(struct.unpack("<I", raw)[0]), pos


def _prefixed(buf: bytes, pos: int) -> tuple[bytes, int]:
    n, pos = _u32(buf, pos)
    return _take(buf, pos, n)


def parse_lineage(value: bytes, max_nodes: int = 64) -> list[RawNode]:
    version, pos = _u32(value, 0)
    if version != LINEAGE_VERSION:
        raise LineageFormatError(f"unknown lineage version {version}")
    nodes: list[RawNode] = []
    while pos < len(value):
        if len(nodes) >= max_nodes:
            raise LineageFormatError("too many lineage nodes")
        node, pos = _prefixed(value, pos)
        signed, npos = _prefixed(node, 0)
        flags, npos = _u32(node, npos)
        next_alg, npos = _u32(node, npos)
        signature, npos = _prefixed(node, npos)
        cert, spos = _prefixed(signed, 0)
        signed_alg, spos = _u32(signed, spos)
        nodes.append(RawNode(cert, hashlib.sha256(cert).hexdigest(), signed, signed_alg, flags, next_alg, signature))
    if not nodes:
        raise LineageFormatError("empty lineage")
    return nodes


def verify_signature(public_key: object, alg: int, data: bytes, signature: bytes) -> bool:
    """Verify ``signature`` over ``data`` with an apksig signature algorithm ID."""
    try:
        if alg in (0x0103, 0x0421) and isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
        elif alg == 0x0104 and isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(signature, data, padding.PKCS1v15(), hashes.SHA512())
        elif alg == 0x0101 and isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                signature, data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256()
            )
        elif alg == 0x0102 and isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                signature, data, padding.PSS(mgf=padding.MGF1(hashes.SHA512()), salt_length=64), hashes.SHA512()
            )
        elif alg in (0x0201, 0x0423) and isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        elif alg == 0x0202 and isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signature, data, ec.ECDSA(hashes.SHA512()))
        elif alg in (0x0301, 0x0425) and isinstance(public_key, dsa.DSAPublicKey):
            public_key.verify(signature, data, hashes.SHA256())
        else:
            return False
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True


@dataclass(frozen=True)
class VerifiedNode:
    cert_der: bytes
    cert_sha256: str
    flags: int
    signed_sig_alg: int
    next_sig_alg: int
    signature_valid: bool | None


def verify_lineage(nodes: list[RawNode]) -> list[VerifiedNode]:
    """Check each node against its predecessor exactly as apksig does; never raises."""
    out: list[VerifiedNode] = []
    seen: set[str] = set()
    prev: RawNode | None = None
    for node in nodes:
        valid: bool | None
        if prev is None:
            valid = None
        else:
            key = load_public_key(prev.cert_der)
            valid = (
                key is not None
                and node.signed_sig_alg == prev.next_sig_alg
                and verify_signature(key, prev.next_sig_alg, node.signed_data, node.signature)
            )
        if node.cert_sha256 in seen:
            valid = False
        seen.add(node.cert_sha256)
        out.append(
            VerifiedNode(node.cert_der, node.cert_sha256, node.flags, node.signed_sig_alg, node.next_sig_alg, valid)
        )
        prev = node
    return out
