"""X.509 certificate facts. Identity is SHA-256 over the DER encoding (INV-9)."""

from __future__ import annotations

import base64
from datetime import UTC

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import NameOID

from kloner.models import CertInfo
from kloner.util.hashing import cert_digests

DEBUG_DN = {"CN": "Android Debug", "O": "Android", "C": "US"}


def _attrs(name: x509.Name) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for attr in name:
        key = {
            NameOID.COMMON_NAME: "CN",
            NameOID.ORGANIZATION_NAME: "O",
            NameOID.COUNTRY_NAME: "C",
            NameOID.ORGANIZATIONAL_UNIT_NAME: "OU",
            NameOID.LOCALITY_NAME: "L",
            NameOID.STATE_OR_PROVINCE_NAME: "ST",
        }.get(attr.oid, attr.oid.dotted_string)
        value = attr.value if isinstance(attr.value, str) else attr.value.hex()
        out.setdefault(key, []).append(value)
    return out


def is_debug_dn(name: x509.Name) -> bool:
    """Subject exactly CN=Android Debug, O=Android, C=US (a label only: a DN is self-asserted)."""
    attrs = _attrs(name)
    return set(attrs) == set(DEBUG_DN) and all(attrs[k] == [v] for k, v in DEBUG_DN.items())


def _key(cert: x509.Certificate) -> tuple[str, int | None]:
    try:
        key = cert.public_key()
    except Exception:
        return "unknown", None
    if isinstance(key, rsa.RSAPublicKey):
        return "RSA", key.key_size
    if isinstance(key, ec.EllipticCurvePublicKey):
        return "EC", key.curve.key_size
    if isinstance(key, dsa.DSAPublicKey):
        return "DSA", key.key_size
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "Ed25519", 256
    if isinstance(key, ed448.Ed448PublicKey):
        return "Ed448", 456
    return type(key).__name__, None


def cert_info(der: bytes) -> CertInfo:
    """Describe a certificate. Never raises: unparseable certificates still get their digests."""
    d = cert_digests(der)
    b64 = base64.b64encode(der).decode("ascii")
    # cryptography parses lazily: loading can succeed and a field access fail later, so every field
    # is read inside the guard (found by tests/fuzz).
    try:
        cert = x509.load_der_x509_certificate(der)
        alg, bits = _key(cert)
        try:
            sig_hash = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else None
        except Exception:
            sig_hash = None
        return CertInfo(
            sha256=d["sha256"],
            sha1=d["sha1"],
            md5=d["md5"],
            subject=cert.subject.rfc4514_string(),
            issuer=cert.issuer.rfc4514_string(),
            serial=format(cert.serial_number, "x"),
            not_before=cert.not_valid_before_utc.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            not_after=cert.not_valid_after_utc.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            key_algorithm=alg,
            key_bits=bits,
            signature_hash=sig_hash,
            debug_dn=is_debug_dn(cert.subject),
            der_b64=b64,
        )
    except Exception:
        return _cert_info_asn1(der, d, b64)


def _cert_info_asn1(der: bytes, d: dict[str, str], b64: str) -> CertInfo:
    """Fallback for certificates the strict DER parser rejects (old Android signing certs exist)."""
    try:
        from asn1crypto import x509 as ax509

        c = ax509.Certificate.load(der)
        subject = c.subject.human_friendly
        issuer = c.issuer.human_friendly
        serial = format(int(c.serial_number), "x")
        algo = str(c.public_key.algorithm).upper()
        bits = int(c.public_key.bit_size)
        debug = dict(c.subject.native.items()) == {
            "common_name": "Android Debug",
            "organization_name": "Android",
            "country_name": "US",
        }
        nb = c["tbs_certificate"]["validity"]["not_before"].native
        na = c["tbs_certificate"]["validity"]["not_after"].native
        return CertInfo(
            sha256=d["sha256"],
            sha1=d["sha1"],
            md5=d["md5"],
            subject=subject,
            issuer=issuer,
            serial=serial,
            not_before=nb.strftime("%Y-%m-%dT%H:%M:%SZ") if nb else None,
            not_after=na.strftime("%Y-%m-%dT%H:%M:%SZ") if na else None,
            key_algorithm=algo,
            key_bits=bits,
            signature_hash=None,
            debug_dn=debug,
            der_b64=b64,
        )
    except Exception:
        return CertInfo(
            sha256=d["sha256"],
            sha1=d["sha1"],
            md5=d["md5"],
            subject="<unparseable certificate>",
            issuer="<unparseable certificate>",
            serial="",
            key_algorithm="unknown",
            der_b64=b64,
        )


def load_public_key(der: bytes) -> object | None:
    try:
        return x509.load_der_x509_certificate(der).public_key()
    except Exception:
        return None


def is_x509(der: bytes) -> bool:
    try:
        cert = x509.load_der_x509_certificate(der)
        cert.subject.rfc4514_string()  # force the lazy parser through the fields
        cert.issuer.rfc4514_string()
        return True
    except Exception:
        try:
            from asn1crypto import x509 as ax509

            ax509.Certificate.load(der).native  # noqa: B018 - forces a full parse
            return True
        except Exception:
            return False
