"""Anchor hygiene (§7.5): applied on add, refresh and import."""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from kloner.models import CertInfo, Identity
from kloner.util.fingerprints import short_fp


class HygieneError(Exception):
    """Exit code 3: the evidence would create an unsafe anchor."""


def check(identities: Iterable[Identity], known_keys: Mapping[str, str], infos: Mapping[str, CertInfo]) -> list[str]:
    """Raise HygieneError for public/test keys; return warnings and information notes."""
    notes: list[str] = []
    for ident in identities:
        name = known_keys.get(ident.cert_sha256)
        if name:
            raise HygieneError(
                f"identity {short_fp(ident.cert_sha256)} is the publicly known key {name}; "
                "an anchor must never trust a public or test key"
            )
        info = infos.get(ident.cert_sha256)
        if info is None:
            continue
        if info.debug_dn:
            notes.append(f"warning: {short_fp(info.sha256)} uses the Android debug subject DN ({info.subject})")
        if info.key_algorithm == "RSA" and info.key_bits is not None and info.key_bits < 2048:
            notes.append(f"info: {short_fp(info.sha256)} is RSA-{info.key_bits} (weak, recorded for information only)")
        if info.signature_hash == "sha1":
            notes.append(f"info: {short_fp(info.sha256)} certificate is signed with SHA-1 (information only)")
    return notes
