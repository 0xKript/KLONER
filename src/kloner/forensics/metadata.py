"""Metadata cross-check (§10.8): what a source claims versus what the file is.

Hashes are compared in the source's own algorithm (MD5/SHA-1/SHA-256); signers too (Aptoide
publishes the SHA-1 of the signing certificate). These weak digests appear only here (INV-9).
"""

from __future__ import annotations

import base64
from pathlib import Path

from kloner.models import Claimed, Evaluation, EvaluationFacts
from kloner.util.hashing import cert_digests, third_party_digests


def cross_check(claimed: Claimed, ev: Evaluation, facts: EvaluationFacts | None, sample_path: Path) -> list[str]:
    """Mismatches between a source's claims and the file (an empty list means consistent)."""
    out: list[str] = []
    if claimed.version_code is not None and ev.version_code is not None and claimed.version_code != ev.version_code:
        out.append(f"versionCode claimed {claimed.version_code}, file has {ev.version_code}")
    if claimed.version_name and ev.version_name and claimed.version_name != ev.version_name:
        out.append(f"versionName claimed {claimed.version_name!r}, file has {ev.version_name!r}")
    if claimed.package and ev.package and claimed.package != ev.package:
        out.append(f"package claimed {claimed.package}, file is {ev.package}")
    if claimed.md5 or claimed.sha1 or claimed.sha256:
        d = third_party_digests(sample_path)
        for alg in ("md5", "sha1", "sha256"):
            want = getattr(claimed, alg)
            if want and want.lower() != d[alg]:
                out.append(f"{alg.upper()} claimed {want.lower()}, file has {d[alg]}")
    if claimed.signer_sha1 and facts is not None and facts.native_inventory is not None and ev.signers:
        certs = facts.native_inventory.certs
        sha1s = {
            cert_digests(base64.b64decode(certs[s.cert_sha256].der_b64))["sha1"]
            for s in ev.signers
            if s.cert_sha256 in certs
        }
        if sha1s and claimed.signer_sha1.lower() not in sha1s:
            out.append(
                f"signer SHA-1 claimed {claimed.signer_sha1.lower()}, file signers have {', '.join(sorted(sha1s))}"
            )
    if (
        claimed.signer_sha256
        and ev.signers
        and claimed.signer_sha256.lower() not in {s.cert_sha256 for s in ev.signers}
    ):
        out.append(f"signer SHA-256 claimed {claimed.signer_sha256.lower()}, not among the file's signers")
    return out
