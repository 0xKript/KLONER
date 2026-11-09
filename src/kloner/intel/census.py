"""Signer, payload and source census (§12): correlations across runs and packages."""

from __future__ import annotations

from typing import Any

from kloner.intel.db import IntelDB
from kloner.models import HOSTILE, Evaluation
from kloner.util.fingerprints import short_fp


def correlate(db: IntelDB, ev: Evaluation, finding: dict[str, Any] | None) -> tuple[list[str], list[dict[str, Any]]]:
    """Intel labels (SHARED_FOREIGN_SIGNER, SHARED_PAYLOAD) and correlation lines for one hostile sample."""
    labels: list[str] = []
    lines: list[dict[str, Any]] = []
    if ev.verdict not in HOSTILE:
        return labels, lines
    for s in ev.signers:
        if s.trust != "none":
            continue
        pkgs = db.foreign_signer_packages(s.cert_sha256, ev.sample_sha256)
        if pkgs:
            labels.append("SHARED_FOREIGN_SIGNER")
            lines.append(
                {
                    "kind": "SHARED_FOREIGN_SIGNER",
                    "cert_sha256": s.cert_sha256,
                    "packages": pkgs,
                    "text": f"Forger key {short_fp(s.cert_sha256)} also signed hostile copies of: {', '.join(pkgs)}",
                }
            )
    payload = (finding or {}).get("payload")
    if payload:
        pkgs = db.payload_packages(payload["payload_id"], payload["shape_id"], ev.sample_sha256)
        if pkgs:
            labels.append("SHARED_PAYLOAD")
            lines.append(
                {
                    "kind": "SHARED_PAYLOAD",
                    "payload_id": payload["payload_id"],
                    "packages": pkgs,
                    "text": f"Payload P-{payload['payload_id'][:4]}… also appears in: {', '.join(pkgs)}",
                }
            )
    return sorted(set(labels)), lines
