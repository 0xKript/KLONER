"""Canonical JSON report (§15.2): schema kloner.report/1, keys sorted, UTC timestamps.

Every other format (terminal, Markdown, HTML, CSV, IOCs, STIX) renders from this document.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from kloner import __version__
from kloner.hunt import RunReport, SampleEntry
from kloner.models import SEVERITY_ORDER, VERDICT_CLASS, Verdict
from kloner.util.canonical import canonical_bytes


def _sample(e: SampleEntry) -> dict[str, Any]:
    ev = e.evaluation.model_dump(mode="json", by_alias=True)
    return {
        "evaluation": ev,
        "verdict_class": VERDICT_CLASS[e.evaluation.verdict],
        "sightings": [s.model_dump(mode="json") for s in e.sightings],
        "forensic_labels": e.forensic_labels,
        "intel_labels": e.intel_labels,
        "lookalikes": e.lookalikes,
        "seen_before": e.seen_before,
        "impersonation_candidate": e.candidate,
        "members": [
            {
                "evaluation": m.evaluation.model_dump(mode="json", by_alias=True),
                "parent_sha256": m.parent_sha256,
            }
            for m in e.result.members
        ],
    }


def build(rep: RunReport) -> dict[str, Any]:
    entries = rep.reported()
    counts = Counter(e.evaluation.verdict.value for e in entries)
    member_counts = Counter(m.evaluation.verdict.value for e in entries for m in e.result.members)
    anchor = None
    if rep.anchor is not None:
        a = rep.anchor
        anchor = {
            "package": a.package,
            "record_sha256": a.record_sha256,
            "corroboration": a.corroboration,
            "identities": [
                {
                    "id": i.id,
                    "label": i.label,
                    "role": i.role,
                    "cert_sha256": i.cert_sha256,
                    "subject": i.subject,
                    "declared_additional": i.declared_additional,
                    "evidence_classes": sorted({ev.klass for ev in i.evidence}),
                }
                for i in a.identities
            ],
            "lineage": [e.cert_sha256 for e in a.lineage],
            "record": a.model_dump(mode="json", by_alias=True),
        }
    findings = [e.finding for e in rep.all_entries() if e.finding]
    return {
        "schema": "kloner.report/1",
        "run": {
            "id": rep.run_id,
            "command": rep.command,
            "package": rep.package,
            "started_utc": rep.started_utc,
            "finished_utc": rep.finished_utc,
            "kloner_version": __version__,
            "apksig_version": rep.apksig_version,
            "config_sha256": rep.config_sha256,
            "new_only": rep.new_only,
        },
        "anchor": anchor,
        "coverage": {
            "statement": rep.coverage,
            "sources": [s.model_dump(mode="json") for s in rep.sources],
            "unique_files": len({e.evaluation.sample_sha256 for e in rep.samples}),
            "sightings": sum(len(e.sightings) for e in rep.samples),
        },
        "samples": [_sample(e) for e in entries],
        "findings": findings,
        "intel": rep.intel,
        "notes": rep.notes,
        "summary": {
            "counts": {v.value: counts.get(v.value, 0) for v in SEVERITY_ORDER},
            "member_counts": {
                v.value: member_counts.get(v.value, 0) for v in SEVERITY_ORDER if member_counts.get(v.value)
            },
            "hostile": sum(counts.get(v.value, 0) for v in (Verdict.TAMPERED, Verdict.FORGED, Verdict.IMPERSONATOR)),
            "review": sum(counts.get(v.value, 0) for v in (Verdict.ANOMALY, Verdict.ERROR)),
            "exit_code": rep.exit_code,
            "fail_on": sorted(rep.fail_on),
        },
    }


def dumps(doc: dict[str, Any]) -> bytes:
    return canonical_bytes(doc)
