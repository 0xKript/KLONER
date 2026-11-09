"""IOC exports (§15.5) and the CSV sample table.

Hostile sample hashes and foreign signer fingerprints are indicators. Network indicators found in
injected code are *leads*, marked as such.
"""

from __future__ import annotations

import csv
import io
from typing import Any

HOSTILE = ("TAMPERED", "FORGED", "IMPERSONATOR")


def indicators(doc: dict[str, Any]) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    findings = {f["sample_sha256"]: f for f in doc["findings"]}
    seen: set[tuple[str, str]] = set()

    def add(kind: str, value: str, context: str, confidence: str) -> None:
        if (kind, value) not in seen:
            seen.add((kind, value))
            out.append({"type": kind, "value": value, "context": context, "confidence": confidence})

    for s in doc["samples"]:
        ev = s["evaluation"]
        if ev["verdict"] not in HOSTILE:
            continue
        ctx = f"{ev['verdict']} copy of {ev.get('brand_package') or ev.get('package')}"
        add("sha256", ev["sample_sha256"], ctx, "high")
        for sig in ev["signers"]:
            if sig["trust"] == "none":
                add("cert-sha256", sig["cert_sha256"], f"foreign signer of {ctx}", "high")
        f = findings.get(ev["sample_sha256"]) or {}
        if f.get("payload"):
            add("payload-id", f["payload"]["payload_id"], f"injected code in {ctx}", "medium")
        for ep in (f.get("capabilities") or {}).get("endpoints") or []:
            kind = "url" if "://" in ep else ("ipv4" if ep.replace(".", "").isdigit() else "domain")
            add(kind, ep, f"lead: new endpoint in injected code of {ctx}", "low")
    return out


def iocs_txt(doc: dict[str, Any]) -> str:
    lines = [
        f"# KLONER IOCs — run {doc['run']['id']} — {doc['run']['package'] or ''}".rstrip(),
        "# type:value — network entries marked lead are low-confidence leads, not verdicts",
    ]
    for i in indicators(doc):
        suffix = "  # lead" if i["confidence"] == "low" else ""
        lines.append(f"{i['type']}:{i['value']}{suffix}")
    return "\n".join(lines) + "\n"


def iocs_csv(doc: dict[str, Any]) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=["type", "value", "context", "confidence"], lineterminator="\n")
    w.writeheader()
    for i in indicators(doc):
        w.writerow(i)
    return buf.getvalue()


def samples_csv(doc: dict[str, Any]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(
        [
            "verdict",
            "sha256",
            "package",
            "version_code",
            "version_name",
            "size",
            "signers",
            "labels",
            "sources",
            "explanation",
        ]
    )
    for s in doc["samples"]:
        ev = s["evaluation"]
        w.writerow(
            [
                ev["verdict"],
                ev["sample_sha256"],
                ev.get("package") or "",
                ev.get("version_code") or "",
                ev.get("version_name") or "",
                ev["size"],
                " ".join(f"{x['cert_sha256']}:{x['trust']}" for x in ev["signers"]),
                " ".join([lab["code"] for lab in ev["labels"]] + s["forensic_labels"] + s["intel_labels"]),
                " ".join(sorted({g["source"] + (f":{g['store']}" if g.get("store") else "") for g in s["sightings"]})),
                ev["explanation"],
            ]
        )
    return buf.getvalue()
