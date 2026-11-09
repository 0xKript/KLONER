"""Markdown report (§15.3): self-contained, no external assets."""

from __future__ import annotations

from typing import Any

from kloner.labels import describe
from kloner.util.fingerprints import short_fp

HOSTILE = ("TAMPERED", "FORGED", "IMPERSONATOR")
REVIEW = ("ANOMALY", "ERROR")


def _esc(s: Any) -> str:
    return str(s).replace("|", "\\|").replace("\n", " ")


def render(doc: dict[str, Any]) -> str:
    run, anchor, cov, summary = doc["run"], doc["anchor"], doc["coverage"], doc["summary"]
    out: list[str] = []
    w = out.append
    w(f"# KLONER report — {run['package'] or run['command']}")
    w("")
    w(f"- Run `{run['id']}` · `{run['command']}` · {run['started_utc']} → {run['finished_utc']}")
    w(f"- KLONER {run['kloner_version']} · apksig {run['apksig_version']}")
    if anchor:
        w(f"- Anchor `{anchor['package']}` record `{anchor['record_sha256']}` ({anchor['corroboration']})")
        if anchor["corroboration"] == "USER_ASSERTED":
            w("- **Anchor not corroborated.**")
    w("")
    w("## Executive summary")
    w("")
    w("| Verdict | Count |")
    w("|---|---|")
    for v, n in summary["counts"].items():
        if n:
            w(f"| {v} | {n} |")
    w("")
    w(f"**Coverage.** {cov['statement']}")
    w("")
    per_source: dict[str, dict[str, int]] = {}
    for s in doc["samples"]:
        for g in s["sightings"]:
            key = g["source"] + (f":{g['store']}" if g.get("store") else "")
            per_source.setdefault(key, {}).setdefault(s["evaluation"]["verdict"], 0)
            per_source[key][s["evaluation"]["verdict"]] += 1
    if per_source:
        w("| Source | Verdicts |")
        w("|---|---|")
        for k in sorted(per_source):
            w(f"| {_esc(k)} | {', '.join(f'{v} {n}' for v, n in sorted(per_source[k].items()))} |")
        w("")
    findings = {f["sample_sha256"]: f for f in doc["findings"]}
    hostile = [s for s in doc["samples"] if s["evaluation"]["verdict"] in HOSTILE]
    w("## Hostile findings")
    w("")
    if not hostile:
        w(f"No hostile copies among {cov['unique_files']} files from the sources listed above.")
        w("")
    for s in hostile:
        ev = s["evaluation"]
        w(f"### {ev['verdict']} `{ev['sample_sha256']}`")
        w("")
        w(f"**Why.** {ev['explanation']}")
        w("")
        w(
            f"- Package `{ev['package']}` version {ev.get('version_name')} ({ev.get('version_code')}), "
            f"{ev['size']} bytes"
        )
        for sig in ev["signers"]:
            w(
                f"- Signer `{sig['cert_sha256']}` ({sig['trust']}) {sig.get('subject') or ''}"
                + (f" — known key **{sig['known_key']}**" if sig.get("known_key") else "")
            )
        w(f"- Reasons: {', '.join(f'`{r}`' for r in ev['reasons'])}")
        labels = [lab["code"] for lab in ev["labels"]] + s["forensic_labels"] + s["intel_labels"]
        if labels:
            w(f"- Labels: {', '.join(f'`{x}`' for x in labels)}")
        for g in s["sightings"]:
            w(
                f"- Seen at {g['source']}{':' + g['store'] if g.get('store') else ''} — "
                f"{g.get('final_url') or g.get('offer_url')} ({g['retrieved_utc']})"
            )
        f = findings.get(ev["sample_sha256"])
        if f:
            if f.get("capabilities"):
                w(f"- {f['capabilities']['line']}")
            if f.get("reference"):
                r = f["reference"]
                w(f"- Diff reference `{short_fp(r['sha256'])}` ({r['kind']}, versionCode {r['version_code']})")
            d = f.get("diff")
            if d:
                perms = d["manifest"]["permissions"]["added"]
                if perms:
                    w(f"- Permissions added: {', '.join(f'`{p}`' for p in perms[:20])}")
                if d["code"]["classes_added"]:
                    w(
                        f"- Classes added: {len(d['code']['classes_added'])}; "
                        f"modified: {len(d['code']['classes_modified'])}"
                    )
            if f.get("overlap"):
                o = f["overlap"]
                w(f"- Overlap (heuristic): J_class {o['j_class']}, J_res {o['j_res']}")
            if f.get("payload"):
                w(f"- Payload `{f['payload']['payload_id']}` (shape `{f['payload']['shape_id']}`)")
        for line in doc["intel"]:
            if line.get("sample_sha256") == ev["sample_sha256"]:
                w(f"- {line['text']}")
        w("")
    review = [s for s in doc["samples"] if s["evaluation"]["verdict"] in REVIEW]
    w("## Review items")
    w("")
    if not review:
        w("None.")
    for s in review:
        ev = s["evaluation"]
        w(f"- **{ev['verdict']}** `{ev['sample_sha256']}`: {ev['explanation']} ({', '.join(ev['reasons'])})")
    w("")
    genuine = [s for s in doc["samples"] if s["evaluation"]["verdict"] == "GENUINE"]
    w("## Genuine copies")
    w("")
    if genuine:
        w("| File | Version | Sources | Labels |")
        w("|---|---|---|---|")
        for s in genuine:
            ev = s["evaluation"]
            srcs = (
                ", ".join(sorted({g["source"] + (f":{g['store']}" if g.get("store") else "") for g in s["sightings"]}))
                or "local"
            )
            w(
                f"| `{short_fp(ev['sample_sha256'])}` | {ev.get('version_name')} ({ev.get('version_code')}) | "
                f"{_esc(srcs)} | "
                f"{', '.join(lab['code'] for lab in ev['labels'])} |"
            )
    else:
        w("None.")
    w("")
    other = [s for s in doc["samples"] if s["evaluation"]["verdict"] in ("MISMATCH", "INVALID", "UNANCHORED")]
    if other:
        w("## Not applicable")
        w("")
        for s in other:
            ev = s["evaluation"]
            w(f"- {ev['verdict']} `{short_fp(ev['sample_sha256'])}`: {ev['explanation']}")
        w("")
    looks = [s for s in doc["samples"] if s["lookalikes"]]
    w("## Lookalikes (heuristic)")
    w("")
    if not looks:
        w("None.")
    for s in looks:
        ev = s["evaluation"]
        sig = ", ".join(
            f"{x['signal']} ({x['candidate']} ~ {x['official']}, score {x['score']})" for x in s["lookalikes"]
        )
        w(f"- `{ev.get('package')}` `{short_fp(ev['sample_sha256'])}` ({ev['verdict']}): {sig}")
    w("")
    w("## Appendix")
    w("")
    if anchor:
        w(f"Anchor record `{anchor['record_sha256']}`:")
        w("")
        for i in anchor["identities"]:
            w(
                f"- {i['id']} {i['label']} `{i['cert_sha256']}` {i.get('subject') or ''} "
                f"[{', '.join(i['evidence_classes'])}]{' (declared additional)' if i['declared_additional'] else ''}"
            )
        if anchor["lineage"]:
            w(f"- Lineage: {' → '.join(short_fp(c) for c in anchor['lineage'])}")
        w("")
    w("Gate traces:")
    w("")
    for s in doc["samples"]:
        ev = s["evaluation"]
        trace = "; ".join(f"{g['gate']} {g['status']}" for g in ev["gate_trace"])
        w(f"- `{short_fp(ev['sample_sha256'])}` {ev['verdict']}: {trace}")
    w("")
    seen = sorted(
        {c for s in doc["samples"] for c in [lab["code"] for lab in s["evaluation"]["labels"]] + s["forensic_labels"]}
    )
    if seen:
        w("Labels used:")
        w("")
        for c in seen:
            w(f"- `{c}` — {describe(c)}")
    return "\n".join(out) + "\n"
