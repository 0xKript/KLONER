"""``kloner explain``: the full gate-by-gate trace of one evaluation (§6.6)."""

from __future__ import annotations

from typing import Any

from rich.console import Console

from kloner.labels import describe
from kloner.util.fingerprints import short_fp


def render_explain(data: dict[str, Any], console: Console) -> None:
    ev = data["evaluation"]
    console.print(f"[bold]{ev['verdict']}[/] {ev['sample_sha256']}")
    console.print(f"  {ev['explanation']}")
    console.print(
        f"  package {ev.get('package')} · version {ev.get('version_name')} ({ev.get('version_code')}) · "
        f"{ev['size']} bytes · format {ev.get('format')}"
    )
    if ev.get("anchor_record_sha256"):
        console.print(f"  anchor {ev.get('anchor_package')} record {ev['anchor_record_sha256']}")
    console.print(f"  KLONER {ev['kloner_version']} · apksig {ev.get('apksig_version')}")
    console.print("[bold]Gates[/]")
    for g in ev["gate_trace"]:
        console.print(f"  {g['gate']:4s} {g['status']:5s} {g['detail']}")
    console.print("[bold]Reasons[/]  " + ", ".join(ev["reasons"]))
    if ev["labels"]:
        console.print("[bold]Labels[/]")
        for lab in ev["labels"]:
            console.print(f"  {lab['code']} ({lab['severity']}) — {lab.get('detail') or describe(lab['code'])}")
    if ev["signers"]:
        console.print("[bold]Signers[/]")
        for s in ev["signers"]:
            console.print(
                f"  {s['cert_sha256']} trust={s['trust']} schemes={','.join(s['schemes'])} "
                f"{s.get('subject') or ''}" + (f" known={s['known_key']}" if s.get("known_key") else "")
            )
    facts = data.get("facts") or {}
    nat = facts.get("native_inventory") or {}
    if nat.get("pairs"):
        console.print("[bold]APK Signing Block[/]")
        for p in nat["pairs"]:
            console.print(f"  {p['id_hex']} {p['name']} ({p['kind']}) {p['size']} B {short_fp(p['sha256'])}")
    for f in data.get("findings", []):
        if f.get("capabilities"):
            console.print(f"[bold]Forensics[/] {f['capabilities']['line']}")
    for s in data.get("sightings", []):
        console.print(
            f"  seen: {s['source']} {s.get('store') or ''} {s.get('final_url') or s.get('offer_url') or ''} "
            f"{s['retrieved_utc']}"
        )
