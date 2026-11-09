"""Human and JSON views of an anchor (§7.7)."""

from __future__ import annotations

import json

from rich.console import Console

from kloner.models import Anchor
from kloner.util.fingerprints import short_fp


def render_anchor(a: Anchor, console: Console, as_json: bool = False) -> None:
    if as_json:
        console.print_json(json.dumps(a.model_dump(mode="json", by_alias=True), sort_keys=True))
        return
    console.print(f"[bold]{a.package}[/]  {a.corroboration}  record #{a.record_sha256[:12]}…{a.record_sha256[-4:]}")
    if a.corroboration == "USER_ASSERTED":
        console.print("[bold yellow]Anchor not corroborated.[/]")
    for i in a.identities:
        flag = " (declared additional)" if i.declared_additional else ""
        console.print(f"  {i.id} {i.label}{flag}: {i.cert_sha256}")
        if i.subject:
            console.print(f"      {i.subject} · {i.key_algorithm or '?'}-{i.key_bits or '?'}")
        for ev in i.evidence:
            where = ev.final_url or ev.url or ev.file_sha256 or ""
            console.print(f"      evidence {ev.klass} via {ev.method} {where} ({ev.retrieved_utc})")
        if i.declared_reason:
            console.print(f"      reason: {i.declared_reason}")
    if a.lineage:
        console.print("  lineage: " + " → ".join(f"{short_fp(e.cert_sha256)}" for e in a.lineage))
        for e in a.lineage:
            caps = ", ".join(k for k, v in sorted(e.capabilities.items()) if v) or "—"
            console.print(f"      {e.cert_sha256} capabilities: {caps}")
    for r in a.release_refs:
        console.print(
            f"  release {r.version_name} ({r.version_code}) file {short_fp(r.file_sha256)} via {r.provenance}"
        )
    b = a.brand
    if b.labels or b.brand_labels or b.icon_asset_sha256:
        console.print(
            f"  brand: labels {b.labels[:6]} · declared {b.brand_labels} · keywords {b.keywords} · "
            f"{len(b.icon_asset_sha256)} icon asset(s)"
        )
    for d in a.decisions:
        console.print(f"  decision {d.utc} {d.action} {d.identity or ''}: {d.reason}")
