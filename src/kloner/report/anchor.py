"""Human and JSON views of an anchor (§7.7, D-069)."""

from __future__ import annotations

import json

from rich.console import Console, Group
from rich.table import Table
from rich.text import Text

from kloner import ui
from kloner.models import Anchor
from kloner.util.fingerprints import short_fp


def _when(utc: str | None) -> str:
    return (utc or "").replace("T", " ")


def render_anchor(a: Anchor, console: Console, as_json: bool = False, command: str = "anchor") -> None:
    if as_json:
        console.print_json(json.dumps(a.model_dump(mode="json", by_alias=True), sort_keys=True))
        return
    ui.heading(console, command, a.package)
    level_meaning = ui.CORROBORATION.get(a.corroboration, ("bold", ""))[1]
    b = a.brand
    contents = [ui.plural(len(a.identities), "identity", "identities"), ui.plural(len(a.release_refs), "release")]
    if b.brand_labels:
        contents.append("brand labels: " + ", ".join(b.brand_labels))
    console.print()
    ui.kv(
        console,
        [
            ("Package", Text(a.package, style=f"bold {ui.PALE}")),
            ("Trust", Text.assemble(ui.corroboration_pill(a.corroboration), (f"  {level_meaning}", ui.MUTED))),
            ("Record", Text(f"#{a.record_sha256[:12]}…{a.record_sha256[-4:]}", style=ui.SOFT)),
            ("Contents", " · ".join(contents)),
        ],
    )
    if a.corroboration == "USER_ASSERTED":
        console.print()
        console.print(
            Text.assemble(
                ("▲ Anchor not corroborated.", f"bold {ui.AMBER}"),
                (
                    " Add an official method (--from-url, --from-assetlinks, --from-fingerprint, --from-fdroid).",
                    ui.AMBER,
                ),
            )
        )

    ui.section(console, "Signing identities", "the keys this app may be signed with; any other key is not genuine")
    for i in a.identities:
        role = i.label + (" · declared additional" if i.declared_additional else "")
        key = f"{i.key_algorithm or '?'}-{i.key_bits or '?'}" if (i.key_algorithm or i.key_bits) else ""
        rows: list[Text | Table] = [Text(i.cert_sha256, style=f"bold {ui.PALE}")]
        if i.subject:
            rows.append(Text(i.subject, style=ui.SOFT))
        ev_grid = Table.grid(padding=(0, 2))
        ev_grid.add_column(no_wrap=True)
        ev_grid.add_column(overflow="fold")
        for ev in i.evidence:
            where = ev.final_url or ev.url or ev.file_sha256 or ""
            ev_grid.add_row(
                Text.assemble(("● ", ui.GREEN if ev.klass != "USER" else ui.AMBER), (ev.klass, f"bold {ui.SOFT}")),
                Text.assemble(
                    (f"{ev.method}  ", ui.MUTED), (where, ui.SOFT), (f"  {_when(ev.retrieved_utc)}", ui.MUTED)
                ),
            )
            if ev.klass in ui.EVIDENCE:
                ev_grid.add_row("", Text(ui.EVIDENCE[ev.klass], style=ui.MUTED))
        if i.evidence:
            rows.append(Text("Evidence", style=f"bold {ui.BRIGHT}"))
            rows.append(ev_grid)
        if i.declared_reason:
            rows.append(Text.assemble(("Reason  ", ui.MUTED), (i.declared_reason, ui.SOFT)))
        title = Text.assemble((f"{i.id} · {role}", f"bold {ui.BRIGHT}"), (f"   {key}" if key else "", ui.MUTED))
        console.print(ui.panel(Group(*rows), title, tone="quiet"))

    if a.lineage:
        ui.section(console, "Key lineage", "proof-of-rotation: each key signed by the one before it")
        chain = Text(" → ", style=ui.MUTED).join(
            Text(short_fp(e.cert_sha256), style=f"bold {ui.PALE}") for e in a.lineage
        )
        console.print(chain)
        g = ui.grid()
        for e in a.lineage:
            caps = ", ".join(k for k, v in sorted(e.capabilities.items()) if v) or "—"
            g.add_row(e.cert_sha256, Text(f"capabilities: {caps}", style=ui.SOFT))
        console.print(g)

    if a.release_refs:
        ui.section(console, "Releases", "builds recorded with the anchor, and where each came from")
        t = ui.table("VERSION", "CODE", "FILE", "PROVENANCE")
        for r in a.release_refs:
            t.add_row(
                Text(r.version_name or "—", style=ui.PALE),
                str(r.version_code),
                Text(short_fp(r.file_sha256), style=ui.SOFT),
                Text(r.provenance, style=ui.SOFT),
            )
        console.print(t)

    if b.labels or b.brand_labels or b.icon_asset_sha256 or b.keywords:
        ui.section(console, "Brand profile", "what an impersonator would copy: names and icons")
        ui.kv(
            console,
            [
                (
                    "Labels",
                    ", ".join(b.labels[:6]) + (f"  (+{len(b.labels) - 6} more)" if len(b.labels) > 6 else "") or "—",
                ),
                ("Declared", ", ".join(b.brand_labels) or "—"),
                ("Keywords", ", ".join(b.keywords) or "—"),
                ("Icons", ui.plural(len(b.icon_asset_sha256), "icon asset")),
            ],
        )

    if a.decisions:
        ui.section(console, "Decisions", "choices recorded in the anchor, with the reason given")
        for d in a.decisions:
            console.print(
                Text.assemble(
                    (_when(d.utc), ui.MUTED),
                    ("  " + d.action, f"bold {ui.SOFT}"),
                    (f" {d.identity}" if d.identity else "", ui.PALE),
                    (f"  {d.reason}", ui.SOFT),
                )
            )
