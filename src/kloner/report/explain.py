"""``kloner explain``: the full gate-by-gate trace of one evaluation (§6.6, D-069)."""

from __future__ import annotations

from typing import Any

from rich.console import Console, Group
from rich.text import Text

from kloner import ui
from kloner.util.fingerprints import short_fp


def _size(n: Any) -> str:
    return f"{n:,} bytes" if isinstance(n, int) else f"{n} bytes"


def render_explain(data: dict[str, Any], console: Console) -> None:
    ev = data["evaluation"]
    verdict = ev["verdict"]
    ui.heading(console, "explain", ev.get("package"))
    tone = {"hostile": "hostile", "review": "review", "clean": "clean"}.get(ui.verdict_class(verdict), "quiet")
    head = Group(
        Text.assemble(ui.verdict_pill(verdict), ("  ", ""), (ev["sample_sha256"], f"bold {ui.PALE}")),
        Text(ev["explanation"], style=ui.SOFT),
        Text(ui.meaning(verdict), style=ui.MUTED),
    )
    console.print()
    console.print(ui.panel(head, "Verdict", tone=tone))

    rows: list[tuple[str, Any]] = [
        (
            "File",
            f"package {ev.get('package')} · version {ev.get('version_name')} ({ev.get('version_code')}) · "
            f"{_size(ev['size'])} · format {ev.get('format')}",
        ),
    ]
    if ev.get("anchor_record_sha256"):
        rows.append(("Anchor", f"{ev.get('anchor_package')} · record {ev['anchor_record_sha256']}"))
    rows.append(("Engine", f"KLONER {ev['kloner_version']} · apksig {ev.get('apksig_version')}"))
    console.print()
    ui.kv(console, rows)

    ui.section(console, "Gates", "the checks run in this order; the first decisive one ends the evaluation")
    t = ui.table()
    t.add_column("GATE", no_wrap=True, style=f"bold {ui.PALE}")
    t.add_column("CHECKS", no_wrap=True, style=ui.SOFT)
    t.add_column("RESULT", no_wrap=True)
    t.add_column("DETAIL", overflow="fold", style=ui.SOFT)
    for g in ev["gate_trace"]:
        name, what = ui.GATES.get(g["gate"], (g["gate"], ""))
        word, style = ui.GATE_STATUS.get(g["status"], (g["status"], ui.SOFT))
        t.add_row(
            g["gate"],
            Text.assemble((name, f"bold {ui.SOFT}"), (f"  {what}", ui.MUTED)),
            Text(word, style=style),
            g["detail"],
        )
    console.print(t)
    console.print(Text.assemble(("Reasons  ", ui.MUTED), (", ".join(ev["reasons"]), f"bold {ui.PALE}")))

    if ev["labels"]:
        ui.section(
            console, "Labels", "what KLONER noticed about the file; labels never change the verdict on their own"
        )
        g2 = ui.grid()
        for lab in ev["labels"]:
            g2.add_row(
                Text.assemble(ui.label_text(lab["code"]), (f"  {lab['severity']}", ui.MUTED)),
                Text(lab.get("detail") or ui.label_meaning(lab["code"]) or "", style=ui.SOFT),
            )
        console.print(g2)

    if ev["signers"]:
        ui.section(console, "Signers", "every key that signed the file; trust none means not an official key")
        t2 = ui.table("CERTIFICATE SHA-256", "TRUST", "SCHEMES", "SUBJECT")
        for s in ev["signers"]:
            trusted = s["trust"] != "none"
            t2.add_row(
                Text(s["cert_sha256"], style=f"bold {ui.PALE}"),
                Text(("✓ " if trusted else "✗ ") + s["trust"], style=f"bold {ui.GREEN if trusted else ui.RED}"),
                Text(",".join(s["schemes"]), style=ui.SOFT),
                Text(
                    (s.get("subject") or "") + (f"  known={s['known_key']}" if s.get("known_key") else ""),
                    style=ui.SOFT,
                ),
            )
        t2.columns[0].overflow = "fold"
        t2.columns[3].overflow = "fold"
        console.print(t2)

    facts = data.get("facts") or {}
    nat = facts.get("native_inventory") or {}
    if nat.get("pairs"):
        ui.section(console, "APK Signing Block", "every block entry, signed or not")
        t3 = ui.table("ID", "NAME", "KIND", "SIZE", "SHA-256")
        for p in nat["pairs"]:
            t3.add_row(
                Text(p["id_hex"], style=ui.PALE),
                p["name"],
                Text(p["kind"], style=ui.SOFT),
                f"{p['size']:,} B" if isinstance(p["size"], int) else f"{p['size']} B",
                Text(short_fp(p["sha256"]), style=ui.SOFT),
            )
        console.print(t3)

    lines = [f["capabilities"]["line"] for f in data.get("findings", []) if f.get("capabilities")]
    if lines:
        ui.section(console, "Forensics", "what the file adds compared with an official build")
        for line in lines:
            console.print(Text(line, style=f"bold {ui.PALE}"))

    sightings = data.get("sightings", [])
    if sightings:
        ui.section(console, "Seen at", "where this exact file was found")
        for s in sightings:
            where = s.get("final_url") or s.get("offer_url") or ""
            console.print(
                Text.assemble(
                    ("● ", ui.GREEN),
                    (s["source"], f"bold {ui.PALE}"),
                    (f"  {s.get('store') or ''}  ", ui.SOFT),
                    (where, ui.SOFT),
                    (f"  {(s['retrieved_utc'] or '').replace('T', ' ')}", ui.MUTED),
                ),
                soft_wrap=True,
            )
