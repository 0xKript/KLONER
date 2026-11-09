"""Terminal output (§15.1, Appendix B)."""

from __future__ import annotations

from typing import Any

from rich.console import Console
from rich.table import Table
from rich.text import Text

from kloner.util.fingerprints import short_fp

VERDICT_STYLE = {
    "GENUINE": "bold green",
    "TAMPERED": "bold red",
    "FORGED": "bold red",
    "IMPERSONATOR": "bold magenta",
    "ANOMALY": "bold yellow",
    "ERROR": "bold yellow",
    "MISMATCH": "cyan",
    "INVALID": "dim",
    "UNANCHORED": "dim",
}
EXIT_TEXT = {
    0: "no hostile copies, no review items",
    10: "hostile copies found",
    11: "review items present (ANOMALY/ERROR)",
}


def _source_line(doc: dict[str, Any]) -> str:
    parts = []
    for s in doc["coverage"]["sources"]:
        st = s["status"]
        if st == "OK" and len(s.get("stores") or []) > 1:
            parts.append(f"{s['source']} OK ({len(s['stores'])} stores)")
        elif st == "NO_OFFERS":
            parts.append(f"{s['source']} no offers")
        elif st == "DISABLED":
            parts.append(f"{s['source']} disabled")
        elif st == "SKIPPED":
            parts.append(f"{s['source']} skipped")
        else:
            parts.append(f"{s['source']} {st}")
    return " · ".join(parts)


def _signer_cell(ev: dict[str, Any]) -> str:
    signers = ev.get("signers") or []
    if not signers:
        return "—"
    if all(s["trust"] != "none" for s in signers):
        return "official"
    foreign = [s for s in signers if s["trust"] == "none"]
    return short_fp(foreign[0]["cert_sha256"])


def _version_cell(ev: dict[str, Any], candidate: bool) -> str:
    if candidate or ev.get("verdict") == "IMPERSONATOR":
        return ev.get("package") or "—"
    vn, vc = ev.get("version_name"), ev.get("version_code")
    if vn is None and vc is None:
        return "—"
    return f"{vn} ({vc})" if vn else str(vc)


def render(doc: dict[str, Any], console: Console, report_paths: list[str] | None = None) -> None:
    run, anchor = doc["run"], doc["anchor"]
    head = f"KLONER {run['kloner_version']} · apksig {run['apksig_version'] or '—'}"
    if anchor:
        rec = anchor["record_sha256"]
        head += f" · anchor {anchor['package']} #{rec[:4]}…{rec[-3:]} ({anchor['corroboration']})"
    console.print(head)
    if anchor and anchor["corroboration"] == "USER_ASSERTED":
        console.print("[bold yellow]Anchor not corroborated.[/] Verdicts are relative to a USER-asserted identity.")
    if doc["coverage"]["sources"]:
        console.print(f"Sources: {_source_line(doc)}")
    console.print()
    table = Table(box=None, pad_edge=False, show_edge=False, header_style="bold")
    for col in ("VERDICT", "SOURCE", "VERSION", "FILE", "SIGNER", "LABELS"):
        table.add_column(col, overflow="fold")
    for s in doc["samples"]:
        ev = s["evaluation"]
        sightings = s["sightings"]
        src = (
            sightings[0]["source"] + (f":{sightings[0]['store']}" if sightings and sightings[0].get("store") else "")
            if sightings
            else "—"
        )
        if len(sightings) > 1:
            src += f" +{len(sightings) - 1}"
        labels = [lab["code"] for lab in ev["labels"]] + s["forensic_labels"] + s["intel_labels"]
        if s["lookalikes"]:
            labels += sorted({f"LOOKALIKE:{x['signal']}" for x in s["lookalikes"]})
        table.add_row(
            Text(ev["verdict"], style=VERDICT_STYLE.get(ev["verdict"], "")),
            src,
            _version_cell(ev, s["impersonation_candidate"]),
            short_fp(ev["sample_sha256"]),
            _signer_cell(ev),
            " · ".join(labels) or "",
        )
    console.print(table)
    console.print()
    counts = doc["summary"]["counts"]
    parts = [f"{n} {v}" for v, n in counts.items() if n]
    cov = doc["coverage"]
    console.print(
        f"Summary: {' · '.join(parts) or 'no samples'} — {cov['unique_files']} unique files, "
        f"{cov['sightings']} sightings"
    )
    console.print(f"Coverage: {cov['statement']}")
    findings = {f["sample_sha256"]: f for f in doc["findings"]}
    for s in doc["samples"]:
        ev = s["evaluation"]
        if ev["verdict"] not in ("TAMPERED", "FORGED", "IMPERSONATOR"):
            continue
        console.print()
        src = s["sightings"][0]["source"] if s["sightings"] else "local"
        console.print(f"[bold]Top finding — {ev['verdict']} {short_fp(ev['sample_sha256'])} ({src})[/]")
        console.print(f"  {ev['explanation']}")
        f = findings.get(ev["sample_sha256"])
        if f and f.get("capabilities"):
            console.print(f"  {f['capabilities']['line']}")
        for line in doc["intel"]:
            if line.get("sample_sha256") == ev["sample_sha256"]:
                console.print(f"  {line['text']}")
        break
    for note in doc.get("notes", [])[:10]:
        console.print(f"[dim]note: {note}[/]")
    if report_paths:
        console.print()
        console.print(
            f"Reports: {report_paths[0]}" + (f" (+ {', '.join(report_paths[1:])})" if len(report_paths) > 1 else "")
        )
    code = doc["summary"]["exit_code"]
    console.print(f"Exit {code} — {EXIT_TEXT.get(code, '')}")
