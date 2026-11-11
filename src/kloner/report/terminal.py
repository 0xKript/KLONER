"""Terminal output (§15.1, Appendix B): the screen of hunt, verify, fetch and ``report --format terminal`` (D-069).

It renders the canonical JSON document and nothing else, so it can never disagree with report.json.
"""

from __future__ import annotations

from typing import Any

from rich.console import Console, Group
from rich.text import Text

from kloner import ui
from kloner.util.fingerprints import short_fp

EXIT_TEXT = {
    0: "no hostile copies, no review items",
    10: "hostile copies found",
    11: "review items present (ANOMALY/ERROR)",
}
EXIT_TONE = {0: ("✓", ui.GREEN), 10: ("✗", ui.RED), 11: ("▲", ui.AMBER)}
TITLES = {
    "hunt": ("Copies found", "every file the sweep found, and its verdict; the most serious first"),
    "verify": ("Files checked", "every file you gave, and its verdict; the most serious first"),
    "fetch": ("Links fetched", "every downloaded file, and its verdict; the most serious first"),
}


def _source_chips(doc: dict[str, Any]) -> Text:
    chips = []
    for s in doc["coverage"]["sources"]:
        extra = ""
        if s["status"] == "OK":
            stores = s.get("stores") or []
            extra = f"{s.get('fetched', 0)}/{s.get('offers', 0)}" + (
                f" · {len(stores)} stores" if len(stores) > 1 else ""
            )
        chips.append(ui.source_chip(s["source"], s["status"], extra))
    return Text("    ").join(chips)


def _signer_cell(ev: dict[str, Any]) -> Text:
    signers = ev.get("signers") or []
    if not signers:
        return Text("—", style=ui.MUTED)
    if all(s["trust"] != "none" for s in signers):
        return Text("official", style=f"bold {ui.GREEN}")
    foreign = [s for s in signers if s["trust"] == "none"]
    hostile = ui.verdict_class(ev.get("verdict") or "") == "hostile"
    return Text(short_fp(foreign[0]["cert_sha256"]), style=f"bold {ui.RED}" if hostile else ui.SOFT)


def _version_cell(ev: dict[str, Any], candidate: bool) -> str:
    if candidate or ev.get("verdict") == "IMPERSONATOR":
        return ev.get("package") or "—"
    vn, vc = ev.get("version_name"), ev.get("version_code")
    if vn is None and vc is None:
        return "—"
    return f"{vn} ({vc})" if vn else str(vc)


def _source_cell(sightings: list[dict[str, Any]]) -> str:
    if not sightings:
        return "—"
    first = sightings[0]
    src = str(first["source"]) + (f":{first['store']}" if first.get("store") else "")
    return src + (f" +{len(sightings) - 1}" if len(sightings) > 1 else "")


def _labels(s: dict[str, Any]) -> list[str]:
    ev = s["evaluation"]
    labels: list[str] = [lab["code"] for lab in ev["labels"]] + list(s["forensic_labels"]) + list(s["intel_labels"])
    if s["lookalikes"]:
        labels += sorted({f"LOOKALIKE:{x['signal']}" for x in s["lookalikes"]})
    return labels


def _top_finding(doc: dict[str, Any]) -> dict[str, Any] | None:
    samples: list[dict[str, Any]] = doc["samples"]
    for s in samples:
        if s["evaluation"]["verdict"] in ("TAMPERED", "FORGED", "IMPERSONATOR"):
            return s
    return None


def render(doc: dict[str, Any], console: Console, report_paths: list[str] | None = None) -> None:
    run, anchor = doc["run"], doc["anchor"]
    command = run.get("command") or "hunt"
    ui.heading(console, command, run.get("package") or (anchor or {}).get("package"))

    head: list[tuple[str, Any]] = []
    if anchor:
        rec = anchor["record_sha256"]
        level = anchor["corroboration"]
        head.append(
            (
                "Anchor",
                Text.assemble(
                    (anchor["package"], f"bold {ui.PALE}"),
                    (f"  #{rec[:4]}…{rec[-3:]}  ", ui.MUTED),
                    ui.corroboration_pill(level),
                    ("  " + ui.CORROBORATION.get(level, ("", ""))[1], ui.MUTED),
                ),
            )
        )
    head.append(("Engine", f"KLONER {run['kloner_version']} · apksig {run['apksig_version'] or '—'}"))
    head.append(("Run", run.get("id")))
    if doc["coverage"]["sources"]:
        head.append(("Sources", _source_chips(doc)))
    console.print()
    ui.kv(console, head)
    if anchor and anchor["corroboration"] == "USER_ASSERTED":
        console.print()
        console.print(
            Text.assemble(
                ("▲ Anchor not corroborated.", f"bold {ui.AMBER}"),
                (" Verdicts are relative to a USER-asserted identity.", ui.AMBER),
            )
        )

    title, caption = TITLES.get(command, TITLES["hunt"])
    ui.section(console, title, caption)
    rows = sorted(
        doc["samples"],
        key=lambda s: (
            ui.SCREEN_ORDER.index(s["evaluation"]["verdict"])
            if s["evaluation"]["verdict"] in ui.SCREEN_ORDER
            else len(ui.SCREEN_ORDER)
        ),
    )
    # Below 100 columns the vertical borders go, so the labels keep their width and do not break mid-word.
    narrow = console.width < 100
    table = ui.table(narrow=narrow)
    table.add_column("VERDICT", no_wrap=True)
    table.add_column("SOURCE", overflow="fold", style=ui.SOFT)
    table.add_column("VERSION", overflow="fold", style=ui.PALE)
    table.add_column("FILE", no_wrap=True, style=ui.SOFT)
    table.add_column("SIGNER", no_wrap=True)
    longest = max((len(c) for s in doc["samples"] for c in _labels(s)), default=0)
    table.add_column("LABELS", overflow="fold", min_width=min(longest, 24) if narrow else None)
    shown_labels: list[str] = []
    for s in rows:
        ev = s["evaluation"]
        labels = _labels(s)
        shown_labels += labels
        table.add_row(
            ui.verdict_text(ev["verdict"]),
            _source_cell(s["sightings"]),
            _version_cell(ev, s["impersonation_candidate"]),
            short_fp(ev["sample_sha256"]),
            _signer_cell(ev),
            ui.labels_line(labels),
        )
    if rows:
        console.print(table)
    else:
        console.print(Text("  No files to show.", style=ui.MUTED))
    ui.legend(console, [s["evaluation"]["verdict"] for s in rows], shown_labels)

    counts = doc["summary"]["counts"]
    cov = doc["coverage"]
    result = Group(
        ui.counts_line(counts),
        Text(
            f"{ui.plural(cov['unique_files'], 'unique file')} · {ui.plural(cov['sightings'], 'sighting')}",
            style=ui.MUTED,
        ),
        Text.assemble(("Coverage: ", f"bold {ui.SOFT}"), (cov["statement"], ui.SOFT)),
    )
    console.print()
    console.print(ui.panel(result, "Result", tone="quiet"))

    top = _top_finding(doc)
    findings = {f["sample_sha256"]: f for f in doc["findings"]}
    if top is not None:
        ev = top["evaluation"]
        src = top["sightings"][0]["source"] if top["sightings"] else "local"
        body: list[Text] = [Text(ev["explanation"], style=ui.SOFT)]
        f = findings.get(ev["sample_sha256"])
        if f and f.get("capabilities"):
            body.append(Text(f["capabilities"]["line"], style=f"bold {ui.PALE}"))
        for line in doc["intel"]:
            if line.get("sample_sha256") == ev["sample_sha256"]:
                body.append(Text(line["text"], style=ui.AMBER))
        heading = Text(
            f"✗ Top finding — {ev['verdict']} {short_fp(ev['sample_sha256'])} ({src})", style=f"bold {ui.RED}"
        )
        console.print()
        console.print(ui.panel(Group(*body), heading, tone="hostile"))

    notes = doc.get("notes", [])[:10]
    if notes:
        console.print()
        for n in notes:
            ui.note(console, n)

    console.print()
    if report_paths:
        others = f"  (+ {', '.join(report_paths[1:])})" if len(report_paths) > 1 else ""
        console.print(
            Text.assemble(("Reports  ", ui.MUTED), (report_paths[0], ui.SOFT), (others, ui.MUTED)), soft_wrap=True
        )
    code = doc["summary"]["exit_code"]
    icon, color = EXIT_TONE.get(code, ("•", ui.SOFT))
    console.print(Text(f"{icon} Exit {code} — {EXIT_TEXT.get(code, '')}", style=f"bold {color}"))
    ui.next_steps(console, _next_steps(doc, top, findings))


def _next_steps(doc: dict[str, Any], top: dict[str, Any] | None, findings: dict[str, Any]) -> list[tuple[str, str]]:
    steps: list[tuple[str, str]] = []
    if top is not None:
        sha = top["evaluation"]["sample_sha256"]
        steps.append((f"kloner explain {sha}", "why this file got its verdict, gate by gate"))
        ref = (findings.get(sha) or {}).get("reference") or {}
        if ref.get("sha256"):
            steps.append(
                (f"kloner diff {sha} --against {ref['sha256']}", "what this copy changed against the official build")
            )
        return steps
    review = [s for s in doc["samples"] if ui.verdict_class(s["evaluation"]["verdict"]) == "review"]
    if review:
        sha = review[0]["evaluation"]["sample_sha256"]
        return [(f"kloner explain {sha}", "why KLONER asks you to review this file")]
    if doc["samples"] and doc["run"].get("id"):
        return [(f"kloner reverify {doc['run']['id']}", "recompute every verdict offline and prove it is identical")]
    return steps
