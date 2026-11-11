"""``kloner diff``: a copy next to the reference build, what it changed, and what that adds up to (§10, D-069).

It renders the forensic diff, the overlap and the capability summary as they are; it explains and never decides.
"""

from __future__ import annotations

from typing import Any

from rich.console import Console, Group
from rich.text import Text

from kloner import ui


def _few(items: list[str], n: int = 3) -> str:
    shown = ", ".join(items[:n])
    return shown + (f"  (+{len(items) - n} more)" if len(items) > n else "")


def _side_by_side(a: str, b: str, sv: dict[str, Any], rv: dict[str, Any]) -> Any:
    t = ui.table()
    t.add_column("", no_wrap=True, style=ui.MUTED)
    t.add_column("SAMPLE  the copy you examine", overflow="fold", max_width=36)
    t.add_column("REFERENCE  what you compare it with", overflow="fold", max_width=36)

    def row(name: str, left: Any, right: Any) -> None:
        same = left == right
        style = ui.SOFT if same else f"bold {ui.AMBER}"
        mark = "" if same else "  ≠"
        t.add_row(
            name, Text(f"{left}{mark}", style=style), Text(str(right), style=ui.SOFT if same else f"bold {ui.PALE}")
        )

    t.add_row("SHA-256", Text(a, style=f"bold {ui.PALE}"), Text(b, style=f"bold {ui.PALE}"))
    row("Package", sv.get("package"), rv.get("package"))
    row("Version code", sv.get("version_code"), rv.get("version_code"))
    row("Classes", len(sv.get("classes") or []), len(rv.get("classes") or []))
    row("Permissions", len(sv["manifest"].get("permissions") or []), len(rv["manifest"].get("permissions") or []))
    row("Components", len(sv["manifest"].get("components") or []), len(rv["manifest"].get("components") or []))
    row("Native libraries", len(sv.get("native") or []), len(rv.get("native") or []))
    row("Files", len(sv.get("files") or []), len(rv.get("files") or []))
    return t


def render_diff(
    console: Console,
    a: str,
    b: str,
    sv: dict[str, Any],
    rv: dict[str, Any],
    d: dict[str, Any],
    caps: dict[str, Any],
    ov: dict[str, Any],
    line: str,
    display: dict[str, str],
) -> None:
    c = console
    ui.heading(c, "diff", sv.get("package"))
    ui.section(c, "Side by side", "≠ marks what differs")
    c.print(_side_by_side(a, b, sv, rv))

    th = ov.get("thresholds") or {}
    if ov["label"] == "REPACKAGED":
        reading = Text.assemble(
            ("→ REPACKAGED range: ", f"bold {ui.AMBER}"),
            ("the sample carries most of the reference's code. Same code base, modified.", ui.SOFT),
        )
    elif ov["label"] == "IMPOSTOR":
        reading = Text.assemble(
            ("→ IMPOSTOR range: ", f"bold {ui.VIOLET}"),
            ("the sample shares little code with the reference. A different app.", ui.SOFT),
        )
    else:
        reading = Text(
            "→ Between the two ranges: neither clearly the same code base nor clearly a different one.", style=ui.SOFT
        )
    g = ui.grid()
    g.add_row("classes", ui.bar(float(ov["j_class"])))
    g.add_row("resources", ui.bar(float(ov["j_res"])))
    body = Group(
        g,
        reading,
        Text(
            f"A heuristic, never a verdict: REPACKAGED from {th.get('repackaged_min', '?')}, IMPOSTOR below "
            f"{th.get('impostor_max', '?')} (class overlap).",
            style=ui.MUTED,
        ),
    )
    c.print()
    title = f"Code overlap (heuristic): classes {ov['j_class']:.2f}, resources {ov['j_res']:.2f}"
    c.print(ui.panel(body, title, tone="quiet"))

    m, code, nat, files = d["manifest"], d["code"], d["native"], d["files"]
    ind = code["new_indicators"]
    endpoints = sorted(set(ind.get("urls", [])) | set(ind.get("domains", [])) | set(ind.get("ips", [])))
    ui.section(c, "What the sample changed", "+ only in the sample, - only in the reference")
    t = ui.table()
    t.add_column("AREA", no_wrap=True, style=f"bold {ui.PALE}")
    t.add_column("+", justify="right", no_wrap=True)
    t.add_column("-", justify="right", no_wrap=True)
    t.add_column("DETAILS", overflow="fold", style=ui.SOFT)

    def count(n: int, sign: str) -> Text:
        if not n:
            return Text(f"{sign}0", style=ui.MUTED)
        return Text(f"{sign}{n}", style=f"bold {ui.RED if sign == '+' else ui.AMBER}")

    def both(added: list[str], removed: list[str]) -> str:
        parts = []
        if added:
            parts.append("+ " + _few(added))
        if removed:
            parts.append("- " + _few(removed))
        return "\n".join(parts)

    comps_added = [f"{x['type']}:{x['name']}" for x in m["components_added"]]
    comps_removed = [f"{x['type']}:{x['name']}" for x in m["components_removed"]]
    rows = [
        (
            "Permissions",
            len(m["permissions"]["added"]),
            len(m["permissions"]["removed"]),
            both(m["permissions"]["added"], m["permissions"]["removed"]),
        ),
        ("Components", len(comps_added), len(comps_removed), both(comps_added, comps_removed)),
        (
            "Classes",
            len(code["classes_added"]),
            len(code["classes_removed"]),
            f"{len(code['classes_modified'])} modified"
            + (f" · new packages: {_few(code['packages_added'])}" if code["packages_added"] else ""),
        ),
        ("Network endpoints", len(endpoints), 0, _few(endpoints)),
        ("Risky API references", len(code["risky_api_deltas"]), 0, _few(sorted(code["risky_api_deltas"]))),
        (
            "Native libraries",
            len(nat["added"]),
            len(nat["removed"]),
            " · ".join(
                x
                for x in (
                    f"{len(nat['changed'])} changed" if nat["changed"] else "",
                    both(nat["added"], nat["removed"]),
                )
                if x
            ),
        ),
        (
            "Files",
            len(files["added"]),
            len(files["removed"]),
            f"{len(files['embedded_payloads'])} embedded payloads"
            + (f" · {both(files['added'], files['removed'])}" if files["added"] or files["removed"] else ""),
        ),
    ]
    for area, plus, minus, detail in rows:
        t.add_row(area, count(plus, "+"), count(minus, "-"), detail)
    extra = []
    if m.get("launcher"):
        extra.append(f"launcher {m['launcher']['before']} → {m['launcher']['after']}")
    if m["application"]:
        extra.append("application: " + _few(sorted(m["application"])))
    if m["components_changed"]:
        extra.append(f"{len(m['components_changed'])} components changed")
    if extra:
        t.add_row("Manifest", Text(""), Text(""), " · ".join(extra))
    c.print(t)

    found = [x for x in caps.get("capabilities", []) if not x.startswith("NEW_NETWORK_ENDPOINTS")]
    tone = "hostile" if (found or endpoints) and ov["label"] != "IMPOSTOR" else "quiet"
    lines: list[Text] = [Text(line, style=f"bold {ui.PALE}")]
    for cap, why in sorted((caps.get("evidence") or {}).items()):
        lines.append(Text.assemble((f"• {display.get(cap, cap)}: ", f"bold {ui.AMBER}"), (_few(list(why), 2), ui.SOFT)))
    c.print()
    c.print(ui.panel(Group(*lines), "Capabilities", tone=tone))
