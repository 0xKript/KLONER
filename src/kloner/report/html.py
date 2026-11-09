"""Self-contained HTML report (§15.3): no external assets, autoescaped."""

from __future__ import annotations

from typing import Any

from jinja2 import Environment, PackageLoader, select_autoescape


def render(doc: dict[str, Any]) -> str:
    env = Environment(
        loader=PackageLoader("kloner.report", "templates"),
        autoescape=select_autoescape(["html", "j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    tpl = env.get_template("report.html.j2")
    return tpl.render(**doc, findings_by={f["sample_sha256"]: f for f in doc["findings"]})
