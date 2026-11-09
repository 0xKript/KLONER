"""Reports and exports (§15). All formats render from the canonical JSON document."""

from __future__ import annotations

from pathlib import Path
from typing import Any

FORMATS = ("terminal", "json", "md", "html", "csv", "iocs", "stix21")
FILE_NAMES = {
    "json": "report.json",
    "md": "report.md",
    "html": "report.html",
    "csv": "samples.csv",
    "iocs": "iocs.txt",
    "stix21": "stix21.json",
}


def write_reports(doc: dict[str, Any], out_dir: Path, formats: list[str]) -> list[Path]:
    from kloner.report import html, ioc, jsonout, markdown, stix

    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for fmt in formats:
        if fmt == "terminal":
            continue
        path = out_dir / FILE_NAMES[fmt]
        if fmt == "json":
            path.write_bytes(jsonout.dumps(doc))
        elif fmt == "md":
            path.write_text(markdown.render(doc), encoding="utf-8")
        elif fmt == "html":
            path.write_text(html.render(doc), encoding="utf-8")
        elif fmt == "csv":
            path.write_text(ioc.samples_csv(doc), encoding="utf-8")
        elif fmt == "iocs":
            path.write_text(ioc.iocs_txt(doc), encoding="utf-8")
            (out_dir / "iocs.csv").write_text(ioc.iocs_csv(doc), encoding="utf-8")
            written.append(out_dir / "iocs.csv")
        elif fmt == "stix21":
            path.write_text(stix.bundle(doc), encoding="utf-8")
        written.append(path)
    return written


def parse_formats(value: str) -> list[str]:
    out = []
    for f in (x.strip().lower() for x in value.split(",") if x.strip()):
        if f not in FORMATS:
            raise ValueError(f"unknown format {f!r}; choose from {', '.join(FORMATS)}")
        out.append(f)
    return out
