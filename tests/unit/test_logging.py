"""Structured JSON-lines logging (§16.5): run IDs, no credentials, no query strings."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from kloner.util.logging import bind_run, get_logger, log_event, safe_url, setup_logging


def test_safe_url_drops_query_fragment_and_user_info() -> None:
    assert safe_url("https://user:pw@cdn.example.org:8443/p/a.apk?token=abc&x=1#frag") == (
        "https://cdn.example.org:8443/p/a.apk"
    )
    assert safe_url("http://example.org/a.apk") == "http://example.org/a.apk"
    assert safe_url(None) is None
    assert safe_url("") == ""
    local = r"C:\samples\a.apk"
    assert safe_url(local) == local  # a local path is not a URL


def test_lines_carry_the_run_id_and_redact_secrets(tmp_path: Path) -> None:
    path = setup_logging(tmp_path, "session-1")
    log = get_logger("test")
    log_event(log, "first", event="x", aas_token="SECRET", password="hunter2", url="https://h/p")
    bind_run("2026-01-01T00-00-00Z")
    log_event(log, "second", event="y", count=2)
    root = logging.getLogger("kloner")
    for h in list(root.handlers):  # close the file so the temporary directory can be removed
        root.removeHandler(h)
        h.close()
    lines = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert [ln["event"] for ln in lines] == ["x", "y"]
    assert lines[0]["run_id"] == "session-1" and lines[1]["run_id"] == "2026-01-01T00-00-00Z"
    assert lines[0]["aas_token"] == "<redacted>" and lines[0]["password"] == "<redacted>"
    assert "SECRET" not in path.read_text(encoding="utf-8")
    assert lines[1]["count"] == 2 and lines[1]["logger"] == "kloner.test"
