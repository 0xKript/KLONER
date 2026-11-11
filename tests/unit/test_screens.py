"""The terminal design (D-069): every verdict, gate, source state and option is explained, every screen renders at
any width with or without color, and the look never reaches stdout of --json, report files or exit codes."""

from __future__ import annotations

import io
import json
import re
from pathlib import Path
from types import SimpleNamespace
from typing import Any, get_args

import pytest
import typer
from rich.console import Console
from typer.testing import CliRunner

from kloner import cli, ui
from kloner.models import VERDICT_CLASS, SourceRunStatus, SourceStatus, Verdict
from kloner.report.terminal import render

ROOT = Path(__file__).resolve().parents[2]
ANSI = re.compile(r"\x1b\[")
runner = CliRunner()
CLASS = {"Hostile": "hostile", "Review": "review", "Clean": "clean", "Not applicable": "other"}


def test_every_verdict_has_a_look_and_a_meaning() -> None:
    assert set(ui.VERDICTS) == {v.value for v in Verdict}
    assert [v.value for v in Verdict] == ui.ORDER  # severity order, as docs/VERDICTS.md
    for v in Verdict:
        icon, pill, text, klass, meaning = ui.VERDICTS[v.value]
        assert icon and pill and text and meaning.endswith(".")
        assert klass == CLASS[VERDICT_CLASS[v]], v
    assert set(ui.SCREEN_ORDER) == set(ui.VERDICTS)


def test_every_gate_and_source_state_has_a_name() -> None:
    gates = set(re.findall(r'ctx\.step\("(G\d)"', (ROOT / "src" / "kloner" / "decide.py").read_text(encoding="utf-8")))
    assert gates and gates <= set(ui.GATES)
    assert set(get_args(SourceRunStatus)) <= set(ui.SOURCE_STATE)
    assert set(ui.CORROBORATION) == {"CORROBORATED", "SINGLE_OFFICIAL", "USER_ASSERTED"}


def test_every_option_and_command_is_explained() -> None:
    # "A million things appear and I do not know what they do": no command and no option without a help text.
    root = typer.main.get_command(cli.app)

    def walk(cmd: Any, path: str) -> list[str]:
        missing = [] if (cmd.help or "").strip() else [path]
        for p in cmd.params:
            if getattr(p, "help", None) is None and p.name != "help":
                missing.append(f"{path} {p.name}")
        for name, sub in getattr(cmd, "commands", {}).items():
            missing += walk(sub, f"{path} {name}")
        return missing

    assert walk(root, "kloner") == []


def test_help_follows_the_three_steps() -> None:
    r = runner.invoke(cli.app, ["--help"], env={"COLUMNS": "120", "NO_COLOR": "1"})
    assert r.exit_code == 0
    # on GitHub Actions Typer forces a terminal: NO_COLOR drops the colors but keeps bold, so strip every code
    out = re.sub(r"\x1b\[[0-9;]*m", "", r.output)
    steps = [
        out.index(t)
        for t in ("How it works", "Step 1 · Anchor", "Step 2 · Hunt", "Step 3 · Inspect", "Setup and health")
    ]
    assert steps == sorted(steps), steps
    for name in ("anchor", "hunt", "verify", "fetch", "survey", "explain", "diff", "report", "reverify", "doctor"):
        assert re.search(rf"\b{name}\b", out), name


def _doc(exit_code: int = 10) -> dict[str, Any]:
    official = "d8af" + "0" * 57 + "dea"
    foreign = "6581" + "1" * 57 + "0a1"

    def sample(verdict: str, sha: str, signer: str | None, labels: list[str], forensic: list[str]) -> dict[str, Any]:
        trust = "T" if signer == official else "none"
        return {
            "evaluation": {
                "verdict": verdict,
                "sample_sha256": sha * 64,
                "version_name": "1.0",
                "version_code": 1,
                "package": "dev.kloner.fixture",
                "labels": [{"code": c, "severity": "alert"} for c in labels],
                "signers": [{"cert_sha256": signer, "trust": trust}] if signer else [],
                "explanation": f"An explanation of {verdict}.",
            },
            "sightings": [{"source": "aptoide", "store": "catappult"}, {"source": "fdroid", "store": None}],
            "forensic_labels": forensic,
            "intel_labels": [],
            "lookalikes": [],
            "impersonation_candidate": False,
        }

    samples = [
        sample("GENUINE", "a", official, [], []),
        sample("FORGED", "b", foreign, ["DEBUG_DN"], ["REPACKAGED", "SHARED_FOREIGN_SIGNER"]),
        sample("MISMATCH", "c", foreign, [], []),
        sample("INVALID", "d", None, [], []),
    ]
    return {
        "run": {
            "id": "2026-11-11T00-00-00Z",
            "command": "hunt",
            "package": "dev.kloner.fixture",
            "kloner_version": "1.0.0",
            "apksig_version": "build-tools 36.0.0",
        },
        "anchor": {"package": "dev.kloner.fixture", "record_sha256": "e" * 64, "corroboration": "CORROBORATED"},
        "coverage": {
            "statement": "Evaluated 4 unique files (8 sightings) from 2 of 3 sources — aptoide OK, apkpure ERROR.",
            "sources": [
                {"source": "aptoide", "status": "OK", "fetched": 3, "offers": 3, "stores": ["catappult", "apps"]},
                {"source": "fdroid", "status": "NO_OFFERS", "fetched": 0, "offers": 0, "stores": []},
                {"source": "apkpure", "status": "ERROR", "fetched": 0, "offers": 0, "stores": []},
            ],
            "unique_files": 4,
            "sightings": 8,
        },
        "samples": samples,
        "findings": [
            {
                "sample_sha256": "b" * 64,
                "capabilities": {"line": "Injected: SMS interception"},
                "reference": {"sha256": "a" * 64},
            }
        ],
        "intel": [{"sample_sha256": "b" * 64, "text": "Forger key 6581…0a1 also signed other copies."}],
        "notes": ["apkpure: ERROR"],
        "summary": {"counts": {"FORGED": 1, "MISMATCH": 1, "INVALID": 1, "GENUINE": 1}, "exit_code": exit_code},
    }


@pytest.mark.parametrize("width", [40, 80, 120, 160])
@pytest.mark.parametrize("color", [True, False])
def test_the_hunt_screen_renders_at_any_width(width: int, color: bool) -> None:
    buf = io.StringIO()
    console = Console(
        file=buf, width=width, force_terminal=color, no_color=not color, color_system="truecolor" if color else None
    )
    render(_doc(), console, ["/tmp/run/report.json", "/tmp/run/report.html"])
    out = buf.getvalue()
    plain = ANSI.sub("", out) if color else out
    assert bool(ANSI.search(out)) == color
    for word in (
        "FORGED",
        "GENUINE",
        "MISMATCH",
        "INVALID",
        "official",
        "Coverage:",
        "Exit 10",
        "What this means",
        "Top finding",
        "Injected: SMS interception",
        "apkpure",
    ):
        assert word in plain.replace("\n", " ") or word in plain, (word, width)
    # the most serious first: FORGED is listed before GENUINE, whatever the order in the document
    assert plain.index("✗ FORGED") < plain.index("✓ GENUINE")
    # the next steps carry full, copyable commands
    flat = plain.replace("\n", "")
    assert f"kloner explain {'b' * 64}" in flat and f"--against {'a' * 64}" in flat


def test_exit_lines_and_next_steps_for_clean_and_review_runs() -> None:
    doc = _doc(exit_code=0)
    doc["samples"] = [doc["samples"][0]]
    doc["findings"] = []
    doc["summary"]["counts"] = {"GENUINE": 1}
    buf = io.StringIO()
    render(doc, Console(file=buf, width=100, no_color=True))
    out = buf.getvalue()
    assert "Exit 0 — no hostile copies, no review items" in out and "kloner reverify 2026-11-11T00-00-00Z" in out
    doc["samples"][0]["evaluation"]["verdict"] = "ANOMALY"
    doc["summary"] = {"counts": {"ANOMALY": 1}, "exit_code": 11}
    buf = io.StringIO()
    render(doc, Console(file=buf, width=100, no_color=True))
    assert "Exit 11" in buf.getvalue() and f"kloner explain {'a' * 64}" in buf.getvalue()


def test_the_spinner_never_writes_to_stdout(capsys: pytest.CaptureFixture[str]) -> None:
    with ui.working("busy"):
        pass
    with ui.working("busy", enabled=False):
        pass
    captured = capsys.readouterr()
    assert captured.out == "" and captured.err == ""


class _FakeRuntime:
    def close(self) -> None:
        return None


def test_doctor_screen_says_ready_or_not(monkeypatch: pytest.MonkeyPatch) -> None:
    from kloner import doctor

    checks = [
        doctor.Check("kloner", "PASS", "version 1.0.0", "", True),
        doctor.Check("apkeep", "WARN", "not installed", "kloner setup", False),
    ]
    monkeypatch.setattr(cli, "_runtime", lambda *a, **k: _FakeRuntime())
    monkeypatch.setattr(doctor, "run_doctor", lambda rt: checks)
    r = runner.invoke(cli.app, ["doctor"], env={"COLUMNS": "100", "NO_COLOR": "1"})
    assert r.exit_code == 0, r.output
    assert "✓ PASS" in r.output and "▲ WARN" in r.output and "fix: kloner setup" in r.output
    assert "Ready, with warnings" in r.output and "Next: kloner selftest" in r.output
    checks.append(doctor.Check("bridge", "FAIL", "no JDK", "kloner setup", True))
    r = runner.invoke(cli.app, ["doctor"], env={"COLUMNS": "100", "NO_COLOR": "1"})
    assert r.exit_code == 4 and "Not ready" in r.output and "Next: kloner setup" in r.output
    js = runner.invoke(cli.app, ["--json", "doctor"])
    assert js.exit_code == 4 and [c["name"] for c in json.loads(js.stdout)] == ["kloner", "apkeep", "bridge"]


def test_survey_screen_lists_signers_and_gives_no_verdict(monkeypatch: pytest.MonkeyPatch) -> None:
    from kloner import hunt

    row = SimpleNamespace(
        cert_sha256="f" * 64,
        subject="CN=Someone",
        verified=True,
        known_key=None,
        samples=["x", "y"],
        versions={"1.0"},
        sources={"aptoide"},
    )

    statuses = [
        SourceStatus(source="aptoide", status="OK", offers=2, fetched=2),
        SourceStatus(source="fdroid", status="NO_OFFERS"),
    ]
    monkeypatch.setattr(cli, "_runtime", lambda *a, **k: _FakeRuntime())
    monkeypatch.setattr(hunt, "run_survey", lambda rt, package, sources, limit: ([row], statuses, 2))
    r = runner.invoke(cli.app, ["survey", "com.example.app"], env={"COLUMNS": "120", "NO_COLOR": "1"})
    assert r.exit_code == 0, r.output
    assert "f" * 32 in r.output and "✓ verified" in r.output and "No verdicts" in r.output
    assert "Next: kloner anchor add com.example.app" in r.output.replace("\n", "")
    js = runner.invoke(cli.app, ["--json", "survey", "com.example.app"])
    assert json.loads(js.stdout)["signers"][0]["samples"] == 2
