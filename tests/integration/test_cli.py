"""End-to-end CLI tests (P4-P7): anchors, verify, hunt, reports, reverify, explain, intel, exit codes."""

from __future__ import annotations

import json
import os
import shutil
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from kloner.cli import app

pytestmark = pytest.mark.toolchain
P = "dev.kloner.fixture"
GOLDEN = Path(__file__).parents[1] / "golden" / "hunt_projection.json"
runner = CliRunner()


@pytest.fixture(scope="module")
def cli_home(toolchain_home: Path, tmp_path_factory: pytest.TempPathFactory) -> Path:
    home = tmp_path_factory.mktemp("cli-home")
    (home / "toolchain").mkdir()
    shutil.copy(toolchain_home / "toolchain" / "toolchain.json", home / "toolchain" / "toolchain.json")
    (home / "config.toml").write_text('[sources]\nenabled = ["local"]\n[general]\nworkers = 2\n', encoding="utf-8")
    return home


@pytest.fixture(scope="module")
def drop(corpus: dict[str, Any], tmp_path_factory: pytest.TempPathFactory) -> Path:
    d = tmp_path_factory.mktemp("drop")
    for cid in ("C-01", "C-02", "C-03", "C-06", "C-15", "C-21", "C-22", "C-24", "C-25", "C-33", "X-02"):
        src = corpus["files"][cid]
        shutil.copy(src, d / f"{cid}{src.suffix}")
    return d


def k(home: Path, *args: str) -> Any:
    return runner.invoke(app, ["--home", str(home), *args], catch_exceptions=False)


@pytest.fixture()
def webhook() -> Iterator[tuple[str, list[dict[str, Any]]]]:
    """A local receiver for --notify-webhook; it records every JSON body it is sent."""
    received: list[dict[str, Any]] = []

    class Hook(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            body = self.rfile.read(int(self.headers.get("content-length", "0")))
            received.append(json.loads(body))
            self.send_response(204)
            self.end_headers()

        def log_message(self, format: str, *args: Any) -> None:
            return

    server = HTTPServer(("127.0.0.1", 0), Hook)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/hook", received
    finally:
        server.shutdown()
        server.server_close()


def test_version_and_help() -> None:
    assert runner.invoke(app, ["--version"]).output.startswith("kloner ")
    assert runner.invoke(app, ["--help"]).exit_code == 0


def test_end_to_end(
    cli_home: Path,
    drop: Path,
    corpus: dict[str, Any],
    tmp_path: Path,
    webhook: tuple[str, list[dict[str, Any]]],
) -> None:
    hook_url, posted = webhook
    # no anchor yet: usage error with the next command
    r = k(cli_home, "hunt", P, "--sources", "local", "--local", str(drop))
    assert r.exit_code == 2 and "kloner anchor add" in r.output

    r = k(cli_home, "anchor", "add", P, "--from-apk", str(corpus["files"]["C-01"]), "--brand-label", "Kloner Fixture")
    assert r.exit_code == 0, r.output
    assert "USER_ASSERTED" in r.output and "Next: kloner hunt" in r.output
    assert k(cli_home, "anchor", "show", P).exit_code == 0
    assert P in k(cli_home, "anchor", "list").output
    js = k(cli_home, "--json", "anchor", "show", P)
    assert json.loads(js.output)["package"] == P
    exported = tmp_path / "a.json"
    assert k(cli_home, "anchor", "export", P, str(exported)).exit_code == 0
    assert k(cli_home, "anchor", "import", str(exported)).exit_code == 0
    r = k(cli_home, "anchor", "add", P, "--from-apk", str(corpus["files"]["C-02"]))
    assert r.exit_code == 3 and "CONFLICT" in r.output

    r = k(cli_home, "hunt", P, "--require-corroborated", "--sources", "local", "--local", str(drop))
    assert r.exit_code == 2 and "USER_ASSERTED" in r.output

    assert k(cli_home, "verify", str(corpus["files"]["C-01"]), "--package", P).exit_code == 0
    js = k(cli_home, "--json", "verify", str(corpus["files"]["C-01"]), "--package", P)
    assert js.exit_code == 0 and json.loads(js.output)["samples"][0]["evaluation"]["verdict"] == "GENUINE"
    r = k(cli_home, "verify", str(corpus["files"]["C-02"]), "--package", P)
    assert r.exit_code == 10 and "FORGED" in r.output
    r = k(cli_home, "verify", str(corpus["files"]["C-33"]))  # SOC triage: every brand profile is checked
    assert r.exit_code == 10 and "IMPERSONATOR" in r.output

    out = tmp_path / "run"
    r = k(
        cli_home,
        "hunt",
        P,
        "--sources",
        "local",
        "--local",
        str(drop),
        "--out",
        str(out),
        "--format",
        "terminal,json,md,html,csv,iocs,stix21",
        "--notify-webhook",
        hook_url,
    )
    assert r.exit_code == 10, r.output
    assert "Coverage:" in r.output and "Exit 10" in r.output
    assert len(posted) == 1 and set(posted[0]) == {"run", "summary", "coverage"}
    assert posted[0]["summary"]["exit_code"] == 10 and posted[0]["summary"]["hostile"] > 0
    assert posted[0]["coverage"].startswith("Evaluated ")
    for name in ("report.json", "report.md", "report.html", "samples.csv", "iocs.txt", "iocs.csv", "stix21.json"):
        assert (out / name).is_file(), name
    doc = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert doc["schema"] == "kloner.report/1" and doc["summary"]["exit_code"] == 10
    assert "Anchor not corroborated" in (out / "report.md").read_text(encoding="utf-8")
    assert "<!doctype html>" in (out / "report.html").read_text(encoding="utf-8")
    stix = json.loads((out / "stix21.json").read_text(encoding="utf-8"))
    assert stix["type"] == "bundle" and any(o["type"] == "indicator" for o in stix["objects"])
    errors = [f.get("error") for f in doc["findings"] if "FORENSICS_INCOMPLETE" in f["labels"]]
    assert not errors, errors
    projection = project(doc)
    if os.environ.get("KLONER_UPDATE_GOLDEN") == "1" or not GOLDEN.exists():
        GOLDEN.parent.mkdir(parents=True, exist_ok=True)
        GOLDEN.write_text(json.dumps(projection, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    assert projection == json.loads(GOLDEN.read_text(encoding="utf-8"))

    run_id = doc["run"]["id"]
    logged = [
        json.loads(line)
        for f in sorted((cli_home / "logs").glob("*.jsonl"))
        for line in f.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    events = [ln["event"] for ln in logged if ln.get("run_id") == run_id]
    assert events[0] == "run.start" and events[-1] == "run.finish", events
    assert {"source.discover", "fetch", "evaluate"} <= set(events)
    evals = [ln for ln in logged if ln.get("run_id") == run_id and ln["event"] == "evaluate"]
    assert len(evals) == len(doc["samples"]) and all(ln["seconds"] >= 0 for ln in evals)
    finish = next(ln for ln in logged if ln.get("run_id") == run_id and ln["event"] == "run.finish")
    assert finish["exit_code"] == 10

    r = k(cli_home, "reverify", run_id)
    assert r.exit_code == 0 and "IDENTICAL" in r.output, r.output
    r = k(cli_home, "report", run_id, "--format", "md,html,csv,iocs,stix21,json")
    assert r.exit_code == 0
    forged = next(s for s in doc["samples"] if s["evaluation"]["verdict"] == "FORGED")
    sha = forged["evaluation"]["sample_sha256"]
    r = k(cli_home, "explain", sha)
    assert r.exit_code == 0 and "G7" in r.output and "R-G7-FOREIGN-SIGNER" in r.output
    foreign_cert = next(s["cert_sha256"] for s in forged["evaluation"]["signers"] if s["trust"] == "none")
    assert sha in k(cli_home, "--json", "intel", "signer", foreign_cert).output
    assert k(cli_home, "intel", "package", P).exit_code == 0
    assert k(cli_home, "intel", "sources").exit_code == 0
    assert k(cli_home, "intel", "payload", "00" * 32).exit_code == 0
    r = k(cli_home, "diff", str(corpus["files"]["C-02"]), "--against", str(corpus["files"]["C-01"]))
    assert r.exit_code == 0 and "Injected:" in r.output and "Code overlap (heuristic): classes 1.00" in r.output
    # an unrelated app is not "injected" code (found on the live Signal sweep, D-063)
    js = k(cli_home, "--json", "diff", str(corpus["files"]["C-33"]), "--against", str(corpus["files"]["C-01"]))
    ov = json.loads(js.output)["overlap"]
    r = k(cli_home, "diff", str(corpus["files"]["C-33"]), "--against", str(corpus["files"]["C-01"]))
    assert r.exit_code == 0 and "Code overlap (heuristic)" in r.output
    assert ("not an injection" in r.output) == (ov["label"] == "IMPOSTOR")

    r = k(
        cli_home,
        "hunt",
        P,
        "--sources",
        "local",
        "--local",
        str(drop),
        "--new-only",
        "--format",
        "json",
        "--out",
        str(tmp_path / "run2"),
        "--notify-webhook",
        hook_url,
    )
    assert r.exit_code == 0
    doc2 = json.loads((tmp_path / "run2" / "report.json").read_text(encoding="utf-8"))
    assert doc2["samples"] == []
    assert len(posted) == 1  # nothing new and hostile: no notification

    r = k(cli_home, "export", "samples", "--run", run_id, "--out", str(tmp_path / "samples.zip"))
    assert r.exit_code in (0, 2)
    r = k(cli_home, "--json", "doctor")
    assert r.exit_code == 0 and json.loads(r.output)[0]["name"] == "kloner"


def project(doc: dict[str, Any]) -> dict[str, Any]:
    """Golden projection (§18.6): stable fields only (keys are random per corpus build)."""
    out = {}
    for s in doc["samples"]:
        names = sorted(Path(g["offer_url"]).name for g in s["sightings"])
        ev = s["evaluation"]
        out[",".join(names)] = {
            "verdict": ev["verdict"],
            "labels": [lab["code"] for lab in ev["labels"]],
            "forensic_labels": s["forensic_labels"],
            "members": sorted(m["evaluation"]["verdict"] for m in s["members"]),
        }
    return out


def test_errors_map_to_exit_codes(cli_home: Path, tmp_path: Path) -> None:
    empty = tmp_path / "empty-home"
    r = k(empty, "verify", str(tmp_path))
    assert r.exit_code == 4 and "kloner setup" in r.output
    r = k(cli_home, "anchor", "add", "not a package", "--from-fingerprint", "00" * 32)
    assert r.exit_code == 2
    r = k(cli_home, "anchor", "add", P)
    assert r.exit_code == 2 and "choose exactly one method" in r.output
    r = k(cli_home, "hunt", P, "--sources", "nonsense")
    assert r.exit_code == 2
    r = k(cli_home, "explain", "ab" * 32)
    assert r.exit_code == 2
    r = k(cli_home, "reverify", "no-such-run")
    assert r.exit_code == 2
