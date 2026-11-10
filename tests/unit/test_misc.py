"""Toolchain helpers, process supervision, bridge failure handling, quarantine, logging, export, doctor."""

from __future__ import annotations

import json
import logging
import sys
import zipfile
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from kloner.acquire.quarantine import Quarantine, QuarantineError
from kloner.toolchain import (
    BUILD_TOOLS_FLOOR,
    Toolchain,
    ToolchainError,
    java_major,
    load_toolchain,
    parse_revision,
)
from kloner.util import proc
from kloner.util.hashing import sha256_bytes, sha256_stream
from kloner.util.logging import get_logger, log_event, setup_logging


def test_revision_and_java_parsing() -> None:
    assert parse_revision("36.0.0") == (36, 0, 0) >= BUILD_TOOLS_FLOOR
    assert parse_revision("34.0.0 rc3") == (34, 0, 0) < BUILD_TOOLS_FLOOR
    assert parse_revision("junk") == (0, 0, 0)
    assert java_major('java version "17.0.12" 2024-07-16 LTS') == 17
    assert java_major('openjdk version "1.8.0_392"') == 8
    assert java_major("nothing") is None


def test_proc_run_handles_timeouts_and_missing_tools(tmp_path: Path) -> None:
    ok = proc.run([sys.executable, "-c", "print('hi')"], timeout_s=60)
    assert ok.ok and ok.text().strip() == "hi"
    slow = proc.run([sys.executable, "-c", "import time; time.sleep(30)"], timeout_s=0.5)
    assert slow.timed_out and not slow.ok
    missing = proc.run([str(tmp_path / "no-such-tool")], timeout_s=5)
    assert missing.returncode is None and not missing.ok
    env = proc.minimal_env({"EXTRA": "1"})
    assert env["EXTRA"] == "1" and "PATH" in env


def test_quarantine_layout_and_limits(tmp_path: Path) -> None:
    q = Quarantine(tmp_path)
    sha, size = q.ingest_bytes(b"sample", 100)
    assert size == 6 and q.has(sha) and q.path_for(sha).name == sha
    assert q.path_for(sha).parent.parent.name == sha[:2]
    assert q.ingest_bytes(b"sample", 100) == (sha, 6)  # deduplicated
    with pytest.raises(QuarantineError):
        q.ingest_bytes(b"x" * 101, 100)
    with pytest.raises(QuarantineError):
        q.path_for("../../etc/passwd")
    ev = q.write_evidence(sha, {"source": "test"})
    assert json.loads(ev.read_text())["source"] == "test"
    q.remove(sha)
    assert not q.has(sha)
    assert list(q.incoming.iterdir()) == []


def test_hash_stream(tmp_path: Path) -> None:
    p = tmp_path / "f"
    p.write_bytes(b"abcdef")
    with p.open("rb") as f:
        assert sha256_stream(f, 3) == sha256_bytes(b"abc")


def test_logging_redacts_secrets(tmp_path: Path) -> None:
    path = setup_logging(tmp_path, "run-1", debug=True)
    log = get_logger("test")
    log_event(log, "fetch", url="https://x.example", aas_token="secret-value", status=200)
    try:
        raise ValueError("boom")
    except ValueError:
        log.exception("failed")
    for h in logging.getLogger("kloner").handlers:
        h.flush()
    lines = [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines()]
    assert lines[0]["aas_token"] == "<redacted>" and lines[0]["run_id"] == "run-1" and lines[0]["status"] == 200
    assert "exc" in lines[1]


@pytest.mark.toolchain
def test_bridge_failures_are_contained(rt: Any) -> None:
    from kloner.verify.bridge import BridgeClient, BridgeFailure

    tc: Toolchain = rt.toolchain()
    crash = BridgeClient(replace(tc, java=sys.executable), timeout_s=30)
    with pytest.raises(BridgeFailure):
        crash.verify(Path("x.apk"), 24, 30)
    crash.close()
    slow = BridgeClient(tc, timeout_s=0.001)
    with pytest.raises(BridgeFailure):
        slow.verify(Path("x.apk"), 24, 30)
    assert slow.restarts >= 1
    slow.close()
    good = BridgeClient(tc, timeout_s=60)
    v = good.version()
    from kloner.toolchain import BRIDGE_VERSION

    assert v["bridge_version"] == BRIDGE_VERSION
    res = good.verify(Path("definitely-missing.apk"), 24, 30)
    assert res.fatal and not res.verified
    good.close()


@pytest.mark.toolchain
def test_toolchain_lock_and_doctor(rt: Any, tmp_path: Path) -> None:
    from kloner.doctor import run_doctor

    with pytest.raises(ToolchainError):
        load_toolchain(tmp_path)
    checks = run_doctor(rt, network=False)
    names = {c.name: c.status for c in checks}
    assert names["bridge"] == "PASS" and names["apksig"] == "PASS" and names["aapt2"] == "PASS"
    assert names["apkeep"] in ("PASS", "WARN")


def test_installer_refuses_unsafe_archives(tmp_path: Path) -> None:
    from kloner.toolchain_install import _safe_extract

    good = tmp_path / "good.zip"
    with zipfile.ZipFile(good, "w") as z:
        z.writestr("cmdline-tools/bin/sdkmanager", "#!/bin/sh\n")
    _safe_extract(good, tmp_path / "out")
    assert (tmp_path / "out" / "cmdline-tools" / "bin" / "sdkmanager").is_file()
    bad = tmp_path / "bad.zip"
    with zipfile.ZipFile(bad, "w") as z:
        z.writestr("../outside.txt", "x")
    with pytest.raises(ToolchainError):
        _safe_extract(bad, tmp_path / "out2")
    assert not (tmp_path / "outside.txt").exists()


@pytest.mark.toolchain
def test_export_requires_7zip_or_samples(rt: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    import shutil as sh

    from kloner.export import export_samples

    monkeypatch.setattr(sh, "which", lambda name: None)
    with pytest.raises(ValueError, match="7-Zip"):
        export_samples(rt, "no-run", "infected", None)


def test_closed_stdout_keeps_the_run_exit_code(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """`kloner hunt … | head` must still exit 10/11/0, not Python's 120 (found in the live trial)."""
    from kloner.cli import exit_keeping_code

    target = open(tmp_path / "stdout.txt", "w", encoding="utf-8")  # noqa: SIM115 - fd is replaced below

    class ClosedPipe:
        def flush(self) -> None:
            raise BrokenPipeError(32, "Broken pipe")

        def fileno(self) -> int:
            return target.fileno()

    monkeypatch.setattr(sys, "stdout", ClosedPipe())
    with pytest.raises(SystemExit) as exc:
        exit_keeping_code(10)
    assert exc.value.code == 10
    target.close()


def test_toolchain_dir_can_live_outside_the_home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """The Docker image keeps its toolchain outside the /kloner data volume (D-051)."""
    from kloner.toolchain import lock_path, toolchain_dir

    monkeypatch.delenv("KLONER_TOOLCHAIN", raising=False)
    assert toolchain_dir(tmp_path / "home") == tmp_path / "home" / "toolchain"
    monkeypatch.setenv("KLONER_TOOLCHAIN", str(tmp_path / "opt"))
    assert toolchain_dir(tmp_path / "home") == tmp_path / "opt"
    assert lock_path(tmp_path / "home") == tmp_path / "opt" / "toolchain.json"


def test_client_profile_records_user_agent_and_proxy() -> None:
    """Every sighting records the client profile used (T-17 selective serving, multi-vantage fetching)."""
    from kloner.acquire.http import Http
    from kloner.acquire.sources import _profile

    h = Http("kloner-test/1", proxy="http://127.0.0.1:3128")
    try:
        p = _profile(h)
    finally:
        h.close()
    assert p.user_agent == "kloner-test/1" and p.proxy == "http://127.0.0.1:3128"


@pytest.mark.toolchain
def test_an_unpinned_apksigner_jar_is_refused(rt: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """INV-7: setup and doctor refuse any apksigner.jar whose SHA-256 is not the pinned one."""
    import kloner.toolchain as tcmod
    from kloner.doctor import run_doctor

    bt = tmp_path / "sdk" / "build-tools" / "36.0.0"
    (bt / "lib").mkdir(parents=True)
    fake = bt / "lib" / "apksigner.jar"
    fake.write_bytes(b"not the pinned apksig")
    monkeypatch.setattr(tcmod, "find_build_tools", lambda home: (tmp_path / "sdk", bt, "36.0.0"))
    with pytest.raises(ToolchainError, match="not the pinned value"):
        tcmod.setup(tmp_path / "home", install_apkeep_binary=False, user_agent="kloner-tests")
    import kloner.doctor as doctor_mod

    tampered = replace(rt.toolchain(), apksigner_jar=str(fake))
    monkeypatch.setattr(doctor_mod, "load_toolchain", lambda home: tampered)
    apksig = next(c for c in run_doctor(rt, network=False) if c.name == "apksig")
    assert apksig.status == "FAIL" and apksig.critical


def test_apkeep_download_is_checksum_verified(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """A downloaded apkeep binary whose SHA-256 is not the pinned digest is discarded, never installed."""
    import contextlib
    from collections.abc import Iterator

    import httpx

    import kloner.toolchain as tcmod

    class Resp:
        def raise_for_status(self) -> None:
            return None

        def iter_bytes(self) -> Iterator[bytes]:
            yield b"not the pinned apkeep"

    @contextlib.contextmanager
    def fake_stream(*args: Any, **kwargs: Any) -> Iterator[Resp]:
        yield Resp()

    monkeypatch.delenv("KLONER_TOOLCHAIN", raising=False)
    monkeypatch.setattr(tcmod, "apkeep_asset", lambda: ("apkeep-x86_64-unknown-linux-gnu", "0" * 64))
    monkeypatch.setattr(httpx, "stream", fake_stream)
    with pytest.raises(ToolchainError, match="checksum mismatch"):
        tcmod.install_apkeep(tmp_path, "kloner-tests")
    assert not [p for p in (tmp_path / "toolchain" / "apkeep").rglob("*") if p.is_file()]


def test_a_stale_compiled_bridge_is_refused(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """The bridge protocol changed (v2 adds RSA-PSS on desktop JDKs): an older compiled bridge must be rebuilt."""
    import kloner.toolchain as tcmod

    tc = Toolchain(
        home=str(tmp_path),
        java="java",
        javac=None,
        java_version="17",
        sdk_root=str(tmp_path),
        build_tools=str(tmp_path),
        build_tools_version="36.0.0",
        apksigner_jar=str(tmp_path / "apksigner.jar"),
        apksigner_jar_sha256="ab" * 32,
        aapt2=str(tmp_path / "aapt2"),
        d8_jar=str(tmp_path / "d8.jar"),
        platform_jar=None,
        bridge_classes=str(tmp_path),
    )
    old = json.dumps({"bridge_version": "1", "apksig_jar_sha256": "ab" * 32, "java_version": "17"}).encode()
    monkeypatch.setattr(tcmod.proc, "run", lambda *a, **k: proc.ProcResult(("java",), 0, old, b"", False, 0.1))
    with pytest.raises(ToolchainError, match="run: kloner setup"):
        tcmod.bridge_round_trip(tc)
