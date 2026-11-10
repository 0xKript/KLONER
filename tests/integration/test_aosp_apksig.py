"""Real-file verdicts on AOSP apksig's official test APKs (Apache-2.0), pinned by commit and SHA-256 (D-057).

The files are fetched once into a cache outside the repository (``scripts/fetch_aosp_apksig.py``); nothing is
committed. Every case evaluates one file with an anchor made of AOSP's public test certificates and must reach
exactly the verdict and the labels recorded in ``tests/aosp/manifest.json``.
"""

from __future__ import annotations

import base64
import importlib.util
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import ModuleType
from typing import Any

import httpx
import pytest

from kloner.anchor.store import seal
from kloner.app import Runtime
from kloner.decide import decide
from kloner.models import Anchor, Identity

ROOT = Path(__file__).parents[2]


def _fetcher() -> ModuleType:
    spec = importlib.util.spec_from_file_location("fetch_aosp_apksig", ROOT / "scripts" / "fetch_aosp_apksig.py")
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


FETCH = _fetcher()
MANIFEST: dict[str, Any] = FETCH.load_manifest()
CERTS = {c["file"].split(".x509")[0]: c["cert_sha256"] for c in MANIFEST["certs"]}


@pytest.fixture(scope="module")
def aosp_dir() -> Path:
    try:
        out: Path = FETCH.fetch(MANIFEST)
    except FETCH.FetchError as e:
        if os.environ.get("CI"):
            raise
        pytest.skip(f"AOSP apksig test files unavailable: {e}")
    return out


def _anchor(package: str, refs: list[str]) -> Anchor:
    digests = [r.removeprefix("sha256:") if r.startswith("sha256:") else CERTS[r] for r in refs]
    return seal(
        Anchor(
            package=package,
            created_utc="2026-01-01T00:00:00Z",
            refreshed_utc="2026-01-01T00:00:00Z",
            identities=[Identity(id=f"id-{i + 1}", cert_sha256=d) for i, d in enumerate(digests)],
            corroboration="USER_ASSERTED",
        )
    )


@pytest.mark.toolchain
def test_every_aosp_case_reaches_its_recorded_verdict(rt: Runtime, aosp_dir: Path) -> None:
    pipe = rt.pipeline()

    def run(entry: dict[str, Any]) -> list[str]:
        sha, _ = rt.quarantine.ingest_file(aosp_dir / entry["file"], 1 << 30)
        facts, _ = pipe.facts(sha, None)
        package = facts.manifest.package if facts.manifest and facts.manifest.package else None
        failures = []
        for case in entry["cases"]:
            anchors = {package: _anchor(package, case["anchor"])} if package and case["anchor"] else {}
            ev = decide(facts, anchors, rt.known_keys)
            got = (ev.verdict.value, sorted(ev.label_codes()))
            want = (case["verdict"], sorted(case["labels"]))
            if got != want:
                failures.append(f"{entry['file']} anchor={case['anchor']}: got {got}, want {want}")
        return failures

    with ThreadPoolExecutor(max_workers=rt.worker_count()) as pool:
        failures = [f for fs in pool.map(run, MANIFEST["apks"]) for f in fs]
    assert not failures, "\n".join(failures)


def test_manifest_is_pinned_and_covers_every_verdict_path() -> None:
    entries = [MANIFEST["license"], *MANIFEST["certs"], *MANIFEST["apks"]]
    assert all(e.get("sha256") and e.get("git_blob") for e in entries)
    assert not any(str(e["file"]).endswith(".pk8") for e in entries)  # private keys are never fetched
    assert MANIFEST["spdx_license"] == "Apache-2.0" and "Apache License" in MANIFEST["notice"]
    verdicts = {c["verdict"] for e in MANIFEST["apks"] for c in e["cases"]}
    assert {"GENUINE", "TAMPERED", "FORGED", "INVALID", "ANOMALY", "ERROR", "UNANCHORED"} <= verdicts
    labels = {lab for e in MANIFEST["apks"] for c in e["cases"] for lab in c["labels"]}
    assert {
        "ROTATED_KEY",
        "MIXED_SIGNERS",
        "KNOWN_PUBLIC_KEY:AOSP_TESTKEY",
        "SCHEME_STRIPPED",
        "ZIP_AMBIGUITY",
    } <= labels
    assert {"CONTENT_MODIFIED_UNDER_OFFICIAL_SIGNATURE", "UNSIGNED_BLOCK_DATA", "PLAY_SOURCE_STAMP"} <= labels


def test_fetch_refuses_bytes_that_are_not_pinned(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KLONER_AOSP_CACHE", str(tmp_path))
    manifest = {**MANIFEST, "certs": [], "apks": []}

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=base64.b64encode(b"not the Apache license"))

    client = FETCH.Client(transport=httpx.MockTransport(handler), interval_s=0)
    with pytest.raises(FETCH.FetchError, match="git blob id"):
        FETCH.fetch(manifest, client=client)
    assert not (tmp_path / str(MANIFEST["commit"]) / "LICENSE").exists()
