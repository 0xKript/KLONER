"""The release SBOM (§16.8) lists every locked package and the pinned toolchain, deterministically."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).parents[2]


def _script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("build_sbom", ROOT / "scripts" / "build_sbom.py")
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_sbom_covers_the_lock_and_the_toolchain(monkeypatch: pytest.MonkeyPatch) -> None:
    m = _script()
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1767225600")
    lock = ROOT / "requirements.lock"
    bom = m.build(lock)
    reqs = m.parse_lock(lock.read_text(encoding="utf-8"))
    libs = [c for c in bom["components"] if c["type"] == "library"]
    assert bom["bomFormat"] == "CycloneDX" and bom["specVersion"] == "1.5"
    assert bom["metadata"]["timestamp"] == "2026-01-01T00:00:00Z"
    assert len(libs) == len(reqs) > 20
    assert all(c["purl"].startswith("pkg:pypi/") and c["hashes"] for c in libs)
    assert {"androguard", "cryptography", "httpx", "pydantic", "typer", "rich", "stix2"} <= {c["name"] for c in libs}
    jar = next(c for c in bom["components"] if c["name"] == "apksigner.jar")
    assert jar["hashes"] == [
        {"alg": "SHA-256", "content": "3716d9311e55d2b0918a2fd9d54ba9e406c5f6abeea700b287f11259bc163dec"}
    ]
    assert len([c for c in bom["components"] if c["name"] == "apkeep"]) == 3
    assert m.build(lock) == bom  # deterministic, serial number included


def test_lock_parser_reads_markers_and_continuation_hashes() -> None:
    m = _script()
    text = (
        "# header\n"
        "Foo_Bar==1.2 ; python_full_version < '3.12' \\\n"
        "    --hash=sha256:" + "a" * 64 + " \\\n"
        "    --hash=sha256:" + "b" * 64 + "\n"
        "    # via kloner\n"
        "baz==2.0 \\\n"
        "    --hash=sha256:" + "c" * 64 + "\n"
    )
    assert m.parse_lock(text) == [
        ("foo-bar", "1.2", ["a" * 64, "b" * 64], "python_full_version < '3.12'"),
        ("baz", "2.0", ["c" * 64], None),
    ]
