"""Shared fixtures: a throwaway KLONER home with the real toolchain, and the synthetic corpus.

Toolchain-dependent tests are skipped when no JDK 17+ or Android build-tools 36.0.0 is available.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from rich.console import Console

from kloner.app import Runtime
from kloner.toolchain import ToolchainError, setup


@pytest.fixture(scope="session")
def home(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return tmp_path_factory.mktemp("kloner-home")


@pytest.fixture(scope="session")
def toolchain_home(home: Path) -> Path:
    try:
        setup(home, install_apkeep_binary=False, user_agent="kloner-tests")
    except ToolchainError as e:
        pytest.skip(f"toolchain unavailable: {e}")
    return home


@pytest.fixture(scope="session")
def rt(toolchain_home: Path) -> Iterator[Runtime]:
    r = Runtime.open(toolchain_home, workers=min(4, os.cpu_count() or 2))
    yield r
    r.close()


@pytest.fixture(scope="session")
def corpus(rt: Runtime, tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    from kloner.selftest.runner import build

    work = tmp_path_factory.mktemp("corpus")
    cases, ctx = build(rt, work, Console(quiet=True))
    ctx["cases"] = {c.id: c for c in cases}
    return ctx


@pytest.fixture(scope="session")
def facts01(corpus: dict[str, Any]) -> Any:
    return corpus["facts01"]
