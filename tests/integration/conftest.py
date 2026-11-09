from __future__ import annotations

import json
import shutil
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from kloner.acquire.http import Http
from kloner.app import Runtime

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def fresh_rt(toolchain_home: Path, tmp_path: Path) -> Iterator[Runtime]:
    """A new KLONER home sharing the session's compiled toolchain (fresh anchors, DB, quarantine)."""
    home = tmp_path / "home"
    (home / "toolchain").mkdir(parents=True)
    shutil.copy(toolchain_home / "toolchain" / "toolchain.json", home / "toolchain" / "toolchain.json")
    (home / "config.toml").write_text('[sources]\nenabled = ["local", "url"]\n', encoding="utf-8")
    rt = Runtime.open(home, workers=2)
    yield rt
    rt.close()


def mock_http(rt: Runtime, handler: Callable[[httpx.Request], httpx.Response]) -> Http:
    transport = httpx.MockTransport(handler)
    http = Http("kloner-tests", rate_per_host=1000.0, retries=1, transport=transport)
    rt._http = http
    rt.transport = transport
    return http


def fixture_json(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))
