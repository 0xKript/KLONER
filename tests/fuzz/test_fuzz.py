"""Fuzzing (§18.4): every parser fed random and structure-aware mutated inputs.

Pass criteria: no uncaught exception (only the parsers' typed errors), every iteration under 1 s.
Iterations per target: KLONER_FUZZ_ITERATIONS (default 1000; the full budget is 10000).
"""

from __future__ import annotations

import contextlib
import os
import secrets
import struct
import time
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from kloner.container.detect import detect
from kloner.container.zipstrict import ZipFailure, open_archive, structural_gate, verify_crcs
from kloner.selftest.corpus import fixture_path
from kloner.util.limits import Limits
from kloner.verify import sigblock
from kloner.verify.lineage import LineageFormatError, parse_lineage, verify_lineage
from kloner.verify.manifest import parse_badging
from kloner.verify.v1pkcs7 import parse_signed_data

N = int(os.environ.get("KLONER_FUZZ_ITERATIONS", "1000"))
LIMITS = Limits(max_file_bytes=8 << 20, max_entries=4096, max_total_uncompressed=64 << 20)
R = secrets.SystemRandom()


def mutate(data: bytes, hot: list[tuple[int, int]] | None = None) -> bytes:
    b = bytearray(data)
    op = R.randrange(7)
    if not b:
        return bytes(R.getrandbits(8) for _ in range(R.randrange(64)))
    if op == 0:
        for _ in range(R.randrange(1, 9)):
            i = R.randrange(len(b))
            b[i] ^= 1 << R.randrange(8)
    elif op == 1:
        del b[R.randrange(len(b)) :]
    elif op == 2:
        i = R.randrange(len(b))
        b[i:i] = bytes(R.getrandbits(8) for _ in range(R.randrange(1, 64)))
    elif op == 3 and hot:
        start, end = R.choice(hot)
        i = R.randrange(start, max(start + 1, end))
        width = R.choice((2, 4))
        if i + width <= len(b):
            b[i : i + width] = R.choice(
                (b"\xff" * width, b"\x00" * width, struct.pack("<I", R.getrandbits(32))[:width])
            )
    elif op == 4:
        i = R.randrange(len(b))
        j = min(len(b), i + R.randrange(1, 256))
        b[i:i] = b[i:j]
    elif op == 5:
        b = bytearray(bytes(R.getrandbits(8) for _ in range(R.randrange(1, 4096))))
    else:
        i = R.randrange(len(b))
        b[i] = R.getrandbits(8)
    return bytes(b)


def run_target(
    name: str,
    seeds: list[bytes],
    fn: Callable[[bytes], Any],
    allowed: tuple[type[BaseException], ...],
    hot: list[tuple[int, int]] | None = None,
) -> None:
    worst = 0.0
    for _ in range(N):
        data = mutate(R.choice(seeds), hot)
        t0 = time.perf_counter()
        with contextlib.suppress(allowed):
            fn(data)
        worst = max(worst, time.perf_counter() - t0)
    assert worst < 1.0, f"{name}: slowest iteration took {worst:.2f}s"


@pytest.fixture(scope="module")
def seeds(corpus: dict[str, Any]) -> dict[str, Any]:
    signed = corpus["files"]["C-15"].read_bytes()
    modern = fixture_path("modern").read_bytes()
    with zipfile.ZipFile(corpus["files"]["C-01"]) as z:
        rsa = next(z.read(n) for n in z.namelist() if n.upper().endswith(".RSA"))
    a = open_archive(corpus["files"]["C-15"], LIMITS)
    blk = sigblock.locate(a, LIMITS)
    assert blk is not None
    v3 = next(v for pid, _, v in blk.pairs if pid == sigblock.V3_BLOCK_ID)
    por = next(v for aid, v in sigblock._parse_signers(v3, True, LIMITS)[0].attrs if aid == sigblock.POR_ATTR_ID)
    hot = [(blk.start, blk.end), (a.cd_offset, a.size)]
    return {"signed": signed, "modern": modern, "rsa": rsa, "por": por, "hot": hot, "blk": blk}


def _zip(tmp: Path) -> Callable[[bytes], Any]:
    p = tmp / "fuzz.apk"

    def fn(data: bytes) -> None:
        p.write_bytes(data)
        a = open_archive(p, LIMITS)
        verify_crcs(a)
        structural_gate(a, None)
        detect(a)

    return fn


pytestmark = pytest.mark.toolchain


def test_fuzz_strict_zip(tmp_path: Path, seeds: dict[str, Any]) -> None:
    run_target("zip", [seeds["signed"], seeds["modern"]], _zip(tmp_path), (ZipFailure,), seeds["hot"])


def test_fuzz_signing_block(tmp_path: Path, seeds: dict[str, Any]) -> None:
    p = tmp_path / "fuzz-sb.apk"

    def fn(data: bytes) -> None:
        p.write_bytes(data)
        a = open_archive(p, LIMITS)
        blk = sigblock.locate(a, LIMITS)
        if blk is not None:
            sigblock.inventory_pairs(blk, {}, LIMITS)

    run_target("sigblock", [seeds["signed"]], fn, (ZipFailure, sigblock.SigBlockFormatError), [seeds["hot"][0]])


def test_fuzz_pkcs7(seeds: dict[str, Any]) -> None:
    run_target("pkcs7", [seeds["rsa"]], parse_signed_data, (ValueError, TypeError, KeyError, OverflowError))


def test_fuzz_lineage(seeds: dict[str, Any]) -> None:
    def fn(data: bytes) -> None:
        verify_lineage(parse_lineage(data))

    run_target("lineage", [seeds["por"]], fn, (LineageFormatError,))


def test_fuzz_badging() -> None:
    seed = (
        b"package: name='dev.kloner.fixture' versionCode='1' versionName='1.0'\n"
        b"minSdkVersion:'24'\ntargetSdkVersion:'35'\n"
    )

    def fn(data: bytes) -> None:
        parse_badging(data.decode("utf-8", errors="replace"))

    run_target("badging", [seed], fn, (ValueError,))


def test_fuzz_androguard_manifest_wrapper(tmp_path: Path, seeds: dict[str, Any]) -> None:
    """The worker treats any androguard failure as MANIFEST_UNREADABLE; it must never hang the run."""
    from kloner.util.logging import quiet_third_party
    from kloner.verify.manifest import androguard_view

    quiet_third_party()
    from androguard.core.apk import APK

    p = tmp_path / "fuzz-ag.apk"
    worst = 0.0
    for _ in range(max(50, N // 10)):
        p.write_bytes(mutate(seeds["modern"], seeds["hot"]))
        t0 = time.perf_counter()
        with contextlib.suppress(Exception):
            androguard_view(APK(str(p)))
        worst = max(worst, time.perf_counter() - t0)
    assert worst < 1.0
