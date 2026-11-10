"""Bit flips in the 12-byte headers of APK Signing Block pairs (D-064, found by P-02 on CI).

The APK Signing Block is outside the content the v2/v3 signatures cover. When a flip leaves a file that apksig
still verifies, the verdict may be GENUINE, but it always records the changed block (UNSIGNED_BLOCK_DATA or
UNKNOWN_SIGNER_BLOCK, T-13, B5, D-021). It is never FORGED.
"""

from __future__ import annotations

from typing import Any

import pytest

from kloner.app import Runtime
from kloner.container.zipstrict import open_archive
from kloner.models import Evaluation, Verdict
from kloner.selftest import corpus as c
from kloner.util.limits import DEFAULT_LIMITS
from kloner.verify.sigblock import locate

pytestmark = pytest.mark.toolchain
PADDING, V2, V3 = 0x42726577, 0x7109871A, 0xF05368C0


def _flip(rt: Runtime, corpus: dict[str, Any], offset: int) -> Evaluation:
    data = bytearray(corpus["files"]["C-01"].read_bytes())
    data[offset] ^= 0x01
    sha, _ = rt.quarantine.ingest_bytes(bytes(data), 1 << 30)
    anchors = {c.FIXTURE_PACKAGE: corpus["anchors"]["v"]}
    ev = rt.pipeline().evaluate(sha, c.FIXTURE_PACKAGE, anchors, rt.known_keys).evaluation
    rt.quarantine.remove(sha)
    return ev


def test_flips_in_pair_headers(rt: Runtime, corpus: dict[str, Any]) -> None:
    blk = locate(open_archive(corpus["files"]["C-01"], DEFAULT_LIMITS), DEFAULT_LIMITS)
    assert blk is not None
    value_offset = {pid: off for pid, off, _ in blk.pairs}
    # pair layout: uint64 length, uint32 ID, value; the ID's first byte is 4 bytes before the value
    padding = _flip(rt, corpus, value_offset[PADDING] - 4)
    assert padding.verdict == Verdict.GENUINE and padding.has_label("UNSIGNED_BLOCK_DATA")
    v2 = _flip(rt, corpus, value_offset[V2] - 4)
    assert v2.verdict == Verdict.GENUINE and v2.has_label("UNKNOWN_SIGNER_BLOCK")
    v3 = _flip(rt, corpus, value_offset[V3] - 4)
    assert v3.verdict == Verdict.TAMPERED and v3.has_label("SCHEME_STRIPPED")
