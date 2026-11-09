from __future__ import annotations

from pathlib import Path

import pytest

from kloner.util.canonical import canonical_bytes, canonical_sha256
from kloner.util.fingerprints import FingerprintError, colon_fp, is_sha256_hex, normalize_fingerprint, short_fp
from kloner.util.hashing import cert_digests, sha256_bytes, sha256_file, third_party_digests
from kloner.util.timeutil import iso, now_iso, run_id, utc_now

FP = "29f34e5f27f211b424bc5bf9d67162c0eafba2da35af35c16416fc446276ba26"


def test_normalize_fingerprint_accepts_vendor_formats() -> None:
    assert normalize_fingerprint(FP.upper()) == FP
    assert normalize_fingerprint(colon_fp(FP)) == FP
    assert normalize_fingerprint(" ".join(FP[i : i + 2] for i in range(0, 64, 2))) == FP
    assert normalize_fingerprint("-".join(FP[i : i + 4] for i in range(0, 64, 4))) == FP


@pytest.mark.parametrize("bad", ["", "zz" * 32, FP[:-2], FP + "00", "not a fingerprint"])
def test_normalize_fingerprint_rejects(bad: str) -> None:
    with pytest.raises(FingerprintError):
        normalize_fingerprint(bad)


def test_fingerprint_helpers() -> None:
    assert is_sha256_hex(FP) and not is_sha256_hex(FP.upper()) and not is_sha256_hex("ab")
    assert short_fp(FP) == "29f3…a26"
    assert short_fp(None) == "—"
    assert colon_fp(FP).startswith("29:F3:4E")


def test_canonical_json_is_stable() -> None:
    a = {"b": 1, "a": [3, {"z": True, "y": None}], "é": "ü"}
    b = {"é": "ü", "a": [3, {"y": None, "z": True}], "b": 1}
    assert canonical_bytes(a) == canonical_bytes(b)
    assert canonical_bytes(a).startswith(b'{"a":')
    assert canonical_sha256(a) == canonical_sha256(b)
    with pytest.raises(ValueError):
        canonical_bytes({"x": float("nan")})


def test_hashing(tmp_path: Path) -> None:
    p = tmp_path / "f"
    p.write_bytes(b"kloner")
    assert sha256_file(p) == sha256_bytes(b"kloner")
    d = third_party_digests(p)
    assert set(d) == {"md5", "sha1", "sha256"} and d["sha256"] == sha256_bytes(b"kloner")
    assert set(cert_digests(b"x")) == {"md5", "sha1", "sha256"}


def test_time_helpers() -> None:
    assert now_iso().endswith("Z") and "T" in now_iso()
    rid = run_id(utc_now())
    assert ":" not in rid and rid.endswith("Z")
    assert iso(utc_now()).count(":") == 2
