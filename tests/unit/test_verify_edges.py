"""Error and edge branches of the verification layer (every failure must become a typed fact)."""

from __future__ import annotations

import datetime as dt
import json
import struct
import sys
from pathlib import Path
from typing import Any

import pytest
from asn1crypto import algos, cms
from asn1crypto import x509 as ax509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, padding, rsa
from cryptography.x509.oid import NameOID

from kloner.container.zipstrict import open_archive
from kloner.models import BridgeResult, EvaluationFacts, Issue, ManifestFacts, VerifyRange
from kloner.util.limits import DEFAULT_LIMITS, Limits
from kloner.verify import sigblock
from kloner.verify.certs import cert_info
from kloner.verify.facts import choose_package, unknown_items
from kloner.verify.lineage import verify_signature
from kloner.verify.v1pkcs7 import inventory_v1, parse_signed_data

pytestmark = pytest.mark.toolchain


def _cert(key: Any, ski: bool = False) -> x509.Certificate:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "edge")])
    now = dt.datetime(2026, 1, 1, tzinfo=dt.UTC)
    b = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(7)
        .not_valid_before(now)
        .not_valid_after(now + dt.timedelta(days=30))
    )
    if ski:
        b = b.add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    algo = None if isinstance(key, ed25519.Ed25519PrivateKey) else hashes.SHA256()
    return b.sign(key, algo)


def test_signature_algorithms_all_branches() -> None:
    data = b"lineage node signed data"
    r = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    e = ec.generate_private_key(ec.SECP256R1())
    d = dsa.generate_private_key(key_size=2048)
    cases = [
        (r, 0x0101, r.sign(data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())),
        (r, 0x0102, r.sign(data, padding.PSS(mgf=padding.MGF1(hashes.SHA512()), salt_length=64), hashes.SHA512())),
        (r, 0x0103, r.sign(data, padding.PKCS1v15(), hashes.SHA256())),
        (r, 0x0104, r.sign(data, padding.PKCS1v15(), hashes.SHA512())),
        (e, 0x0201, e.sign(data, ec.ECDSA(hashes.SHA256()))),
        (e, 0x0202, e.sign(data, ec.ECDSA(hashes.SHA512()))),
        (d, 0x0301, d.sign(data, hashes.SHA256())),
    ]
    for key, alg, sig in cases:
        assert verify_signature(key.public_key(), alg, data, sig), hex(alg)
        assert not verify_signature(key.public_key(), alg, data + b"x", sig), hex(alg)
    assert not verify_signature(r.public_key(), 0x0201, data, cases[0][2])
    assert not verify_signature(r.public_key(), 0x9999, data, b"")


def test_cert_info_key_types() -> None:
    for key, alg in (
        (ec.generate_private_key(ec.SECP256R1()), "EC"),
        (dsa.generate_private_key(key_size=2048), "DSA"),
        (ed25519.Ed25519PrivateKey.generate(), "Ed25519"),
    ):
        der = _cert(key).public_bytes(serialization.Encoding.DER)
        assert cert_info(der).key_algorithm == alg


def _signed_data(cert: x509.Certificate, ski: bytes) -> bytes:
    acert = ax509.Certificate.load(cert.public_bytes(serialization.Encoding.DER))
    si = cms.SignerInfo(
        {
            "version": "v3",
            "sid": cms.SignerIdentifier({"subject_key_identifier": ski}),
            "digest_algorithm": algos.DigestAlgorithm({"algorithm": "sha256"}),
            "signature_algorithm": algos.SignedDigestAlgorithm({"algorithm": "sha256_rsa"}),
            "signature": b"\x00" * 16,
        }
    )
    sd = cms.SignedData(
        {
            "version": "v3",
            "digest_algorithms": [algos.DigestAlgorithm({"algorithm": "sha256"})],
            "encap_content_info": {"content_type": "data"},
            "certificates": [cms.CertificateChoices({"certificate": acert})],
            "signer_infos": [si],
        }
    )
    return cms.ContentInfo({"content_type": "signed_data", "content": sd}).dump()


def test_v1_subject_key_identifier_and_errors(corpus: dict[str, Any], tmp_path: Path) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = _cert(key, ski=True)
    ski = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
    all_der, signer_der = parse_signed_data(_signed_data(cert, ski))
    assert len(all_der) == 1 and signer_der == all_der
    with pytest.raises(ValueError):
        parse_signed_data(cms.ContentInfo({"content_type": "data", "content": b"x"}).dump())
    a = open_archive(corpus["files"]["C-01"], DEFAULT_LIMITS)
    assert inventory_v1(a, {}, Limits(max_v1_signature_bytes=8))[0].parse_error  # too large to read
    with pytest.raises(ValueError):
        inventory_v1(a, {}, Limits(max_v1_signature_files=0))


def _block_variant(path: Path, tmp: Path, mutate: Any) -> Path:
    data = bytearray(path.read_bytes())
    a = open_archive(path, DEFAULT_LIMITS)
    blk = sigblock.locate(a, DEFAULT_LIMITS)
    assert blk is not None
    mutate(data, blk, a)
    out = tmp / "variant.apk"
    out.write_bytes(bytes(data))
    return out


def test_signing_block_format_errors(corpus: dict[str, Any], tmp_path: Path) -> None:
    src = corpus["files"]["C-01"]

    def size_huge(d: bytearray, blk: Any, a: Any) -> None:
        struct.pack_into("<Q", d, a.cd_offset - 24, 1 << 40)

    def header_differs(d: bytearray, blk: Any, a: Any) -> None:
        struct.pack_into("<Q", d, blk.start, 12345)

    def tiny(d: bytearray, blk: Any, a: Any) -> None:
        struct.pack_into("<Q", d, a.cd_offset - 24, 8)

    for mut in (size_huge, header_differs, tiny):
        p = _block_variant(src, tmp_path, mut)
        with pytest.raises(sigblock.SigBlockFormatError):
            sigblock.locate(open_archive(p, DEFAULT_LIMITS), DEFAULT_LIMITS)
    a = open_archive(src, DEFAULT_LIMITS)
    with pytest.raises(sigblock.SigBlockFormatError):
        sigblock.locate(a, Limits(max_sigblock_pairs=1))
    blk = sigblock.locate(a, DEFAULT_LIMITS)
    assert blk is not None
    v2 = next(v for pid, _, v in blk.pairs if pid == sigblock.V2_BLOCK_ID)
    fake = sigblock.SigningBlock(
        blk.start, blk.end, [(0x13371337, 0, v2), (0x71777777, 0, b"channel"), (sigblock.V2_BLOCK_ID, 0, b"\x01\x00")]
    )
    pairs = sigblock.inventory_pairs(fake, {}, DEFAULT_LIMITS)
    assert [p.kind for p in pairs] == ["sniffed_signature", "unsigned", "signature"]
    assert pairs[1].name == "walle_channel" and pairs[2].parse_error
    r = sigblock._R(b"\x01")
    with pytest.raises(sigblock.SigBlockFormatError):
        r.u32()
    with pytest.raises(sigblock.SigBlockFormatError):
        sigblock._R(b"\x00" * 4).u64()
    with pytest.raises(sigblock.SigBlockFormatError):
        sigblock._R(b"\xff\xff\xff\xff").sub()
    with pytest.raises(sigblock.SigBlockFormatError):
        sigblock._parse_signers(b"\x00\x00\x00\x00", False, DEFAULT_LIMITS)
    with pytest.raises(sigblock.SigBlockFormatError):
        sigblock._parse_signers(v2 + b"x", False, DEFAULT_LIMITS)
    with pytest.raises(sigblock.SigBlockFormatError):
        sigblock._parse_signers(v2, False, Limits(max_certs_per_signer=0))


def test_unknown_items_and_choose_package(facts01: EvaluationFacts) -> None:
    rng: VerifyRange = facts01.verify.full_range  # type: ignore[union-attr]
    r2 = rng.model_copy(deep=True)
    r2.warnings = [Issue(issue="V3_SIG_UNKNOWN_ADDITIONAL_ATTRIBUTE", params=["0x1234"], message="x")]
    nat = facts01.native_inventory.model_copy(deep=True)  # type: ignore[union-attr]
    nat.pairs[0].signers[0].unknown_attribute_ids = [0x1234]
    items = unknown_items(r2, nat)
    assert any("V3_SIG_UNKNOWN_ADDITIONAL_ATTRIBUTE" in i for i in items) and any("0x00001234" in i for i in items)

    def mf(pkg: str | None, split: str | None = None) -> EvaluationFacts:
        return EvaluationFacts(
            sample_sha256="0" * 64, size=1, manifest=ManifestFacts(package=pkg, split=split, unreadable=pkg is None)
        )

    assert choose_package([mf("a.b"), mf("a.b", "config.en"), mf("c.d")]) == "a.b"
    assert choose_package([mf("a.b", "config.en")]) is None
    assert choose_package([mf(None)]) is None


def test_pipeline_failure_paths(rt: Any, corpus: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    from kloner.util import proc
    from kloner.verify.bridge import BridgeFailure

    pipe = rt.pipeline()
    sha, _ = rt.quarantine.ingest_file(corpus["files"]["C-01"], 1 << 30)
    real_run = proc.run
    monkeypatch.setattr(proc, "run", lambda *a, **k: proc.ProcResult(("x",), None, b"", b"", True, 1.0))
    facts, _ = pipe.worker_facts(sha, None)
    assert facts.collection_error and "timed out" in facts.collection_error
    monkeypatch.setattr(proc, "run", lambda *a, **k: proc.ProcResult(("x",), 1, b"garbage", b"crash", False, 1.0))
    facts, _ = pipe.worker_facts(sha, None)
    assert facts.collection_error and "exited" in facts.collection_error
    monkeypatch.setattr(proc, "run", real_run)
    good, _ = pipe.worker_facts(sha, None)

    def boom(*a: Any, **k: Any) -> BridgeResult:
        raise BridgeFailure("bridge timed out after 1s")

    monkeypatch.setattr(pipe.bridges, "verify", boom)
    f1 = good.model_copy(deep=True)
    pipe.add_verification(f1)
    assert f1.verify is not None and f1.verify.engine_failure

    def fatal(path: Any, lo: int, hi: int) -> BridgeResult:
        return BridgeResult.model_validate(
            {
                "bridge_version": "1",
                "fatal": "ApkFormatException: x",
                "input": {"path": str(path), "min_sdk": lo, "max_sdk": hi},
            }
        )

    monkeypatch.setattr(pipe.bridges, "verify", fatal)
    f2 = good.model_copy(deep=True)
    pipe.add_verification(f2)
    assert f2.verify is not None and f2.verify.engine_detail == "ApkFormatException: x"
    f3 = good.model_copy(deep=True)
    f3.manifest.parsers_disagree = True  # type: ignore[union-attr]
    pipe.add_verification(f3)
    assert f3.verify is None


def test_bridge_protocol_errors(rt: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    from kloner.verify.bridge import BridgeClient, BridgeFailure

    scripts = {
        "garbage": "import sys\nfor l in sys.stdin: print('not json', flush=True)",
        "wrong_id": "import sys, json\nfor l in sys.stdin: print(json.dumps({'id': 'other'}), flush=True)",
        "exit": "import sys\nsys.exit(0)",
        "request_error": "import sys, json\nfor l in sys.stdin:\n    r=json.loads(l)\n"
        "    print(json.dumps({'id': r['id'], 'bridge_version':'1', 'fatal':'BridgeRequestError: x'}), flush=True)",
    }
    for _name, code in scripts.items():
        c = BridgeClient(rt.toolchain(), timeout_s=30)
        monkeypatch.setattr(c, "_argv", lambda code=code: [sys.executable, "-c", code])
        with pytest.raises(BridgeFailure):
            c.verify(Path("x.apk"), 24, 30)
        c.close()
    assert json.dumps({}) == "{}"
