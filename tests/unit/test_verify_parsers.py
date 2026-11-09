from __future__ import annotations

import base64
import zipfile
from pathlib import Path
from typing import Any

import pytest

from kloner.container.zipstrict import open_archive
from kloner.models import AndroguardInventory, BridgeSigner, LineageCert, ManifestView, NativeInventory, VerifyRange
from kloner.util.limits import DEFAULT_LIMITS
from kloner.verify import sigblock
from kloner.verify.certs import cert_info, is_debug_dn, is_x509
from kloner.verify.inventory import disagreements, native_inventory
from kloner.verify.lineage import (
    LineageFormatError,
    capabilities,
    parse_lineage,
    verify_lineage,
    verify_signature,
)
from kloner.verify.manifest import compare, manifest_facts, normalize, parse_badging
from kloner.verify.v1pkcs7 import is_v1_signature_name, parse_signed_data

pytestmark = pytest.mark.toolchain


def _pairs(path: Path) -> list[Any]:
    a = open_archive(path, DEFAULT_LIMITS)
    blk = sigblock.locate(a, DEFAULT_LIMITS)
    assert blk is not None
    return sigblock.inventory_pairs(blk, {}, DEFAULT_LIMITS)


def test_signing_block_of_vendor_apk(corpus: dict[str, Any]) -> None:
    V = corpus["keys"]["vendor"]
    pairs = _pairs(corpus["files"]["C-01"])
    names = [p.name for p in pairs]
    assert "v2" in names and "v3" in names
    v2 = next(p for p in pairs if p.name == "v2")
    assert v2.signers[0].signer_cert == V.sha256
    assert v2.signers[0].stripping_protection_scheme == 3
    assert all(p.parse_error is None for p in pairs)


def test_rotation_layouts(corpus: dict[str, Any]) -> None:
    V, R = corpus["keys"]["vendor"], corpus["keys"]["rotated"]
    p15 = {p.name: p for p in _pairs(corpus["files"]["C-15"])}
    s = p15["v3"].signers[0]
    assert s.signer_cert == R.sha256 and s.min_sdk == 28
    assert [n.cert_sha256 for n in s.lineage or []] == [V.sha256, R.sha256]
    assert [n.signature_valid for n in s.lineage or []] == [None, True]
    p16 = {p.name: p for p in _pairs(corpus["files"]["C-16"])}
    assert p16["v3"].signers[0].signer_cert == V.sha256 and p16["v3"].signers[0].rotation_min_sdk == 33
    assert p16["v31"].signers[0].signer_cert == R.sha256


def test_native_lineage_rejects_a_damaged_node_signature(corpus: dict[str, Any]) -> None:
    a = open_archive(corpus["files"]["C-15"], DEFAULT_LIMITS)
    blk = sigblock.locate(a, DEFAULT_LIMITS)
    assert blk is not None
    value = next(v for pid, _, v in blk.pairs if pid == sigblock.V3_BLOCK_ID)
    signer = sigblock._parse_signers(value, True, DEFAULT_LIMITS)[0]
    por = next(v for aid, v in signer.attrs if aid == sigblock.POR_ATTR_ID)
    nodes = parse_lineage(por)
    assert [n.signature_valid for n in verify_lineage(nodes)] == [None, True]
    damaged = bytearray(por)
    damaged[-5] ^= 0x01  # inside the last node's signature
    assert [n.signature_valid for n in verify_lineage(parse_lineage(bytes(damaged)))] == [None, False]
    with pytest.raises(LineageFormatError):
        parse_lineage(b"\x02\x00\x00\x00")
    with pytest.raises(LineageFormatError):
        parse_lineage(b"\x01\x00\x00\x00\xff\x00\x00\x00")
    assert capabilities(31) == {
        "installed_data": True,
        "shared_uid": True,
        "permission": True,
        "rollback": True,
        "auth": True,
    }
    assert verify_signature(object(), 0x0103, b"x", b"y") is False


def test_sniffing_recognizes_signer_structures_only(corpus: dict[str, Any]) -> None:
    a = open_archive(corpus["files"]["C-02"], DEFAULT_LIMITS)
    blk = sigblock.locate(a, DEFAULT_LIMITS)
    assert blk is not None
    v2 = next(v for pid, _, v in blk.pairs if pid == sigblock.V2_BLOCK_ID)
    assert sigblock._sniff(v2, DEFAULT_LIMITS) is not None
    assert sigblock._sniff(b"\x00" * 64, DEFAULT_LIMITS) is None
    assert sigblock._sniff(b'{"channel":"kloner"}', DEFAULT_LIMITS) is None


def test_v1_signature_parsing(corpus: dict[str, Any]) -> None:
    V = corpus["keys"]["vendor"]
    with zipfile.ZipFile(corpus["files"]["C-01"]) as z:
        name = next(n for n in z.namelist() if is_v1_signature_name(n))
        data = z.read(name)
    all_der, signer_der = parse_signed_data(data)
    assert len(all_der) == 1 and len(signer_der) == 1
    assert cert_info(signer_der[0]).sha256 == V.sha256
    with pytest.raises(ValueError):
        parse_signed_data(b"\x30\x03\x02\x01\x01")
    assert is_v1_signature_name("META-INF/CERT.RSA") and is_v1_signature_name("META-INF/x.ec")
    assert not is_v1_signature_name("META-INF/sub/CERT.RSA") and not is_v1_signature_name("CERT.RSA")


def test_cert_info(corpus: dict[str, Any]) -> None:
    D, F = corpus["keys"]["debug"], corpus["keys"]["foreign"]
    i = cert_info(D.der)
    assert i.debug_dn and i.key_algorithm == "RSA" and i.key_bits == 2048
    j = cert_info(F.der)
    assert not j.debug_dn and j.key_bits == 4096 and j.subject.startswith("CN=")
    assert is_x509(F.der) and not is_x509(b"\x30\x00")
    bad = cert_info(b"not a certificate")
    assert bad.subject == "<unparseable certificate>" and len(bad.sha256) == 64
    from cryptography import x509

    assert is_debug_dn(x509.load_der_x509_certificate(D.der).subject)


BADGING = (
    (
        "package: name='dev.kloner.fixture' versionCode='7' versionName='1.7' split='config.en' "
        "platformBuildVersionName='16'\n"
    )
    + """minSdkVersion:'24'
targetSdkVersion:'35'
application-label:'Kloner Fixture'
"""
)


def test_badging_parse_and_compare() -> None:
    v = parse_badging(BADGING)
    assert (v.package, v.version_code, v.version_name, v.split, v.min_sdk, v.target_sdk) == (
        "dev.kloner.fixture",
        7,
        "1.7",
        "config.en",
        24,
        35,
    )
    legacy = parse_badging("package: name='a.b' versionCode='1'\nsdkVersion:'21'\n")
    assert legacy.min_sdk == 21 and legacy.target_sdk == 21
    assert parse_badging("package: name='a.b'\nminSdkVersion:'VanillaIceCream'\n").min_sdk == 10_000
    with pytest.raises(ValueError):
        parse_badging("nothing")
    ag = ManifestView(
        package="dev.kloner.fixture", version_code=7, version_name="1.7", split="config.en", min_sdk=24, target_sdk=35
    )
    assert compare(ag, v) == ([], [])
    diffs, _ = compare(ag.model_copy(update={"package": "x.y"}), v)
    assert diffs and diffs[0].startswith("package:")
    _, notes = compare(ag.model_copy(update={"version_name": "@7F020001"}), v)
    assert notes
    assert normalize(ManifestView(package="a.b")).min_sdk == 1
    mf = manifest_facts(ag, None, ["aapt2: failed"])
    assert mf.unreadable and "aapt2" in (mf.unreadable_detail or "")
    mf2 = manifest_facts(ag, v, [])
    assert not mf2.parsers_disagree and mf2.package == "dev.kloner.fixture"


def test_inventory_agreement_rules(corpus: dict[str, Any], facts01: Any) -> None:
    rng: VerifyRange = facts01.verify.full_range
    nat: NativeInventory = facts01.native_inventory
    ag: AndroguardInventory = facts01.androguard_inventory
    assert disagreements(rng, nat, ag) == []
    bad = rng.model_copy(deep=True)
    bad.signers.append(BridgeSigner(scheme="v2", index=9, cert_sha256="ab" * 32))
    assert any(d.startswith("(a)") for d in disagreements(bad, nat, ag))
    ag2 = ag.model_copy(update={"v2": ["cd" * 32]})
    assert any(d.startswith("(b)") for d in disagreements(rng, nat, ag2))
    rng3 = rng.model_copy(deep=True)
    rng3.schemes["v31"] = True
    assert any(d.startswith("(c)") for d in disagreements(rng3, nat, ag))
    rng4 = rng.model_copy(deep=True)
    for s in rng4.signers:
        if s.scheme == "v3":
            s.lineage = [LineageCert(cert_sha256="ef" * 32)]
    assert any(d.startswith("(d)") for d in disagreements(rng4, nat, ag))
    assert disagreements(rng, None, ag)
    assert disagreements(rng, NativeInventory(error="boom"), ag)
    assert disagreements(rng, nat, AndroguardInventory(error="boom"))


def test_native_inventory_on_unsigned_fixture() -> None:
    from kloner.selftest.corpus import fixture_path

    a = open_archive(fixture_path("modern"), DEFAULT_LIMITS)
    inv, block = native_inventory(a, DEFAULT_LIMITS)
    assert block is None and not inv.has_signing_block and inv.v1 == [] and inv.pairs == []
    assert base64.b64encode(b"x")
