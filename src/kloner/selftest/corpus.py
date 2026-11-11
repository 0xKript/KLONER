"""Synthetic corpus (§18.1, §18.2).

A synthetic vendor (generated keys, never a real vendor's) signs KLONER's own trivial fixture
apps with the real apksigner. File-level cases are legitimate constructions only: signing with
different keys, apksigner key rotation, bundles of signed members, a truncated or corrupted
download, a non-ZIP file, an AAB-shaped archive.

Cases that would need a crafted hostile file (content modified under a kept signature, polyglot,
ZIP ambiguity, stripped or grafted signature blocks, forged lineage, unsigned-region injection,
oversized archives, hostile entry names) are covered at the facts level: they start from the real
facts of C-01 and change only the data ``decide()`` sees (D-026).
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import zipfile
from collections.abc import Callable
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from kloner.models import (
    Anchor,
    Brand,
    EvaluationFacts,
    Identity,
    Issue,
    LineageEntry,
    NativeSigner,
    SigBlockPair,
    StructureViolation,
    Verdict,
)
from kloner.toolchain import Toolchain
from kloner.util import proc

FIXTURE_PACKAGE = "dev.kloner.fixture"
KEY_NAMES = ("vendor", "rotated", "foreign", "debug", "rotated2")


@dataclass
class Key:
    name: str
    pk8: Path
    cert: Path
    sha256: str
    der: bytes


@dataclass
class Case:
    id: str
    title: str
    expected: Verdict | None = None
    labels: tuple[str, ...] = ()
    never: tuple[Verdict, ...] = ()
    one_of: tuple[Verdict, ...] = ()
    level: str = "file"  # file | facts | anchor | special
    file: Path | None = None
    expected_package: str | None = FIXTURE_PACKAGE
    anchors: dict[str, Anchor] = field(default_factory=dict)
    facts: Callable[[EvaluationFacts], EvaluationFacts] | None = None
    note: str = ""


def fixture_path(name: str) -> Path:
    ref = resources.files("kloner.selftest").joinpath(f"fixtures/{name}.apk")
    return Path(str(ref))


def make_key(name: str, out: Path, *, kind: str = "rsa2048", cn: str | None = None, debug: bool = False) -> Key:
    if kind == "rsa4096":
        priv: Any = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    elif kind == "ec":
        priv = ec.generate_private_key(ec.SECP256R1())
    else:
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    if debug:
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "Android Debug"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Android"),
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            ]
        )
    else:
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn or f"Kloner Synthetic {name}")])
    start = dt.datetime(2026, 1, 1, tzinfo=dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(priv.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(start + dt.timedelta(days=3650))
        .sign(priv, hashes.SHA256())
    )
    pk8 = out / f"{name}.pk8"
    pem = out / f"{name}.x509.pem"
    pk8.write_bytes(
        priv.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    pem.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    der = cert.public_bytes(serialization.Encoding.DER)
    return Key(name, pk8, pem, hashlib.sha256(der).hexdigest(), der)


class Signer:
    """Thin wrapper over the real apksigner CLI from the pinned build-tools."""

    def __init__(self, tc: Toolchain) -> None:
        self.tc = tc

    def _run(self, args: list[str]) -> None:
        res = proc.run([self.tc.java, "-jar", self.tc.apksigner_jar, *args], timeout_s=300, env=proc.minimal_env())
        if not res.ok:
            raise RuntimeError(f"apksigner {' '.join(args[:1])} failed: {res.err_text()[-800:]}")

    def sign(
        self,
        src: Path,
        dst: Path,
        key: Key,
        *,
        v1: bool = True,
        v2: bool = True,
        v3: bool = True,
        next_key: Key | None = None,
        lineage: Path | None = None,
        rotation_min_sdk: int | None = None,
    ) -> Path:
        args = [
            "sign",
            "--key",
            str(key.pk8),
            "--cert",
            str(key.cert),
            "--v1-signing-enabled",
            str(v1).lower(),
            "--v2-signing-enabled",
            str(v2).lower(),
            "--v3-signing-enabled",
            str(v3).lower(),
            "--v4-signing-enabled",
            "false",
        ]
        if next_key is not None:
            args += ["--next-signer", "--key", str(next_key.pk8), "--cert", str(next_key.cert)]
        if lineage is not None:
            args += ["--lineage", str(lineage)]
        if rotation_min_sdk is not None:
            args += ["--rotation-min-sdk-version", str(rotation_min_sdk)]
        self._run([*args, "--in", str(src), "--out", str(dst)])
        return dst

    def rotate(self, old: Key, new: Key, out: Path) -> Path:
        self._run(
            [
                "rotate",
                "--out",
                str(out),
                "--old-signer",
                "--key",
                str(old.pk8),
                "--cert",
                str(old.cert),
                "--new-signer",
                "--key",
                str(new.pk8),
                "--cert",
                str(new.cert),
            ]
        )
        return out

    def verify_certs(self, apk: Path) -> tuple[bool, list[str]]:
        """``apksigner verify -v --print-certs`` (§18.5): (verified, signer SHA-256 digests)."""
        res = proc.run(
            [self.tc.java, "-jar", self.tc.apksigner_jar, "verify", "-v", "--print-certs", str(apk)],
            timeout_s=300,
            env=proc.minimal_env(),
        )
        text = res.text()
        digests = sorted(
            {
                ln.split(":", 1)[1].strip()
                for ln in text.splitlines()
                if "certificate SHA-256 digest:" in ln and ln.startswith("Signer")
            }
        )
        return res.returncode == 0 and text.startswith("Verifies"), digests


def anchor_for(
    keys: list[Key],
    *,
    lineage: list[Key] | None = None,
    package: str = FIXTURE_PACKAGE,
    brand_icons: list[str] | None = None,
    brand_labels: list[str] | None = None,
) -> Anchor:
    a = Anchor(
        package=package,
        created_utc="2026-01-01T00:00:00Z",
        refreshed_utc="2026-01-01T00:00:00Z",
        identities=[
            Identity(
                id=f"id-{i + 1}", label=k.name, cert_sha256=k.sha256, cert_der_b64=base64.b64encode(k.der).decode()
            )
            for i, k in enumerate(keys)
        ],
        lineage=[LineageEntry(cert_sha256=k.sha256) for k in (lineage or [])],
        brand=Brand(icon_asset_sha256=sorted(brand_icons or []), brand_labels=sorted(brand_labels or [])),
        corroboration="USER_ASSERTED",
    )
    from kloner.anchor.store import seal

    return seal(a)


def write_xapk(out: Path, members: dict[str, Path], package: str = FIXTURE_PACKAGE) -> Path:
    manifest = {
        "xapk_version": 2,
        "package_name": package,
        "name": "Kloner Fixture",
        "version_code": "1",
        "version_name": "1.0",
        "split_apks": [{"file": n, "id": n.removesuffix(".apk")} for n in members],
    }
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr(zipfile.ZipInfo("manifest.json", (2026, 1, 1, 0, 0, 0)), json.dumps(manifest, indent=2))
        for name, path in members.items():
            z.writestr(
                zipfile.ZipInfo(name, (2026, 1, 1, 0, 0, 0)), path.read_bytes(), compress_type=zipfile.ZIP_STORED
            )
    return out


def write_aab_shaped(out: Path, manifest_bytes: bytes) -> Path:
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr(zipfile.ZipInfo("BundleConfig.pb", (2026, 1, 1, 0, 0, 0)), b"\x0a\x00")
        z.writestr(zipfile.ZipInfo("base/manifest/AndroidManifest.xml", (2026, 1, 1, 0, 0, 0)), manifest_bytes)
    return out


def corrupt_deflated(src: Path, out: Path) -> Path:
    """Flip one byte inside a DEFLATED entry's data: what a broken download looks like (CRC breaks)."""
    data = bytearray(src.read_bytes())
    with zipfile.ZipFile(src) as z:
        info = next(i for i in z.infolist() if i.compress_type == zipfile.ZIP_DEFLATED and i.compress_size > 64)
    off = info.header_offset + 30 + len(info.filename.encode()) + len(info.extra) + info.compress_size // 2
    data[off] ^= 0x5A
    out.write_bytes(bytes(data))
    return out


# --------------------------------------------------------------------------------------------
# facts-level transformations (data only)
# --------------------------------------------------------------------------------------------


def replace_cert(
    facts: EvaluationFacts, old: str, new: str, new_der: bytes | None = None, subject: str | None = None
) -> EvaluationFacts:
    """Return facts in which certificate ``old`` is replaced by ``new`` wherever it appears."""
    raw = facts.model_dump_json(by_alias=True).replace(old, new)
    f = EvaluationFacts.model_validate_json(raw)
    if f.native_inventory and new in f.native_inventory.certs:
        info = f.native_inventory.certs[new]
        upd: dict[str, Any] = {"sha256": new}
        if new_der is not None:
            upd["der_b64"] = base64.b64encode(new_der).decode()
        if subject is not None:
            upd["subject"] = subject
            upd["debug_dn"] = subject == "CN=Android Debug,O=Android,C=US"
        f.native_inventory.certs[new] = info.model_copy(update=upd)
    return f


def with_unverified(facts: EvaluationFacts, *issues: str) -> EvaluationFacts:
    f = facts.model_copy(deep=True)
    assert f.verify is not None and f.verify.full_range is not None
    rng = f.verify.full_range
    rng.verified = False
    rng.schemes = dict.fromkeys(rng.schemes, False)
    rng.all_errors = [Issue(issue=i, message=i) for i in issues]
    rng.errors = list(rng.all_errors)
    f.verify.modern_range = None
    return f


def with_violation(facts: EvaluationFacts, rule: str, kind: str, code: str, detail: str) -> EvaluationFacts:
    f = facts.model_copy(deep=True)
    assert f.structure is not None
    f.structure.violations.append(StructureViolation(rule=rule, kind=kind, code=code, detail=detail))  # type: ignore[arg-type]
    return f


def with_extra_pair(facts: EvaluationFacts, pair: SigBlockPair) -> EvaluationFacts:
    f = facts.model_copy(deep=True)
    assert f.native_inventory is not None
    f.native_inventory.pairs.append(pair)
    return f


def sniffed_pair(cert: str) -> SigBlockPair:
    return SigBlockPair(
        id=0x13371337,
        id_hex="0x13371337",
        name="unknown",
        kind="sniffed_signature",
        offset=0,
        size=1024,
        sha256="0" * 64,
        signers=[NativeSigner(index=0, cert_chain=[cert], signer_cert=cert)],
    )


def unsigned_pair() -> SigBlockPair:
    return SigBlockPair(
        id=0x71777777,
        id_hex="0x71777777",
        name="walle_channel",
        kind="unsigned",
        offset=0,
        size=24,
        sha256=hashlib.sha256(b'{"channel":"kloner"}').hexdigest(),
        preview='{"channel":"kloner"}',
    )
