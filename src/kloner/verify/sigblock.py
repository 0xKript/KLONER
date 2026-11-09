"""Native APK Signing Block inventory (§9 G6), independent of apksig.

Constants are confirmed against the pinned apksig (build-tools 36.0.0) in docs/DECISIONS.md.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

from kloner.container.zipstrict import ZipArchive
from kloner.models import CertInfo, NativeLineageNode, NativeSigner, SigBlockPair, SigPairKind
from kloner.util.limits import Limits
from kloner.verify.certs import cert_info, is_x509
from kloner.verify.lineage import LineageFormatError, capabilities, parse_lineage, verify_lineage

MAGIC = b"APK Sig Block 42"

V2_BLOCK_ID = 0x7109871A
V3_BLOCK_ID = 0xF05368C0
V31_BLOCK_ID = 0x1B93AD61
SOURCE_STAMP_V1_ID = 0x2B09189E
SOURCE_STAMP_V2_ID = 0x6DFF800D
VERITY_PADDING_ID = 0x42726577

POR_ATTR_ID = 0x3BA06F8C
ROTATION_MIN_SDK_ATTR_ID = 0x559F8B02
ROTATION_ON_DEV_RELEASE_ATTR_ID = 0xC2A6B3BA
STRIPPING_PROTECTION_ATTR_ID = 0xBEEFF00D

KNOWN_V2_ATTRS = frozenset({STRIPPING_PROTECTION_ATTR_ID})
KNOWN_V3_ATTRS = frozenset({POR_ATTR_ID, ROTATION_MIN_SDK_ATTR_ID, ROTATION_ON_DEV_RELEASE_ATTR_ID})

SIGNATURE_BLOCKS = {V2_BLOCK_ID: "v2", V3_BLOCK_ID: "v3", V31_BLOCK_ID: "v31"}
SOURCE_STAMP_BLOCKS = {SOURCE_STAMP_V1_ID: "source_stamp_v1", SOURCE_STAMP_V2_ID: "source_stamp_v2"}

# Known non-signature pairs (Appendix A). Names only: every unknown ID is sniffed regardless.
KNOWN_NON_SIGNATURE = {
    VERITY_PADDING_ID: "verity_padding",
    0x504B4453: "dependency_info",
    0x2146444E: "google_play_metadata",
    0x71777777: "walle_channel",
    0x881155FF: "vasdolly_channel",
}


class SigBlockFormatError(ValueError):
    pass


class _R:
    """Bounds-checked little-endian reader over a bytes slice."""

    __slots__ = ("buf", "end", "pos")

    def __init__(self, buf: bytes, pos: int = 0, end: int | None = None) -> None:
        self.buf = buf
        self.pos = pos
        self.end = len(buf) if end is None else end

    def remaining(self) -> int:
        return self.end - self.pos

    def u32(self) -> int:
        if self.remaining() < 4:
            raise SigBlockFormatError("truncated uint32")
        v = int(struct.unpack_from("<I", self.buf, self.pos)[0])
        self.pos += 4
        return v

    def u64(self) -> int:
        if self.remaining() < 8:
            raise SigBlockFormatError("truncated uint64")
        v = int(struct.unpack_from("<Q", self.buf, self.pos)[0])
        self.pos += 8
        return v

    def take(self, n: int) -> bytes:
        if n < 0 or self.remaining() < n:
            raise SigBlockFormatError("length exceeds the enclosing structure")
        v = self.buf[self.pos : self.pos + n]
        self.pos += n
        return v

    def sub(self) -> _R:
        n = self.u32()
        if self.remaining() < n:
            raise SigBlockFormatError("length-prefixed slice exceeds the enclosing structure")
        r = _R(self.buf, self.pos, self.pos + n)
        self.pos += n
        return r

    def prefixed(self) -> bytes:
        n = self.u32()
        return self.take(n)


@dataclass(frozen=True)
class SigningBlock:
    start: int
    end: int
    pairs: list[tuple[int, int, bytes]]  # (id, value file offset, value)


def locate(archive: ZipArchive, limits: Limits) -> SigningBlock | None:
    """Find and split the APK Signing Block that ends where the central directory starts."""
    cd = archive.cd_offset
    if cd < 32:
        return None
    with archive.path.open("rb") as f:
        f.seek(cd - 24)
        footer = f.read(24)
        if len(footer) != 24 or footer[8:] != MAGIC:
            return None
        size = int(struct.unpack_from("<Q", footer, 0)[0])
        if size < 24 or size > limits.max_sigblock_bytes:
            raise SigBlockFormatError(f"APK Signing Block size {size} out of range")
        start = cd - (size + 8)
        if start < 0:
            raise SigBlockFormatError("APK Signing Block starts before the file")
        f.seek(start)
        header = f.read(8)
        if len(header) != 8 or int(struct.unpack_from("<Q", header, 0)[0]) != size:
            raise SigBlockFormatError("APK Signing Block leading and trailing sizes differ")
        body = f.read(size - 24)
    if len(body) != size - 24:
        raise SigBlockFormatError("APK Signing Block truncated")
    r = _R(body)
    pairs: list[tuple[int, int, bytes]] = []
    while r.remaining() > 0:
        if len(pairs) >= limits.max_sigblock_pairs:
            raise SigBlockFormatError("too many ID-value pairs")
        length = r.u64()
        if length < 4 or length > r.remaining():
            raise SigBlockFormatError("ID-value pair length out of range")
        pid = r.u32()
        value_offset = start + 8 + r.pos
        value = r.take(int(length) - 4)
        pairs.append((pid, value_offset, value))
    return SigningBlock(start, cd, pairs)


@dataclass
class _ParsedSigner:
    certs: list[bytes]
    attrs: list[tuple[int, bytes]]
    min_sdk: int | None
    max_sdk: int | None


def _parse_attrs(r: _R) -> list[tuple[int, bytes]]:
    out: list[tuple[int, bytes]] = []
    while r.remaining() > 0:
        a = r.sub()
        aid = a.u32()
        out.append((aid, a.take(a.remaining())))
    return out


def _parse_digests(r: _R) -> None:
    while r.remaining() > 0:
        d = r.sub()
        d.u32()
        d.prefixed()


def _parse_certs(r: _R, limits: Limits) -> list[bytes]:
    certs: list[bytes] = []
    while r.remaining() > 0:
        if len(certs) >= limits.max_certs_per_signer:
            raise SigBlockFormatError("too many certificates in a signer")
        certs.append(r.prefixed())
    return certs


def _parse_signer(r: _R, v3: bool, limits: Limits) -> _ParsedSigner:
    signed = r.sub()
    _parse_digests(signed.sub())
    certs = _parse_certs(signed.sub(), limits)
    if v3:
        signed_min = signed.u32()
        signed_max = signed.u32()
    attrs = _parse_attrs(signed.sub())
    min_sdk = max_sdk = None
    if v3:
        min_sdk = r.u32()
        max_sdk = r.u32()
        if (min_sdk, max_sdk) != (signed_min, signed_max):
            # apksig reports V3_*_SDK_VERSION_MISMATCH; we record the outer values.
            pass
    sigs = r.sub()
    while sigs.remaining() > 0:
        s = sigs.sub()
        s.u32()
        s.prefixed()
    r.prefixed()  # public key
    return _ParsedSigner(certs, attrs, min_sdk, max_sdk)


def _parse_signers(value: bytes, v3: bool, limits: Limits) -> list[_ParsedSigner]:
    outer = _R(value)
    seq = outer.sub()
    if outer.remaining() != 0:
        raise SigBlockFormatError("trailing bytes after the signer sequence")
    out: list[_ParsedSigner] = []
    while seq.remaining() > 0:
        if len(out) >= limits.max_signers_per_block:
            raise SigBlockFormatError("too many signers")
        out.append(_parse_signer(seq.sub(), v3, limits))
    if not out:
        raise SigBlockFormatError("no signers")
    return out


def _preview(value: bytes) -> str:
    return "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in value[:64])


def _native_signer(
    index: int, ps: _ParsedSigner, scheme: str, certs: dict[str, CertInfo], limits: Limits
) -> NativeSigner:
    chain = []
    for der in ps.certs:
        info = cert_info(der)
        certs.setdefault(info.sha256, info)
        chain.append(info.sha256)
    known = KNOWN_V2_ATTRS if scheme == "v2" else KNOWN_V3_ATTRS
    attr_ids = [a for a, _ in ps.attrs]
    signer = NativeSigner(
        index=index,
        cert_chain=chain,
        signer_cert=chain[0] if chain else None,
        min_sdk=ps.min_sdk,
        max_sdk=ps.max_sdk,
        attribute_ids=attr_ids,
        unknown_attribute_ids=sorted({a for a in attr_ids if a not in known}),
    )
    for aid, val in ps.attrs:
        if scheme == "v2" and aid == STRIPPING_PROTECTION_ATTR_ID and len(val) >= 4:
            signer.stripping_protection_scheme = int(struct.unpack_from("<I", val, 0)[0])
        elif scheme in ("v3", "v31") and aid == ROTATION_MIN_SDK_ATTR_ID and len(val) >= 4:
            signer.rotation_min_sdk = int(struct.unpack_from("<I", val, 0)[0])
        elif scheme in ("v3", "v31") and aid == POR_ATTR_ID:
            try:
                nodes = verify_lineage(parse_lineage(val, limits.max_lineage_nodes))
            except (LineageFormatError, SigBlockFormatError) as e:
                signer.lineage_error = str(e)
                continue
            signer.lineage = []
            for n in nodes:
                info = cert_info(n.cert_der)
                certs.setdefault(info.sha256, info)
                signer.lineage.append(
                    NativeLineageNode(
                        cert_sha256=n.cert_sha256,
                        flags=n.flags,
                        signed_sig_alg=n.signed_sig_alg,
                        next_sig_alg=n.next_sig_alg,
                        signature_valid=n.signature_valid,
                        capabilities=capabilities(n.flags),
                    )
                )
    return signer


def _sniff(value: bytes, limits: Limits) -> tuple[list[_ParsedSigner], bool] | None:
    """Try the v3 then the v2 schema. Success requires at least one real X.509 certificate."""
    for v3 in (True, False):
        try:
            signers = _parse_signers(value, v3, limits)
        except SigBlockFormatError:
            continue
        if any(is_x509(c) for s in signers for c in s.certs):
            return signers, v3
    return None


def _pair(pid: int, offset: int, value: bytes, name: str, kind: SigPairKind) -> SigBlockPair:
    return SigBlockPair(
        id=pid,
        id_hex=f"0x{pid:08x}",
        name=name,
        kind=kind,
        offset=offset,
        size=len(value),
        sha256=hashlib.sha256(value).hexdigest(),
        preview=_preview(value),
    )


def inventory_pairs(block: SigningBlock, certs: dict[str, CertInfo], limits: Limits) -> list[SigBlockPair]:
    out: list[SigBlockPair] = []
    for pid, offset, value in block.pairs:
        if pid in SIGNATURE_BLOCKS:
            scheme = SIGNATURE_BLOCKS[pid]
            pair = _pair(pid, offset, value, scheme, "signature")
            try:
                parsed = _parse_signers(value, scheme != "v2", limits)
                pair.signers = [_native_signer(i, ps, scheme, certs, limits) for i, ps in enumerate(parsed)]
            except SigBlockFormatError as e:
                pair.parse_error = str(e)
            out.append(pair)
        elif pid in SOURCE_STAMP_BLOCKS:
            out.append(_pair(pid, offset, value, SOURCE_STAMP_BLOCKS[pid], "source_stamp"))
        elif pid == VERITY_PADDING_ID:
            out.append(_pair(pid, offset, value, "verity_padding", "padding"))
        else:
            name = KNOWN_NON_SIGNATURE.get(pid, "unknown")
            sniffed = _sniff(value, limits)
            if sniffed is not None:
                signers, v3 = sniffed
                pair = _pair(pid, offset, value, name, "sniffed_signature")
                pair.signers = [
                    _native_signer(i, ps, "v3" if v3 else "v2", certs, limits) for i, ps in enumerate(signers)
                ]
                out.append(pair)
            else:
                out.append(_pair(pid, offset, value, name, "unsigned"))
    return out
