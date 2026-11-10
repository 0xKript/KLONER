"""Strict, bounded ZIP parsing (§9 G0, G2, G4).

This parser reads the archive the way a careful verifier must: it locates every EOCD candidate,
parses the central directory with hard limits, reads every local header, streams every entry
through CRC-32, and reports the structural facts that the structural gate decides on.

It never extracts anything to disk.
"""

from __future__ import annotations

import hashlib
import itertools
import struct
import zlib
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO

from kloner.models import ByteGap, StructureFacts, StructureViolation
from kloner.util.limits import Limits

LOCAL_SIG = 0x04034B50
CENTRAL_SIG = 0x02014B50
EOCD_SIG = 0x06054B50
ZIP64_LOCATOR_SIG = 0x07064B50
DATA_DESCRIPTOR_SIG = 0x08074B50

EOCD_SIZE = 22
MAX_COMMENT = 0xFFFF
LOCAL_FIXED = 30
CENTRAL_FIXED = 46
READ_CHUNK = 1 << 16
INFLATE_OUT_CHUNK = 1 << 20

FLAG_ENCRYPTED = 0x0001
FLAG_DATA_DESCRIPTOR = 0x0008
FLAG_STRONG_ENCRYPTION = 0x0040
FLAG_UTF8 = 0x0800

METHOD_STORED = 0
METHOD_DEFLATED = 8


class ZipFailure(Exception):
    """A typed parse failure. ``reason`` maps onto an INVALID reason or an intake reason."""

    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(f"{reason}: {detail}")
        self.reason = reason
        self.detail = detail


@dataclass(frozen=True)
class CentralEntry:
    index: int
    name: bytes
    flags: int
    method: int
    crc32: int
    compressed_size: int
    uncompressed_size: int
    local_header_offset: int
    disk_start: int


@dataclass(frozen=True)
class LocalHeader:
    offset: int
    flags: int
    method: int
    crc32: int
    compressed_size: int
    uncompressed_size: int
    name: bytes
    extra_len: int
    data_offset: int


@dataclass(frozen=True)
class Entry:
    central: CentralEntry
    local: LocalHeader
    descriptor_len: int

    @property
    def raw_name(self) -> bytes:
        return self.central.name

    @property
    def name(self) -> str:
        return decode_name(self.central.name, self.central.flags)

    @property
    def data_offset(self) -> int:
        return self.local.data_offset

    @property
    def data_end(self) -> int:
        return self.local.data_offset + self.central.compressed_size

    @property
    def record_end(self) -> int:
        return self.data_end + self.descriptor_len

    @property
    def is_dir(self) -> bool:
        return self.central.name.endswith(b"/")


@dataclass
class ZipArchive:
    path: Path
    size: int
    eocd_offset: int
    eocd_candidates: list[int]
    cd_offset: int
    cd_size: int
    cd_parsed_size: int
    comment: bytes
    entries: list[Entry]
    starts_with_local_header: bool
    total_uncompressed: int
    _by_name: dict[bytes, list[Entry]] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        for e in self.entries:
            self._by_name.setdefault(e.raw_name, []).append(e)

    def get(self, name: str) -> Entry | None:
        """First central-directory entry with this exact name (duplicates are an S2 violation)."""
        found = self._by_name.get(name.encode("utf-8"))
        return found[0] if found else None

    def has(self, name: str) -> bool:
        return name.encode("utf-8") in self._by_name

    def names(self) -> list[str]:
        return [e.name for e in self.entries]

    def duplicates(self) -> list[bytes]:
        return sorted(n for n, es in self._by_name.items() if len(es) > 1)


def decode_name(raw: bytes, flags: int) -> str:
    if flags & FLAG_UTF8:
        return raw.decode("utf-8", errors="replace")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("cp437", errors="replace")


def _u16(b: bytes, o: int) -> int:
    return int(struct.unpack_from("<H", b, o)[0])


def _u32(b: bytes, o: int) -> int:
    return int(struct.unpack_from("<I", b, o)[0])


def _read_at(f: BinaryIO, offset: int, n: int) -> bytes:
    f.seek(offset)
    return f.read(n)


def find_eocd_candidates(tail: bytes, tail_offset: int, file_size: int) -> tuple[list[int], bool]:
    """Every EOCD whose comment length makes it end exactly at end of file.

    Returns (candidate file offsets sorted ascending, whether any EOCD signature was seen at all).
    """
    sig = struct.pack("<I", EOCD_SIG)
    candidates: list[int] = []
    seen_any = False
    pos = tail.rfind(sig)
    while pos != -1:
        if pos + EOCD_SIZE <= len(tail):
            seen_any = True
            comment_len = _u16(tail, pos + 20)
            if tail_offset + pos + EOCD_SIZE + comment_len == file_size:
                candidates.append(tail_offset + pos)
        pos = tail.rfind(sig, 0, pos)
    return sorted(candidates), seen_any


def open_archive(path: Path, limits: Limits) -> ZipArchive:
    """Parse EOCD, central directory and every local header. Raises ZipFailure."""
    size = path.stat().st_size
    if size == 0:
        raise ZipFailure("EMPTY", "file is empty")
    if size > limits.max_file_bytes:
        raise ZipFailure("TOO_LARGE", f"{size} bytes exceeds the {limits.max_file_bytes}-byte limit")
    with path.open("rb") as f:
        head = f.read(4)
        starts_local = len(head) == 4 and _u32(head, 0) == LOCAL_SIG
        tail_len = min(size, EOCD_SIZE + MAX_COMMENT + 20)
        tail_offset = size - tail_len
        tail = _read_at(f, tail_offset, tail_len)
        candidates, seen_any = find_eocd_candidates(tail, tail_offset, size)
        if not candidates:
            if starts_local or seen_any:
                raise ZipFailure("CORRUPT", "no end-of-central-directory record ends the file (truncated?)")
            raise ZipFailure("NOT_ZIP", "no ZIP end-of-central-directory record")
        eocd_offset = candidates[-1]
        eocd = tail[eocd_offset - tail_offset : eocd_offset - tail_offset + EOCD_SIZE]
        disk_no, cd_disk, disk_entries, total_entries = (_u16(eocd, 4), _u16(eocd, 6), _u16(eocd, 8), _u16(eocd, 10))
        cd_size, cd_offset, comment_len = _u32(eocd, 12), _u32(eocd, 16), _u16(eocd, 20)
        comment = tail[eocd_offset - tail_offset + EOCD_SIZE : eocd_offset - tail_offset + EOCD_SIZE + comment_len]
        if total_entries == 0xFFFF or cd_size == 0xFFFFFFFF or cd_offset == 0xFFFFFFFF:
            raise ZipFailure("UNSUPPORTED_ZIP64", "EOCD fields carry ZIP64 sentinels")
        if eocd_offset >= 20:
            loc = _read_at(f, eocd_offset - 20, 4)
            if len(loc) == 4 and _u32(loc, 0) == ZIP64_LOCATOR_SIG:
                raise ZipFailure("UNSUPPORTED_ZIP64", "ZIP64 end-of-central-directory locator present")
        if disk_no != 0 or cd_disk != 0 or disk_entries != total_entries:
            raise ZipFailure("CORRUPT", "multi-disk archive fields are not zero/consistent")
        if total_entries > limits.max_entries:
            raise ZipFailure("UNSAFE_ARCHIVE", f"{total_entries} entries exceeds the limit of {limits.max_entries}")
        if cd_offset + cd_size > eocd_offset:
            raise ZipFailure("CORRUPT", "central directory overlaps the EOCD record")
        cd = _read_at(f, cd_offset, cd_size)
        if len(cd) != cd_size:
            raise ZipFailure("CORRUPT", "central directory truncated")

        centrals: list[CentralEntry] = []
        total_uncompressed = 0
        p = 0
        for idx in range(total_entries):
            if p + CENTRAL_FIXED > cd_size:
                raise ZipFailure("CORRUPT", f"central directory entry {idx} truncated")
            if _u32(cd, p) != CENTRAL_SIG:
                raise ZipFailure("CORRUPT", f"bad central directory signature at entry {idx}")
            flags, method = _u16(cd, p + 8), _u16(cd, p + 10)
            crc, csize, usize = _u32(cd, p + 16), _u32(cd, p + 20), _u32(cd, p + 24)
            nlen, elen, clen = _u16(cd, p + 28), _u16(cd, p + 30), _u16(cd, p + 32)
            disk_start, lho = _u16(cd, p + 34), _u32(cd, p + 42)
            end = p + CENTRAL_FIXED + nlen + elen + clen
            if end > cd_size:
                raise ZipFailure("CORRUPT", f"central directory entry {idx} overruns the directory")
            name = cd[p + CENTRAL_FIXED : p + CENTRAL_FIXED + nlen]
            if csize == 0xFFFFFFFF or usize == 0xFFFFFFFF or lho == 0xFFFFFFFF:
                raise ZipFailure("UNSUPPORTED_ZIP64", f"entry {idx} uses ZIP64 size/offset sentinels")
            if flags & (FLAG_ENCRYPTED | FLAG_STRONG_ENCRYPTION):
                raise ZipFailure("ENCRYPTED", f"entry {decode_name(name, flags)!r} is encrypted")
            if method not in (METHOD_STORED, METHOD_DEFLATED):
                raise ZipFailure(
                    "CORRUPT", f"entry {decode_name(name, flags)!r}: unsupported compression method {method}"
                )
            if disk_start != 0:
                raise ZipFailure("CORRUPT", f"entry {idx} starts on disk {disk_start}")
            if usize > limits.max_entry_uncompressed:
                raise ZipFailure("UNSAFE_ARCHIVE", f"entry {decode_name(name, flags)!r} declares {usize} bytes")
            if method == METHOD_STORED and csize != usize:
                raise ZipFailure("CORRUPT", f"stored entry {decode_name(name, flags)!r} has csize != usize")
            if method == METHOD_DEFLATED and usize > 0 and (csize == 0 or usize / csize > limits.max_ratio):
                raise ZipFailure(
                    "UNSAFE_ARCHIVE",
                    f"entry {decode_name(name, flags)!r} compression ratio exceeds {limits.max_ratio}:1",
                )
            total_uncompressed += usize
            if total_uncompressed > limits.max_total_uncompressed:
                raise ZipFailure("UNSAFE_ARCHIVE", f"total uncompressed size exceeds {limits.max_total_uncompressed}")
            centrals.append(CentralEntry(idx, name, flags, method, crc, csize, usize, lho, disk_start))
            p = end

        entries: list[Entry] = []
        for ce in centrals:
            if ce.local_header_offset + LOCAL_FIXED > cd_offset:
                raise ZipFailure("CORRUPT", f"entry {ce.index} local header lies outside the entry area")
            lh = _read_at(f, ce.local_header_offset, LOCAL_FIXED)
            if len(lh) != LOCAL_FIXED or _u32(lh, 0) != LOCAL_SIG:
                raise ZipFailure("CORRUPT", f"no local header at offset {ce.local_header_offset} (entry {ce.index})")
            lflags, lmethod = _u16(lh, 6), _u16(lh, 8)
            lcrc, lcsize, lusize = _u32(lh, 14), _u32(lh, 18), _u32(lh, 22)
            lnlen, lelen = _u16(lh, 26), _u16(lh, 28)
            lname = _read_at(f, ce.local_header_offset + LOCAL_FIXED, lnlen)
            data_offset = ce.local_header_offset + LOCAL_FIXED + lnlen + lelen
            data_end = data_offset + ce.compressed_size
            if data_end > cd_offset:
                raise ZipFailure("CORRUPT", f"entry {ce.index} data extends past the central directory")
            desc_len = 0
            if (ce.flags | lflags) & FLAG_DATA_DESCRIPTOR:
                peek = _read_at(f, data_end, 4)
                desc_len = 16 if len(peek) == 4 and _u32(peek, 0) == DATA_DESCRIPTOR_SIG else 12
            local = LocalHeader(
                ce.local_header_offset, lflags, lmethod, lcrc, lcsize, lusize, lname, lelen, data_offset
            )
            entries.append(Entry(ce, local, desc_len))

    ordered = sorted(entries, key=lambda e: e.local.offset)
    for prev, nxt in itertools.pairwise(ordered):
        if nxt.local.offset < prev.record_end:
            raise ZipFailure("UNSAFE_ARCHIVE", f"entries {prev.name!r} and {nxt.name!r} overlap")

    return ZipArchive(
        path=path,
        size=size,
        eocd_offset=eocd_offset,
        eocd_candidates=candidates,
        cd_offset=cd_offset,
        cd_size=cd_size,
        cd_parsed_size=p,
        comment=comment,
        entries=entries,
        starts_with_local_header=starts_local,
        total_uncompressed=total_uncompressed,
    )


def stream_entry(f: BinaryIO, entry: Entry, limit: int) -> Iterator[bytes]:
    """Yield the decompressed bytes of ``entry``; raises ZipFailure on corruption or over-limit."""
    ce = entry.central
    f.seek(entry.data_offset)
    remaining = ce.compressed_size
    if ce.method == METHOD_STORED:
        while remaining > 0:
            chunk = f.read(min(READ_CHUNK, remaining))
            if not chunk:
                raise ZipFailure("CORRUPT", f"{entry.name!r}: truncated data")
            remaining -= len(chunk)
            yield chunk
        return
    d = zlib.decompressobj(-15)
    produced = 0
    try:
        while remaining > 0 and not d.eof:
            chunk = f.read(min(READ_CHUNK, remaining))
            if not chunk:
                raise ZipFailure("CORRUPT", f"{entry.name!r}: truncated compressed data")
            remaining -= len(chunk)
            buf = chunk
            while buf and not d.eof:
                out = d.decompress(buf, INFLATE_OUT_CHUNK)
                produced += len(out)
                if produced > limit:
                    raise ZipFailure("CORRUPT", f"{entry.name!r}: inflates beyond its declared size")
                if out:
                    yield out
                buf = d.unconsumed_tail
        while not d.eof:
            out = d.decompress(b"", INFLATE_OUT_CHUNK)
            if not out:
                break
            produced += len(out)
            if produced > limit:
                raise ZipFailure("CORRUPT", f"{entry.name!r}: inflates beyond its declared size")
            yield out
    except zlib.error as e:
        raise ZipFailure("CORRUPT", f"{entry.name!r}: inflate error: {e}") from e
    if not d.eof:
        raise ZipFailure("CORRUPT", f"{entry.name!r}: deflate stream does not terminate")
    if remaining > 0 or d.unused_data:
        raise ZipFailure("CORRUPT", f"{entry.name!r}: compressed data continues after the deflate stream")


def verify_crcs(archive: ZipArchive) -> None:
    """Stream every entry through CRC-32 and size checks (§9 G2)."""
    with archive.path.open("rb") as f:
        for e in archive.entries:
            crc = 0
            n = 0
            for block in stream_entry(f, e, e.central.uncompressed_size):
                crc = zlib.crc32(block, crc)
                n += len(block)
            if n != e.central.uncompressed_size:
                raise ZipFailure("CORRUPT", f"{e.name!r}: size {n} != declared {e.central.uncompressed_size}")
            if (crc & 0xFFFFFFFF) != e.central.crc32:
                raise ZipFailure("CORRUPT", f"{e.name!r}: CRC-32 mismatch")


def read_entry(archive: ZipArchive, entry: Entry, max_bytes: int) -> bytes:
    if entry.central.uncompressed_size > max_bytes:
        raise ZipFailure("UNSAFE_ARCHIVE", f"{entry.name!r} is larger than the {max_bytes}-byte read limit")
    with archive.path.open("rb") as f:
        return b"".join(stream_entry(f, entry, entry.central.uncompressed_size))


def entry_head(archive: ZipArchive, entry: Entry, n: int) -> bytes:
    """The first ``n`` decompressed bytes of an entry (for type sniffing)."""
    out = bytearray()
    with archive.path.open("rb") as f:
        try:
            for block in stream_entry(f, entry, entry.central.uncompressed_size):
                out.extend(block)
                if len(out) >= n:
                    break
        except ZipFailure:
            pass
    return bytes(out[:n])


def copy_entry(archive: ZipArchive, entry: Entry, sink: BinaryIO, max_bytes: int) -> tuple[int, str]:
    """Stream an entry into ``sink``; returns (size, sha256)."""
    if entry.central.uncompressed_size > max_bytes:
        raise ZipFailure("UNSAFE_ARCHIVE", f"{entry.name!r} exceeds the member size limit")
    h = hashlib.sha256()
    n = 0
    with archive.path.open("rb") as f:
        for block in stream_entry(f, entry, entry.central.uncompressed_size):
            h.update(block)
            sink.write(block)
            n += len(block)
    return n, h.hexdigest()


def hostile_name(name: bytes) -> str | None:
    """Why an entry name is hostile, or None (absolute paths, '..' segments, NUL/control characters)."""
    text = name.decode("utf-8", errors="replace")
    if any(c < 0x20 or c == 0x7F for c in name):
        return "control or NUL character"
    if text.startswith(("/", "\\")) or (len(text) > 1 and text[1] == ":"):
        return "absolute path"
    parts = text.replace("\\", "/").split("/")
    if ".." in parts:
        return "'..' path segment"
    return None


MAX_LEADING_PADDING = 1 << 20


def _empty_local_headers(archive: ZipArchive, end: int) -> ByteGap | None:
    """The bytes before the first listed entry, if they are only empty local headers, else None (D-068).

    Each header must be stored (method 0), unencrypted, without a data descriptor, with CRC-32 and both sizes 0, and
    its name and extra field must hold only zero bytes (zero-filled extra fields are how Android's zip tools pad for
    alignment). It carries no data any parser could read, and the central directory does not list it. DuckDuckGo's
    own release 5.114.3 starts with one (an empty name and 102 zero bytes of extra field), inside its v2 signature.
    """
    if not 0 < end <= MAX_LEADING_PADDING:
        return None
    with archive.path.open("rb") as f:
        head = f.read(end)
    pos = 0
    while pos < end:
        if end - pos < LOCAL_FIXED or _u32(head, pos) != LOCAL_SIG:
            return None
        flags, method = _u16(head, pos + 6), _u16(head, pos + 8)
        crc, csize, usize = _u32(head, pos + 14), _u32(head, pos + 18), _u32(head, pos + 22)
        nlen, xlen = _u16(head, pos + 26), _u16(head, pos + 28)
        rest = head[pos + LOCAL_FIXED : pos + LOCAL_FIXED + nlen + xlen]  # name, then extra field
        if flags & (FLAG_ENCRYPTED | FLAG_DATA_DESCRIPTOR) or method or crc or csize or usize:
            return None
        if len(rest) != nlen + xlen or rest.count(0) != len(rest):
            return None
        pos += LOCAL_FIXED + nlen + xlen
    return ByteGap(start=0, end=end, sha256=hashlib.sha256(head).hexdigest()) if pos == end else None


def structural_gate(archive: ZipArchive, signing_block: tuple[int, int] | None) -> StructureFacts:
    """Rules S1, S2, S3, S5 (decisive) and the informational structure facts (§9 G4)."""
    violations: list[StructureViolation] = []
    first_lho = min((e.local.offset for e in archive.entries), default=0)
    padding = _empty_local_headers(archive, first_lho) if archive.starts_with_local_header else None
    if padding is None and (not archive.starts_with_local_header or first_lho != 0):
        violations.append(
            StructureViolation(
                rule="S1",
                kind="POLYGLOT",
                code="DATA-BEFORE-FIRST-ENTRY",
                detail=(
                    f"the file does not start with a ZIP local file header (first local header at {first_lho})"
                    if not archive.starts_with_local_header
                    else f"{first_lho} bytes before the first entry the central directory lists are not empty padding"
                ),
            )
        )
    for dup in archive.duplicates():
        violations.append(
            StructureViolation(
                rule="S2",
                kind="ZIP_AMBIGUITY",
                code="DUPLICATE-ENTRY",
                detail=f"entry name {decode_name(dup, FLAG_UTF8)!r} appears more than once",
            )
        )
    for e in archive.entries:
        ce, lh = e.central, e.local
        if lh.name != ce.name:
            violations.append(
                StructureViolation(
                    rule="S3",
                    kind="ZIP_AMBIGUITY",
                    code="LOCAL-CENTRAL-NAME-MISMATCH",
                    detail=f"central entry {e.name!r} points at a local header named "
                    f"{decode_name(lh.name, lh.flags)!r}",
                )
            )
            continue
        mismatch = []
        if lh.method != ce.method:
            mismatch.append("compression method")
        if (lh.flags & FLAG_DATA_DESCRIPTOR) != (ce.flags & FLAG_DATA_DESCRIPTOR):
            mismatch.append("data-descriptor flag")
        elif not lh.flags & FLAG_DATA_DESCRIPTOR:
            if lh.crc32 != ce.crc32:
                mismatch.append("CRC-32")
            if lh.compressed_size != ce.compressed_size or lh.uncompressed_size != ce.uncompressed_size:
                mismatch.append("sizes")
        if mismatch:
            violations.append(
                StructureViolation(
                    rule="S3",
                    kind="ZIP_AMBIGUITY",
                    code="LOCAL-CENTRAL-HEADER-MISMATCH",
                    detail=f"{e.name!r}: local and central headers disagree on {', '.join(mismatch)}",
                )
            )
    if len(archive.eocd_candidates) != 1:
        violations.append(
            StructureViolation(
                rule="S5",
                kind="ZIP_AMBIGUITY",
                code="MULTIPLE-EOCD",
                detail=f"{len(archive.eocd_candidates)} end-of-central-directory records end the file",
            )
        )
    if archive.cd_offset + archive.cd_size != archive.eocd_offset:
        violations.append(
            StructureViolation(
                rule="S5",
                kind="ZIP_AMBIGUITY",
                code="EOCD-NOT-ADJACENT",
                detail="bytes lie between the central directory and the EOCD record",
            )
        )
    if archive.cd_parsed_size != archive.cd_size:
        violations.append(
            StructureViolation(
                rule="S5",
                kind="ZIP_AMBIGUITY",
                code="CENTRAL-DIRECTORY-SIZE-MISMATCH",
                detail=f"central directory declares {archive.cd_size} bytes but its entries span "
                f"{archive.cd_parsed_size}",
            )
        )

    hostile = sorted({f"{e.name!r}: {why}" for e in archive.entries if (why := hostile_name(e.raw_name))})
    gaps = _unreferenced(archive, signing_block)
    if padding is not None:
        gaps.insert(0, padding)  # reported as UNREFERENCED_BYTES, a notice
    return StructureFacts(violations=violations, unreferenced=gaps, hostile_names=hostile)


def _unreferenced(archive: ZipArchive, signing_block: tuple[int, int] | None) -> list[ByteGap]:
    spans: list[tuple[int, int]] = [(e.local.offset, e.record_end) for e in archive.entries]
    if signing_block:
        spans.append(signing_block)
    spans.append((archive.cd_offset, archive.cd_offset + archive.cd_size))
    spans.sort()
    gaps: list[tuple[int, int]] = []
    cursor = min((s for s, _ in spans), default=0)
    for start, end in spans:
        if start > cursor:
            gaps.append((cursor, start))
        cursor = max(cursor, end)
    if cursor < archive.eocd_offset:
        gaps.append((cursor, archive.eocd_offset))
    # Zero-filled gaps are alignment padding (apksigner page-aligns the APK Signing Block); they are
    # not reported. Any gap carrying a non-zero byte is reported with its hash.
    out: list[ByteGap] = []
    with archive.path.open("rb") as f:
        for start, end in gaps[:256]:
            h = hashlib.sha256()
            nonzero = False
            f.seek(start)
            remaining = end - start
            while remaining > 0:
                block = f.read(min(READ_CHUNK, remaining))
                if not block:
                    break
                h.update(block)
                nonzero = nonzero or block.count(0) != len(block)
                remaining -= len(block)
            if nonzero:
                out.append(ByteGap(start=start, end=end, sha256=h.hexdigest()))
    return out
