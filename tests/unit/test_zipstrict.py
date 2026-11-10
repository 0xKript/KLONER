from __future__ import annotations

import io
import struct
import zipfile
from dataclasses import replace
from pathlib import Path

import pytest

from kloner.container.detect import detect, sniff_type, zip_members
from kloner.container.zipstrict import (
    CentralEntry,
    Entry,
    LocalHeader,
    ZipArchive,
    ZipFailure,
    copy_entry,
    entry_head,
    find_eocd_candidates,
    hostile_name,
    open_archive,
    read_entry,
    structural_gate,
    verify_crcs,
)
from kloner.selftest.corpus import fixture_path
from kloner.util.limits import DEFAULT_LIMITS, Limits

MODERN = fixture_path("modern")


def test_clean_fixture_parses_and_verifies() -> None:
    a = open_archive(MODERN, DEFAULT_LIMITS)
    verify_crcs(a)
    assert a.has("AndroidManifest.xml") and a.get("classes.dex") is not None
    assert a.starts_with_local_header and len(a.eocd_candidates) == 1
    st = structural_gate(a, None)
    assert st.violations == [] and st.hostile_names == []
    assert detect(a).format == "apk"
    data = read_entry(a, a.get("AndroidManifest.xml"), 1 << 20)  # type: ignore[arg-type]
    assert data[:4] == b"\x03\x00\x08\x00"  # binary AXML
    sink = io.BytesIO()
    n, sha = copy_entry(a, a.get("classes.dex"), sink, 1 << 20)  # type: ignore[arg-type]
    assert n == len(sink.getvalue()) and len(sha) == 64
    assert entry_head(a, a.get("classes.dex"), 4) == b"dex\n"  # type: ignore[arg-type]


def test_empty_too_large_not_zip(tmp_path: Path) -> None:
    e = tmp_path / "e"
    e.write_bytes(b"")
    with pytest.raises(ZipFailure) as x:
        open_archive(e, DEFAULT_LIMITS)
    assert x.value.reason == "EMPTY"
    with pytest.raises(ZipFailure) as x:
        open_archive(MODERN, Limits(max_file_bytes=100))
    assert x.value.reason == "TOO_LARGE"
    h = tmp_path / "h.apk"
    h.write_text("<html>not an apk</html>")
    with pytest.raises(ZipFailure) as x:
        open_archive(h, DEFAULT_LIMITS)
    assert x.value.reason == "NOT_ZIP"


def test_truncated_and_corrupted_are_corrupt(tmp_path: Path) -> None:
    data = MODERN.read_bytes()
    t = tmp_path / "t.apk"
    t.write_bytes(data[: len(data) // 2])
    with pytest.raises(ZipFailure) as x:
        open_archive(t, DEFAULT_LIMITS)
    assert x.value.reason == "CORRUPT"
    with zipfile.ZipFile(MODERN) as z:
        info = z.getinfo("classes.dex")
    off = info.header_offset + 30 + len(info.filename) + len(info.extra) + info.compress_size // 2
    b = bytearray(data)
    b[off] ^= 0xFF
    c = tmp_path / "c.apk"
    c.write_bytes(bytes(b))
    a = open_archive(c, DEFAULT_LIMITS)
    with pytest.raises(ZipFailure) as x:
        verify_crcs(a)
    assert x.value.reason == "CORRUPT"


def test_limits_make_archives_unsafe() -> None:
    with pytest.raises(ZipFailure) as x:
        open_archive(MODERN, Limits(max_ratio=1))
    assert x.value.reason == "UNSAFE_ARCHIVE"
    with pytest.raises(ZipFailure) as x:
        open_archive(MODERN, Limits(max_entries=1))
    assert x.value.reason == "UNSAFE_ARCHIVE"
    with pytest.raises(ZipFailure) as x:
        open_archive(MODERN, Limits(max_total_uncompressed=10))
    assert x.value.reason == "UNSAFE_ARCHIVE"
    with pytest.raises(ZipFailure) as x:
        open_archive(MODERN, Limits(max_entry_uncompressed=10))
    assert x.value.reason == "UNSAFE_ARCHIVE"
    a = open_archive(MODERN, DEFAULT_LIMITS)
    with pytest.raises(ZipFailure):
        read_entry(a, a.get("classes.dex"), 4)  # type: ignore[arg-type]


def _eocd(entries: int, size: int, offset: int, comment: bytes = b"") -> bytes:
    return struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, entries, entries, size, offset, len(comment)) + comment


def test_zip64_and_multidisk_are_refused(tmp_path: Path) -> None:
    z64 = tmp_path / "z64"
    z64.write_bytes(b"PK\x03\x04" + b"\0" * 26 + _eocd(0xFFFF, 0, 0))
    with pytest.raises(ZipFailure) as x:
        open_archive(z64, DEFAULT_LIMITS)
    assert x.value.reason == "UNSUPPORTED_ZIP64"
    md = tmp_path / "md"
    md.write_bytes(b"PK\x03\x04" + b"\0" * 26 + struct.pack("<IHHHHIIH", 0x06054B50, 1, 0, 0, 0, 0, 0, 0))
    with pytest.raises(ZipFailure) as x:
        open_archive(md, DEFAULT_LIMITS)
    assert x.value.reason == "CORRUPT"


def test_encrypted_entry_is_detected(tmp_path: Path) -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("a.txt", b"hello")
    raw = bytearray(buf.getvalue())
    cd = raw.rfind(b"PK\x01\x02")
    raw[cd + 8] |= 0x01  # general-purpose flag bit 0: encrypted
    p = tmp_path / "enc.zip"
    p.write_bytes(bytes(raw))
    with pytest.raises(ZipFailure) as x:
        open_archive(p, DEFAULT_LIMITS)
    assert x.value.reason == "ENCRYPTED"


def test_eocd_candidates() -> None:
    tail = b"xx" + _eocd(0, 0, 0)
    cands, seen = find_eocd_candidates(tail, 0, len(tail))
    assert cands == [2] and seen
    cands, seen = find_eocd_candidates(b"nothing here", 0, 12)
    assert cands == [] and not seen


def _archive(entries: list[Entry], **kw: object) -> ZipArchive:
    base = {
        "path": MODERN,
        "size": 1000,
        "eocd_offset": 900,
        "eocd_candidates": [900],
        "cd_offset": 800,
        "cd_size": 100,
        "cd_parsed_size": 100,
        "comment": b"",
        "entries": entries,
        "starts_with_local_header": True,
        "total_uncompressed": 10,
    }
    base.update(kw)
    return ZipArchive(**base)  # type: ignore[arg-type]


def _entry(name: bytes, lho: int, local_name: bytes | None = None, method: int = 8, crc: int = 1) -> Entry:
    ce = CentralEntry(0, name, 0, method, crc, 10, 20, lho, 0)
    lh = LocalHeader(
        lho, 0, method, crc, 10, 20, local_name if local_name is not None else name, 0, lho + 30 + len(name)
    )
    return Entry(ce, lh, 0)


def test_structural_gate_rules_on_parsed_structures() -> None:
    ok = _archive([_entry(b"a", 0), _entry(b"b", 100)])
    assert structural_gate(ok, None).violations == []
    s1 = structural_gate(_archive([_entry(b"a", 64)], starts_with_local_header=False), None)
    assert [v.rule for v in s1.violations] == ["S1"] and s1.violations[0].kind == "POLYGLOT"
    s2 = structural_gate(_archive([_entry(b"a", 0), _entry(b"a", 100)]), None)
    assert [v.code for v in s2.violations] == ["DUPLICATE-ENTRY"]
    s3 = structural_gate(_archive([_entry(b"a", 0, local_name=b"b")]), None)
    assert [v.code for v in s3.violations] == ["LOCAL-CENTRAL-NAME-MISMATCH"]
    e = _entry(b"a", 0)
    mismatch = replace(e, local=replace(e.local, method=0))
    s3b = structural_gate(_archive([mismatch]), None)
    assert [v.code for v in s3b.violations] == ["LOCAL-CENTRAL-HEADER-MISMATCH"]
    s5 = structural_gate(_archive([_entry(b"a", 0)], eocd_candidates=[850, 900]), None)
    assert [v.code for v in s5.violations] == ["MULTIPLE-EOCD"]
    s5b = structural_gate(_archive([_entry(b"a", 0)], cd_size=50, cd_parsed_size=50), None)
    assert "EOCD-NOT-ADJACENT" in [v.code for v in s5b.violations]
    s5c = structural_gate(_archive([_entry(b"a", 0)], cd_parsed_size=60), None)
    assert "CENTRAL-DIRECTORY-SIZE-MISMATCH" in [v.code for v in s5c.violations]


@pytest.mark.parametrize(
    ("name", "why"),
    [
        (b"../evil.so", "'..' path segment"),
        (b"assets/../../x", "'..' path segment"),
        (b"/etc/passwd", "absolute path"),
        (b"C:\\x", "absolute path"),
        (b"a\x00b", "control or NUL character"),
        (b"res/raw/ok.bin", None),
    ],
)
def test_hostile_names(name: bytes, why: str | None) -> None:
    assert hostile_name(name) == why


def test_sniff_and_members(tmp_path: Path) -> None:
    assert sniff_type(b"PK\x03\x04....") == "zip"
    assert sniff_type(b"dex\n035\x00") == "dex"
    assert sniff_type(b"\x7fELF") == "so"
    assert sniff_type(b"#!/bin/sh") == "script"
    assert sniff_type(b"\x89PNG") == "png"
    assert sniff_type(b"????") == "unknown"
    p = tmp_path / "bundle.zip"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("manifest.json", "{}")
        z.writestr("base.apk", MODERN.read_bytes())
    a = open_archive(p, DEFAULT_LIMITS)
    assert [e.name for e in zip_members(a)] == ["base.apk"]
    d = detect(a)
    assert d.format == "bundle" and d.bundle_kind == "xapk"
    q = tmp_path / "plain.zip"
    with zipfile.ZipFile(q, "w") as z:
        z.writestr("readme.txt", "hi")
    assert detect(open_archive(q, DEFAULT_LIMITS)).format == "zip"


def _with_leading(tmp_path: Path, prefix: bytes) -> Path:
    """A ZIP whose entries follow ``prefix``; the central directory offsets include it (D-068)."""
    buf = io.BytesIO()
    buf.write(prefix)
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        z.writestr("a.txt", b"hello")
        z.writestr("b.txt", b"world")
    p = tmp_path / "leading.zip"
    p.write_bytes(buf.getvalue())
    return p


def _empty_header(
    name: bytes, *, flags: int = 0, method: int = 0, crc: int = 0, size: int = 0, extra: bytes = b""
) -> bytes:
    return (
        struct.pack(
            "<IHHHHHIIIHH", 0x04034B50, 0, flags, method, 0x0821, 0x0221, crc, size, size, len(name), len(extra)
        )
        + name
        + extra
    )


@pytest.mark.parametrize(
    "prefix",
    [
        # DuckDuckGo's own release 5.114.3: one stored, empty local header with an empty name and a 102-byte
        # zero-filled extra field (alignment padding), not listed in the central directory, then the entries
        _empty_header(b"", extra=b"\x00" * 102),
        _empty_header(b"\x00" * 102),  # the same padding in a NUL name
        _empty_header(b"", extra=b"\x00" * 40) + _empty_header(b"", extra=b"\x00" * 32),  # two of them
    ],
)
def test_leading_empty_local_headers_are_padding_not_a_polyglot(tmp_path: Path, prefix: bytes) -> None:
    a = open_archive(_with_leading(tmp_path, prefix), DEFAULT_LIMITS)
    assert a.starts_with_local_header and min(e.local.offset for e in a.entries) == len(prefix)
    st = structural_gate(a, None)
    assert st.violations == []
    assert st.unreferenced[0].start == 0 and st.unreferenced[0].end == len(prefix)


@pytest.mark.parametrize(
    "prefix",
    [
        _empty_header(b"x" * 102),  # a real name
        _empty_header(b"", extra=b"\x00" * 50 + b"\x01" + b"\x00" * 51),  # an extra field that holds a byte
        _empty_header(b"\x00" * 10, size=4) + b"DATA",  # data
        _empty_header(b"\x00" * 10, crc=1),
        _empty_header(b"\x00" * 10, method=8),
        _empty_header(b"\x00" * 10, flags=0x0008),  # a data descriptor
        _empty_header(b"\x00" * 10) + b"\x00" * 7,  # trailing bytes that are no header
        b"dex\n035\x00" + b"\x00" * 104,  # a DEX header (Janus class)
    ],
)
def test_leading_bytes_that_could_carry_anything_stay_s1(tmp_path: Path, prefix: bytes) -> None:
    st = structural_gate(open_archive(_with_leading(tmp_path, prefix), DEFAULT_LIMITS), None)
    assert [v.rule for v in st.violations] == ["S1"] and st.violations[0].kind == "POLYGLOT"
