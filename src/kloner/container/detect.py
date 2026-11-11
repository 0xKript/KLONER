"""Content-based format detection (§9 G0, §6.5)."""

from __future__ import annotations

from dataclasses import dataclass

from kloner.container.zipstrict import Entry, ZipArchive, entry_head

ZIP_MAGIC = b"PK\x03\x04"

# Bundle metadata, per format:
#   XAPK (APKPure): manifest.json, icon.png, Android/obb/...
#   APKM (APKMirror): info.json, icon.png
#   APKS (bundletool build-apks): toc.pb
#   APKS (SAI): meta.sai_v1.json / meta.sai_v2.json, icon.png
BUNDLE_KINDS = (
    ("manifest.json", "xapk"),
    ("info.json", "apkm"),
    ("toc.pb", "apks"),
    ("meta.sai_v2.json", "apks"),
    ("meta.sai_v1.json", "apks"),
)
KNOWN_METADATA = frozenset({"manifest.json", "info.json", "icon.png", "toc.pb", "meta.sai_v1.json", "meta.sai_v2.json"})


@dataclass(frozen=True)
class Detection:
    format: str  # apk | bundle | aab | zip
    bundle_kind: str | None = None


def sniff_type(head: bytes) -> str:
    if head.startswith(ZIP_MAGIC):
        return "zip"
    if head.startswith(b"dex\n"):
        return "dex"
    if head.startswith(b"\x7fELF"):
        return "so"
    if head.startswith(b"#!"):
        return "script"
    if head.startswith(b"\x89PNG"):
        return "png"
    return "unknown"


def zip_members(archive: ZipArchive) -> list[Entry]:
    out = []
    for e in archive.entries:
        if e.is_dir or e.central.uncompressed_size < 4:
            continue
        if entry_head(archive, e, 4) == ZIP_MAGIC:
            out.append(e)
    return out


def detect(archive: ZipArchive) -> Detection:
    if archive.has("AndroidManifest.xml"):
        return Detection("apk")
    if archive.has("BundleConfig.pb") and archive.has("base/manifest/AndroidManifest.xml"):
        return Detection("aab")
    if zip_members(archive):
        kind = "zip"
        for name, k in BUNDLE_KINDS:
            if archive.has(name):
                kind = k
                break
        return Detection("bundle", kind)
    return Detection("zip")
