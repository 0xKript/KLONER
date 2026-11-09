"""Launcher icon assets (§11, §7.8): every density, round icons and adaptive-icon layers.

Icons are resolved through resources.arsc across all configurations. The bytes of every resolved
asset are hashed with SHA-256; EXACT_ICON means byte-identical to an official icon asset.
"""

from __future__ import annotations

import io
from typing import Any

from kloner.container.zipstrict import ZipArchive, ZipFailure, read_entry
from kloner.impersonation.labels import ANDROID_NS, resource_id
from kloner.util.hashing import sha256_bytes

MAX_ICON_BYTES = 8 << 20
ADAPTIVE_LAYERS = ("foreground", "background", "monochrome")


def _launcher_refs(apk: Any) -> list[str]:
    refs: list[str] = []
    xml = apk.get_android_manifest_xml()
    if xml is None:
        return refs
    app = xml.find("application")
    if app is not None:
        for attr in ("icon", "roundIcon"):
            v = app.get(ANDROID_NS + attr)
            if v:
                refs.append(v)
        for tag in ("activity", "activity-alias"):
            for act in app.findall(tag):
                cats = {c.get(ANDROID_NS + "name") for c in act.iter("category")}
                if "android.intent.category.LAUNCHER" in cats:
                    for attr in ("icon", "roundIcon"):
                        v = act.get(ANDROID_NS + attr)
                        if v:
                            refs.append(v)
    return refs


def _resolve(apk: Any, arsc: Any, ref: str, depth: int, out: set[str]) -> None:
    rid = resource_id(ref)
    if rid is None or depth > 3:
        return
    for _cfg, value in arsc.get_resolved_res_configs(rid):
        if not isinstance(value, str) or not value.startswith("res/"):
            continue
        out.add(value)
        if value.endswith(".xml"):
            try:
                from androguard.core.axml import AXMLPrinter

                root = AXMLPrinter(apk.get_file(value)).get_xml_obj()
            # not a readable adaptive icon: no layers to add
            except Exception:  # noqa: S112  # nosec B112
                continue
            if root is None:
                continue
            for layer in ADAPTIVE_LAYERS:
                for el in root.iter(layer):
                    d = el.get(ANDROID_NS + "drawable")
                    if d:
                        _resolve(apk, arsc, d, depth + 1, out)


def dhash(data: bytes) -> str | None:
    """64-bit difference hash of a raster icon (heuristic lookalike evidence only, §11)."""
    try:
        from PIL import Image

        Image.MAX_IMAGE_PIXELS = 16_000_000
        with Image.open(io.BytesIO(data)) as im:
            im.draft("L", (64, 64))
            g = im.convert("L").resize((9, 8), Image.Resampling.LANCZOS)
            flat = getattr(g, "get_flattened_data", None)
            px = list(flat() if flat else g.getdata())
    except Exception:
        return None
    bits = 0
    for row in range(8):
        for col in range(8):
            bits = (bits << 1) | (px[row * 9 + col] > px[row * 9 + col + 1])
    return f"{bits:016x}"


def resolve_icon_assets(apk: Any, archive: ZipArchive) -> tuple[list[str], list[str], list[str], str | None]:
    """Return (asset paths, SHA-256 of each asset's bytes, dHashes of raster assets, error or None)."""
    try:
        arsc = apk.get_android_resources()
        refs = _launcher_refs(apk)
    except Exception as e:
        return [], [], [], f"{type(e).__name__}: {e}"
    if arsc is None or not refs:
        return [], [], [], None if not refs else "no resource table"
    paths: set[str] = set()
    try:
        for ref in refs:
            _resolve(apk, arsc, ref, 0, paths)
    except Exception as e:
        return sorted(paths), [], [], f"{type(e).__name__}: {e}"
    hashes: set[str] = set()
    dhashes: set[str] = set()
    for p in sorted(paths):
        entry = archive.get(p)
        if entry is None:
            continue
        try:
            data = read_entry(archive, entry, MAX_ICON_BYTES)
        except ZipFailure:
            continue
        hashes.add(sha256_bytes(data))
        if not p.endswith(".xml"):
            dh = dhash(data)
            if dh:
                dhashes.add(dh)
    return sorted(paths), sorted(hashes), sorted(dhashes), None
