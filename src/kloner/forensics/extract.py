"""Forensic view of one APK (§10.2), extracted inside the bounded worker process.

The view is everything the diff needs: manifest capabilities, DEX classes with bytecode digests,
string constants, high-risk API references, native libraries and embedded files. Only what is
needed is parsed (class names, method code, strings); the full androguard analysis graph is never
built (§10.9).
"""

from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from pathlib import Path
from typing import Any

from kloner.container.detect import sniff_type
from kloner.container.zipstrict import ZipArchive, ZipFailure, entry_head, open_archive, read_entry
from kloner.forensics.dex import indicators, parse_dex
from kloner.util.limits import Limits

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def component_name(package: str, name: str) -> str:
    """Resolve a manifest component name the way Android does (".X" and "X" are package-relative)."""
    if name.startswith("."):
        return package + name
    if name and "." not in name:
        return f"{package}.{name}"
    return name


def _manifest(apk: Any) -> dict[str, Any]:
    xml = apk.get_android_manifest_xml()
    package = apk.get_package() or ""
    out: dict[str, Any] = {
        "permissions": sorted(set(apk.get_permissions() or [])),
        "components": [],
        "application": {},
        "launcher": None,
        "queries": [],
        "features": [],
        "shared_user_id": None,
    }
    if xml is None:
        return out
    out["shared_user_id"] = xml.get(ANDROID_NS + "sharedUserId")
    app = xml.find("application")
    if app is not None:
        for attr in (
            "debuggable",
            "allowBackup",
            "usesCleartextTraffic",
            "networkSecurityConfig",
            "testOnly",
            "name",
            "appComponentFactory",
        ):
            v = app.get(ANDROID_NS + attr)
            if v is not None:
                out["application"][attr] = v
        for tag in ("activity", "activity-alias", "service", "receiver", "provider"):
            for el in app.findall(tag):
                actions = sorted({a.get(ANDROID_NS + "name") or "" for a in el.iter("action")})
                cats = sorted({c.get(ANDROID_NS + "name") or "" for c in el.iter("category")})
                comp = {
                    "type": tag,
                    "name": component_name(package, el.get(ANDROID_NS + "name") or ""),
                    "exported": el.get(ANDROID_NS + "exported"),
                    "permission": el.get(ANDROID_NS + "permission"),
                    "actions": actions,
                    "categories": cats,
                }
                out["components"].append(comp)
                if (
                    tag in ("activity", "activity-alias")
                    and "android.intent.action.MAIN" in actions
                    and "android.intent.category.LAUNCHER" in cats
                    and out["launcher"] is None
                ):
                    out["launcher"] = comp["name"]
    q = xml.find("queries")
    if q is not None:
        out["queries"] = sorted({p.get(ANDROID_NS + "name") or "" for p in q.iter("package")})
    out["features"] = sorted({f.get(ANDROID_NS + "name") or "" for f in xml.iter("uses-feature")})
    out["components"].sort(key=lambda c: (c["type"], c["name"]))
    return out


def _files(archive: ZipArchive, limits: Limits) -> tuple[list[dict[str, Any]], list[str]]:
    files: list[dict[str, Any]] = []
    dex_names: list[str] = []
    for e in archive.entries:
        if e.is_dir:
            continue
        name = e.name
        if re.fullmatch(r"classes\d*\.dex", name):
            dex_names.append(name)
            continue
        rec: dict[str, Any] = {"name": name, "size": e.central.uncompressed_size, "crc32": f"{e.central.crc32:08x}"}
        interesting = name.startswith(("assets/", "lib/", "res/raw/")) or not name.startswith(("res/", "META-INF/"))
        if interesting and e.central.uncompressed_size <= (64 << 20):
            try:
                data = read_entry(archive, e, 64 << 20)
            except ZipFailure:
                data = b""
            rec["sha256"] = hashlib.sha256(data).hexdigest()
            rec["type"] = sniff_type(data[:8])
            if rec["type"] == "unknown" and len(data) >= 4096:
                rec["entropy"] = round(entropy(data[: 1 << 20]), 3)
        else:
            rec["type"] = sniff_type(entry_head(archive, e, 8))
        files.append(rec)
    files.sort(key=lambda f: f["name"])
    return files, sorted(dex_names, key=lambda n: (len(n), n))


def extract_view(req: dict[str, Any]) -> dict[str, Any]:
    from kloner.util.logging import quiet_third_party
    from kloner.verify.worker import limits_from_dict

    quiet_third_party()
    from androguard.core.apk import APK

    path = Path(req["path"])
    limits = limits_from_dict(req.get("limits", {}))
    archive = open_archive(path, limits)
    apk = APK(str(path))
    files, dex_names = _files(archive, limits)
    datas = []
    for n in dex_names:
        e = archive.get(n)
        if e is not None:
            datas.append(read_entry(archive, e, limits.max_dex_bytes))
    dex = parse_dex(datas)
    native = [
        {
            "name": f["name"],
            "sha256": f.get("sha256"),
            "abi": f["name"].split("/")[1] if f["name"].count("/") >= 2 else None,
        }
        for f in files
        if f["name"].startswith("lib/") and f["name"].endswith(".so")
    ]
    return {
        "sample_sha256": req.get("sha256"),
        "package": apk.get_package(),
        "version_code": apk.get_androidversion_code(),
        "manifest": _manifest(apk),
        "classes": dex["classes"],
        "strings_indicators": indicators(dex["strings"]),
        "risky_apis": dex["risky_apis"],
        "native": native,
        "files": files,
    }
