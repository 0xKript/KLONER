"""Manifest identity with two independent parsers (§9 G3): androguard (binary AXML) and aapt2 badging.

Any disagreement on package, versionCode, versionName, split, minSdk or targetSdk is a fact that
``decide()`` turns into ANOMALY(PARSER_DIFFERENTIAL). Either parser failing is MANIFEST_UNREADABLE.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from kloner.models import ManifestFacts, ManifestView
from kloner.util import proc

_KV = re.compile(r"(\w+)='((?:[^'\\]|\\.)*)'")
_SDK_LINE = re.compile(r"^(sdkVersion|minSdkVersion|targetSdkVersion):'([^']*)'\s*$")
_UNRESOLVED_REF = re.compile(r"^@(?:[0-9A-Fa-f]{8}|[\w.:]+/[\w.]+)$")
CODENAME_SDK = 10_000  # apksig treats a codename minSdk as "newer than any released level"


def _sdk(value: str | None) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except ValueError:
        return CODENAME_SDK


def _int(value: str | None) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value, 0)
    except ValueError:
        return None


def normalize(view: ManifestView) -> ManifestView:
    """Apply platform defaults: minSdk defaults to 1, targetSdk defaults to minSdk."""
    min_sdk = view.min_sdk if view.min_sdk is not None else 1
    target = view.target_sdk if view.target_sdk is not None else min_sdk
    return view.model_copy(update={"min_sdk": min_sdk, "target_sdk": target})


def androguard_view(apk: Any) -> ManifestView:
    """Read the manifest identity from an androguard ``APK`` object."""
    package = apk.get_package()
    if not package:
        raise ValueError("androguard found no package name")
    split = apk.get_attribute_value("manifest", "split")
    return normalize(
        ManifestView(
            package=package,
            version_code=_int(apk.get_androidversion_code()),
            version_name=apk.get_androidversion_name() or None,
            split=split or None,
            min_sdk=_sdk(apk.get_min_sdk_version()),
            target_sdk=_sdk(apk.get_target_sdk_version()),
        )
    )


def parse_badging(text: str) -> ManifestView:
    package_line = next((ln for ln in text.splitlines() if ln.startswith("package:")), None)
    if package_line is None:
        raise ValueError("aapt2 badging has no package line")
    kv = dict(_KV.findall(package_line))
    sdk: dict[str, str] = {}
    for ln in text.splitlines():
        m = _SDK_LINE.match(ln.strip())
        if m:
            sdk[m.group(1)] = m.group(2)
    min_sdk = sdk.get("minSdkVersion", sdk.get("sdkVersion"))
    if not kv.get("name"):
        raise ValueError("aapt2 badging has no package name")
    return normalize(
        ManifestView(
            package=kv.get("name"),
            version_code=_int(kv.get("versionCode")),
            version_name=kv.get("versionName") or None,
            split=kv.get("split") or None,
            min_sdk=_sdk(min_sdk),
            target_sdk=_sdk(sdk.get("targetSdkVersion")),
        )
    )


def aapt2_view(path: Path, aapt2: Path, timeout_s: float = 120.0) -> ManifestView:
    res = proc.run([aapt2, "dump", "badging", path], timeout_s=timeout_s, max_output=64 << 20)
    if res.timed_out:
        raise ValueError("aapt2 dump badging timed out")
    text = res.text()
    if res.returncode != 0 and "package:" not in text:
        raise ValueError(f"aapt2 dump badging failed ({res.returncode}): {res.err_text().strip()[:300]}")
    return parse_badging(text)


def compare(androguard: ManifestView, aapt2: ManifestView) -> tuple[list[str], list[str]]:
    """Return (differences, notes). versionName is compared only when both values are literal."""
    diffs: list[str] = []
    notes: list[str] = []
    for fld in ("package", "version_code", "split", "min_sdk", "target_sdk"):
        a, b = getattr(androguard, fld), getattr(aapt2, fld)
        if a != b:
            diffs.append(f"{fld}: androguard={a!r} aapt2={b!r}")
    an, bn = androguard.version_name, aapt2.version_name
    if an is not None and _UNRESOLVED_REF.match(an):
        notes.append("versionName is a resource reference androguard did not resolve; not compared")
    elif an != bn:
        diffs.append(f"version_name: androguard={an!r} aapt2={bn!r}")
    return diffs, notes


def manifest_facts(androguard: ManifestView | None, aapt2: ManifestView | None, errors: list[str]) -> ManifestFacts:
    if androguard is None or aapt2 is None:
        return ManifestFacts(
            unreadable=True,
            unreadable_detail="; ".join(errors) or "a manifest parser failed",
            androguard=androguard,
            aapt2=aapt2,
        )
    diffs, notes = compare(androguard, aapt2)
    return ManifestFacts(
        unreadable=False,
        parsers_disagree=bool(diffs),
        differences=diffs,
        notes=notes,
        androguard=androguard,
        aapt2=aapt2,
        package=aapt2.package,
        version_code=aapt2.version_code,
        version_name=aapt2.version_name,
        split=aapt2.split,
        min_sdk=aapt2.min_sdk,
        target_sdk=aapt2.target_sdk,
    )
