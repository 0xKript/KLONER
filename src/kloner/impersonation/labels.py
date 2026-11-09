"""Application labels: extraction (all locales) and deterministic normalization (§11).

EXACT_LABEL compares a candidate's label with a *declared* brand label after Unicode NFKC
normalization, case folding and whitespace collapsing.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Any

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
_WS = re.compile(r"\s+")
_REF = re.compile(r"^@([0-9A-Fa-f]{8})$")


def normalize_label(text: str) -> str:
    return _WS.sub(" ", unicodedata.normalize("NFKC", text).casefold()).strip()


def resource_id(ref: str | None) -> int | None:
    if not ref:
        return None
    m = _REF.match(ref.strip())
    return int(m.group(1), 16) if m else None


def extract_labels(apk: Any) -> tuple[str | None, list[str]]:
    """(default label, every label across all resource configurations)."""
    labels: set[str] = set()
    default: str | None = None
    try:
        default = apk.get_app_name() or None
    except Exception:
        default = None
    if default:
        labels.add(default)
    try:
        xml = apk.get_android_manifest_xml()
        app = xml.find("application") if xml is not None else None
        raw = app.get(ANDROID_NS + "label") if app is not None else None
        rid = resource_id(raw)
        if rid is not None:
            arsc = apk.get_android_resources()
            if arsc is not None:
                for _cfg, value in arsc.get_resolved_res_configs(rid):
                    if isinstance(value, str) and value:
                        labels.add(value)
        elif raw:
            labels.add(raw)
    # odd resource tables yield fewer labels, never a crash
    except Exception:  # noqa: S110  # nosec B110
        pass
    return default, sorted(labels)
