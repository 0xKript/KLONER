"""Impersonation sweep (§11): discovery queries and heuristic lookalike signals.

Deterministic presentation evidence (EXACT_ICON, EXACT_LABEL) lives in ``decide.brand_check``.
Everything here is heuristic: LOOKALIKE:<signal> labels with scores, listed under
"Lookalikes (heuristic)", never verdicts (INV-4).
"""

from __future__ import annotations

import json
import unicodedata
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Any

from kloner.impersonation.labels import normalize_label
from kloner.models import Anchor, Evaluation, EvaluationFacts


@lru_cache(maxsize=1)
def _confusables() -> dict[str, str]:
    try:
        ref = resources.files("kloner").joinpath("data/confusables.json")
        text = ref.read_text(encoding="utf-8") if ref.is_file() else None
    except (FileNotFoundError, ModuleNotFoundError):
        text = None
    if text is None:
        text = (Path(__file__).resolve().parents[3] / "data" / "confusables.json").read_text(encoding="utf-8")
    data: dict[str, Any] = json.loads(text)
    return {chr(int(k, 16)): v for k, v in data.get("map", {}).items()}


def skeleton(text: str) -> str:
    """UTS #39 skeleton: NFD, map confusables to prototypes, NFD again."""
    table = _confusables()
    s = unicodedata.normalize("NFD", text)
    s = "".join(table.get(ch, ch) for ch in s)
    return unicodedata.normalize("NFD", s)


def edit_distance(a: str, b: str, cap: int = 8) -> int:
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb))
        prev = cur
    return prev[-1]


def hamming(a: str, b: str) -> int:
    return bin(int(a, 16) ^ int(b, 16)).count("1")


def queries(anchor: Anchor) -> list[str]:
    qs = set(anchor.brand.brand_labels) | set(anchor.brand.keywords) | set(anchor.brand.labels)
    return sorted(q for q in qs if q and q.strip())


def lookalikes(
    ev: Evaluation,
    facts: EvaluationFacts | None,
    anchor: Anchor,
    *,
    label_max_edit: int,
    dhash_max: int,
) -> list[dict[str, Any]]:
    """Heuristic signals that a candidate imitates the brand of ``anchor`` (never verdicts)."""
    if ev.package is None or ev.package == anchor.package:
        return []
    out: list[dict[str, Any]] = []
    official = {normalize_label(x) for x in anchor.brand.labels + anchor.brand.brand_labels if x}
    cand_labels = sorted({normalize_label(x) for x in (facts.brand.labels if facts and facts.brand else []) if x})
    for cl in cand_labels:
        for ol in sorted(official):
            if cl == ol:
                continue
            d = edit_distance(cl, ol)
            if d <= label_max_edit:
                out.append({"signal": "LABEL_EDIT", "candidate": cl, "official": ol, "score": d})
            elif skeleton(cl) == skeleton(ol):
                out.append({"signal": "CONFUSABLE", "candidate": cl, "official": ol, "score": 0})
    for ch in sorted(facts.brand.icon_dhashes if facts and facts.brand else []):
        for oh in sorted(anchor.brand.icon_dhash):
            d = hamming(ch, oh)
            if d <= dhash_max:
                out.append({"signal": "ICON_DHASH", "candidate": ch, "official": oh, "score": d})
    p, o = ev.package, anchor.package
    pd = edit_distance(p, o)
    if pd <= 2:
        out.append({"signal": "PACKAGE_TYPOSQUAT", "candidate": p, "official": o, "score": pd})
    elif p.startswith(o + ".") or p.endswith("." + o) or o in p:
        out.append({"signal": "PACKAGE_AFFIX", "candidate": p, "official": o, "score": 0})
    return out
