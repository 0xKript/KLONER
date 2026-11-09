"""Code and resource overlap (§10.5). Heuristic labels only, always shown with the raw numbers."""

from __future__ import annotations

from typing import Any


def jaccard(a: set[str], b: set[str]) -> float:
    if not a and not b:
        return 1.0
    return len(a & b) / len(a | b)


def _resources(view: dict[str, Any]) -> set[str]:
    return {f"{f['name']}:{f.get('crc32', '')}" for f in view["files"] if f["name"].startswith(("res/", "assets/"))}


def overlap(sample: dict[str, Any], ref: dict[str, Any], repackaged_min: float, impostor_max: float) -> dict[str, Any]:
    jc = jaccard(set(sample["classes"]), set(ref["classes"]))
    jr = jaccard(_resources(sample), _resources(ref))
    label = "REPACKAGED" if jc >= repackaged_min else ("IMPOSTOR" if jc < impostor_max else None)
    return {
        "j_class": round(jc, 4),
        "j_res": round(jr, 4),
        "label": label,
        "heuristic": True,
        "thresholds": {"repackaged_min": repackaged_min, "impostor_max": impostor_max},
    }
