"""Forensic diff of a sample against a GENUINE reference (§10.2). Explains; never decides."""

from __future__ import annotations

from typing import Any


def _set_delta(a: list[str] | set[str], b: list[str] | set[str]) -> dict[str, list[str]]:
    sa, sb = set(a), set(b)
    return {"added": sorted(sa - sb), "removed": sorted(sb - sa)}


def _components(view: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {f"{c['type']}:{c['name']}": c for c in view["manifest"]["components"]}


def _packages(classes: list[str]) -> set[str]:
    out = set()
    for c in classes:
        name = c[1:-1] if c.startswith("L") and c.endswith(";") else c
        if "/" in name:
            out.add(name.rsplit("/", 1)[0].replace("/", "."))
    return out


def diff_views(sample: dict[str, Any], ref: dict[str, Any]) -> dict[str, Any]:
    sm, rm = sample["manifest"], ref["manifest"]
    scomp, rcomp = _components(sample), _components(ref)
    added_components = [scomp[k] for k in sorted(set(scomp) - set(rcomp))]
    removed_components = [rcomp[k] for k in sorted(set(rcomp) - set(scomp))]
    changed_components = [
        {"key": k, "before": rcomp[k], "after": scomp[k]}
        for k in sorted(set(scomp) & set(rcomp))
        if (scomp[k]["exported"], scomp[k]["actions"], scomp[k]["permission"])
        != (rcomp[k]["exported"], rcomp[k]["actions"], rcomp[k]["permission"])
    ]
    app_changes = {
        k: {"before": rm["application"].get(k), "after": sm["application"].get(k)}
        for k in sorted(set(sm["application"]) | set(rm["application"]))
        if sm["application"].get(k) != rm["application"].get(k)
    }
    if sm.get("shared_user_id") != rm.get("shared_user_id"):
        app_changes["sharedUserId"] = {"before": rm.get("shared_user_id"), "after": sm.get("shared_user_id")}
    sc, rc = sample["classes"], ref["classes"]
    added_classes = sorted(set(sc) - set(rc))
    removed_classes = sorted(set(rc) - set(sc))
    modified = sorted(c for c in set(sc) & set(rc) if sc[c] != rc[c])
    si, ri = sample["strings_indicators"], ref["strings_indicators"]
    new_indicators = {k: sorted(set(si[k]) - set(ri.get(k, []))) for k in si}
    risky = {
        k: {"before": ref["risky_apis"].get(k, 0), "after": v}
        for k, v in sample["risky_apis"].items()
        if v > ref["risky_apis"].get(k, 0)
    }
    snat = {n["name"]: n["sha256"] for n in sample["native"]}
    rnat = {n["name"]: n["sha256"] for n in ref["native"]}
    sabi = {n["abi"] for n in sample["native"] if n["abi"]}
    rabi = {n["abi"] for n in ref["native"] if n["abi"]}
    native = {
        "added": sorted(set(snat) - set(rnat)),
        "removed": sorted(set(rnat) - set(snat)),
        "changed": sorted(n for n in set(snat) & set(rnat) if snat[n] != rnat[n]),
        "abis": _set_delta(sabi, rabi),
    }
    sfiles = {f["name"]: f for f in sample["files"]}
    rfiles = {f["name"]: f for f in ref["files"]}
    added_files = [sfiles[n] for n in sorted(set(sfiles) - set(rfiles))]
    payload_ext = (".apk", ".dex", ".jar", ".zip", ".so")
    embedded = [
        f
        for f in added_files
        if f.get("type") in ("zip", "dex", "so")
        or f["name"].lower().endswith(payload_ext)
        or (f.get("entropy") or 0) >= 7.5
    ]
    launcher = None
    if sm.get("launcher") != rm.get("launcher"):
        launcher = {"before": rm.get("launcher"), "after": sm.get("launcher")}
    return {
        "manifest": {
            "permissions": _set_delta(sm["permissions"], rm["permissions"]),
            "components_added": added_components,
            "components_removed": removed_components,
            "components_changed": changed_components,
            "application": app_changes,
            "launcher": launcher,
            "queries": _set_delta(sm["queries"], rm["queries"]),
            "features": _set_delta(sm["features"], rm["features"]),
        },
        "code": {
            "classes_added": added_classes,
            "classes_removed": removed_classes,
            "classes_modified": modified,
            "packages_added": sorted(_packages(added_classes) - _packages(list(rc))),
            "packages_removed": sorted(_packages(removed_classes) - _packages(list(sc))),
            "new_indicators": new_indicators,
            "risky_api_deltas": risky,
        },
        "native": native,
        "files": {
            "added": [f["name"] for f in added_files],
            "removed": sorted(set(rfiles) - set(sfiles)),
            "embedded_payloads": embedded,
        },
    }
