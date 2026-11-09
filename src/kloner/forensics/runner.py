"""Forensics runner (§10): reference selection, diff, capabilities, payload IDs, overlap.

Runs for every non-GENUINE sample of the hunted package and for IMPERSONATOR candidates. It
explains; it never decides (INV-4). Extraction runs in the bounded worker; failure yields
FORENSICS_INCOMPLETE and leaves the verdict untouched.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from kloner.forensics.capabilities import capabilities
from kloner.forensics.diff import diff_views
from kloner.forensics.overlap import overlap
from kloner.forensics.payload import payload_ids
from kloner.forensics.unsigned import inventory
from kloner.models import Anchor, Evaluation, EvaluationFacts, Verdict
from kloner.util import proc
from kloner.verify.worker import limits_to_dict

if TYPE_CHECKING:
    from kloner.app import Runtime


@dataclass(frozen=True)
class Reference:
    sha256: str
    kind: str  # same-version-same-variant | same-version | acquired-same-version | nearest-version | anchor-source
    version_code: int | None


def select_reference(
    ev: Evaluation,
    genuine: Sequence[Evaluation],
    anchor: Anchor | None,
    have_sample: Callable[[str], bool],
    acquire: Callable[[int], Evaluation | None] | None = None,
) -> Reference | None:
    """The §10.1 preference order. ``genuine`` holds GENUINE evaluations of the same brand package."""
    pkg = ev.package if ev.verdict != Verdict.IMPERSONATOR else (ev.brand_package or ev.package)
    # Only APKs can be diff references: a GENUINE bundle is a container, not code.
    pool = [
        g
        for g in genuine
        if g.package == pkg
        and g.verdict == Verdict.GENUINE
        and g.format == "apk"
        and g.sample_sha256 != ev.sample_sha256
    ]
    vc = ev.version_code
    if vc is not None:
        exact = sorted((g for g in pool if g.version_code == vc and g.split == ev.split), key=lambda g: g.sample_sha256)
        if exact:
            return Reference(exact[0].sample_sha256, "same-version-same-variant", vc)
        same = sorted((g for g in pool if g.version_code == vc), key=lambda g: g.sample_sha256)
        if same:
            return Reference(same[0].sample_sha256, "same-version", vc)
        if acquire is not None:
            got = acquire(vc)
            if got is not None and got.verdict == Verdict.GENUINE:
                return Reference(got.sample_sha256, "acquired-same-version", vc)
        versioned = [g for g in pool if g.version_code is not None]
        if versioned:
            near = min(versioned, key=lambda g: (abs((g.version_code or 0) - vc), g.sample_sha256))
            return Reference(near.sample_sha256, "nearest-version", near.version_code)
    elif pool:
        first = sorted(pool, key=lambda g: g.sample_sha256)[0]
        return Reference(first.sample_sha256, "nearest-version", first.version_code)
    if anchor is not None:
        for r in sorted(anchor.release_refs, key=lambda r: -r.version_code):
            if have_sample(r.file_sha256):
                return Reference(r.file_sha256, "anchor-source", r.version_code)
    return None


class ForensicsError(Exception):
    pass


class Forensics:
    def __init__(self, rt: Runtime) -> None:
        self.rt = rt
        self._views: dict[str, dict[str, Any]] = {}

    def view(self, sha: str) -> dict[str, Any]:
        if sha in self._views:
            return self._views[sha]
        cfg = self.rt.config
        req = {
            "op": "forensics",
            "path": str(self.rt.quarantine.path_for(sha)),
            "sha256": sha,
            "limits": limits_to_dict(cfg.parse_limits()),
        }
        timeout = cfg.forensics.timeout_s
        res = proc.run(
            [sys.executable, "-I", "-m", "kloner.verify.worker"],
            timeout_s=timeout,
            input_bytes=json.dumps(req).encode("utf-8"),
            env=proc.minimal_env(),
            address_space=cfg.limits.worker_memory_bytes,
            cpu_seconds=int(timeout) + 5,
        )
        if res.timed_out:
            raise ForensicsError(f"forensics timed out after {timeout:.0f}s")
        try:
            data = json.loads(res.stdout or b"{}")
        except json.JSONDecodeError as e:
            raise ForensicsError(f"forensics worker output unreadable: {e}") from e
        if not data.get("ok"):
            raise ForensicsError(str(data.get("error") or f"forensics worker exited {res.returncode}"))
        view: dict[str, Any] = data["view"]
        self._views[sha] = view
        return view

    def analyze(self, ev: Evaluation, facts: EvaluationFacts | None, ref: Reference | None) -> dict[str, Any]:
        cfg = self.rt.config.forensics
        finding: dict[str, Any] = {
            "sample_sha256": ev.sample_sha256,
            "verdict": ev.verdict.value,
            "reference": None,
            "labels": [],
            "signers": [s.model_dump(mode="json") for s in ev.signers if s.trust == "none"],
            "unsigned": inventory(facts.native_inventory if facts else None),
            "error": None,
        }
        if ref is None:
            finding["labels"].append("NO_REFERENCE")
            return finding
        finding["reference"] = {"sha256": ref.sha256, "kind": ref.kind, "version_code": ref.version_code}
        if ref.kind == "nearest-version" and ref.version_code != ev.version_code:
            finding["labels"].append("CROSS_VERSION_DIFF")
        try:
            sv = self.view(ev.sample_sha256)
            rv = self.view(ref.sha256)
        except ForensicsError as e:
            finding["labels"].append("FORENSICS_INCOMPLETE")
            finding["error"] = str(e)
            return finding
        d = diff_views(sv, rv)
        caps = capabilities(d)
        ov = overlap(sv, rv, cfg.repackaged_min_jaccard, cfg.impostor_max_jaccard)
        added = {c: sv["classes"][c] for c in d["code"]["classes_added"]}
        ids = payload_ids(added)
        if ov["label"]:
            finding["labels"].append(ov["label"])
        finding.update(
            {
                "diff": _trim(d),
                "capabilities": caps,
                "overlap": ov,
                "payload": {"payload_id": ids[0], "shape_id": ids[1], "classes": len(added)} if ids else None,
            }
        )
        return finding


def _trim(d: dict[str, Any], cap: int = 200) -> dict[str, Any]:
    """Keep reports readable: long lists are truncated, with their full length recorded."""

    def walk(o: Any) -> Any:
        if isinstance(o, dict):
            return {k: walk(v) for k, v in o.items()}
        if isinstance(o, list):
            if len(o) > cap:
                return [walk(x) for x in o[:cap]] + [f"… {len(o) - cap} more"]
            return [walk(x) for x in o]
        return o

    out: dict[str, Any] = walk(d)
    return out
