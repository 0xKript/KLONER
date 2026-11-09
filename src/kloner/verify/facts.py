"""Facts assembly: bounded worker (G0-G4, G6 native/androguard) + apksig bridge (G5), then decide().

Every sample is evaluated from its quarantined copy. Bundles are split into members, each member is
evaluated on its own, and the container verdict follows §6.5.
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from kloner.acquire.quarantine import Quarantine
from kloner.config import KlonerConfig
from kloner.decide import MAX_SDK, UNKNOWN_ATTRIBUTE_ISSUES, MemberResult, OtherMember, decide, decide_bundle
from kloner.models import Anchor, Evaluation, EvaluationFacts, NativeInventory, VerifyFacts, VerifyRange
from kloner.toolchain import Toolchain
from kloner.util import proc
from kloner.verify.bridge import BridgeFailure, BridgePool
from kloner.verify.worker import limits_to_dict

MODERN_FLOOR = 24


@dataclass
class SampleResult:
    evaluation: Evaluation
    facts: EvaluationFacts
    members: list[SampleResult] = field(default_factory=list)
    parent_sha256: str | None = None


def unknown_items(rng: VerifyRange, native: NativeInventory | None) -> list[str]:
    items: set[str] = set()
    issues = list(rng.warnings) + [w for s in rng.signers for w in s.warnings]
    for i in issues:
        if i.issue in UNKNOWN_ATTRIBUTE_ISSUES:
            items.add(f"{i.issue}({', '.join(p or '' for p in i.params)})")
    if native is not None and not native.error:
        for p in native.pairs:
            if p.kind != "signature":
                continue
            for s in p.signers:
                for a in s.unknown_attribute_ids:
                    items.add(f"{p.name} signer #{s.index} attribute 0x{a:08x}")
    return sorted(items)


class Pipeline:
    def __init__(
        self, home: Path, tc: Toolchain, config: KlonerConfig, quarantine: Quarantine, bridges: BridgePool
    ) -> None:
        self.home = home
        self.tc = tc
        self.config = config
        self.quarantine = quarantine
        self.bridges = bridges
        self.limits = config.parse_limits()

    # -- facts --------------------------------------------------------------------------------

    def worker_facts(self, sha: str, expected: str | None) -> tuple[EvaluationFacts, list[dict[str, Any]] | None]:
        path = self.quarantine.path_for(sha)
        req = {
            "op": "facts",
            "path": str(path),
            "sha256": sha,
            "expected_package": expected,
            "aapt2": self.tc.aapt2,
            "limits": limits_to_dict(self.limits),
            "home": str(self.home),
        }
        timeout = self.config.limits.worker_timeout_s
        res = proc.run(
            [sys.executable, "-I", "-m", "kloner.verify.worker"],
            timeout_s=timeout,
            input_bytes=json.dumps(req).encode("utf-8"),
            env=proc.minimal_env(),
            address_space=self.config.limits.worker_memory_bytes,
            cpu_seconds=int(timeout) + 5,
        )
        size = path.stat().st_size
        if res.timed_out:
            return EvaluationFacts(
                sample_sha256=sha,
                size=size,
                expected_package=expected,
                collection_error=f"facts worker timed out after {timeout:.0f}s",
            ), None
        try:
            data = json.loads(res.stdout or b"{}")
        except json.JSONDecodeError:
            data = {}
        if not data.get("ok"):
            err = data.get("error") or f"facts worker exited with {res.returncode}: {res.err_text()[-500:]}"
            return EvaluationFacts(sample_sha256=sha, size=size, expected_package=expected, collection_error=err), None
        return EvaluationFacts.model_validate(data["facts"]), data.get("members")

    def add_verification(self, facts: EvaluationFacts) -> None:
        m = facts.manifest
        if facts.intake.failed or facts.intake.format != "apk" or facts.archive is None or facts.archive.failed:
            return
        if m is None or m.unreadable or m.parsers_disagree:
            return
        path = self.quarantine.path_for(facts.sample_sha256)
        version = self.tc.apksig_version
        min_sdk = max(1, m.min_sdk or 1)
        try:
            full = self.bridges.verify(path, min_sdk, MAX_SDK)
            if full.fatal:
                facts.verify = VerifyFacts(engine_failure=True, engine_detail=full.fatal, apksig_version=version)
                return
            full_range = VerifyRange.from_bridge(full)
            modern_range = None
            if not full.verified and min_sdk < MODERN_FLOOR:
                mr = self.bridges.verify(path, MODERN_FLOOR, MAX_SDK)
                if mr.fatal:
                    facts.verify = VerifyFacts(engine_failure=True, engine_detail=mr.fatal, apksig_version=version)
                    return
                modern_range = VerifyRange.from_bridge(mr)
        except BridgeFailure as e:
            facts.verify = VerifyFacts(engine_failure=True, engine_detail=str(e), apksig_version=version)
            return
        effective = full_range if full_range.verified else (modern_range or full_range)
        facts.verify = VerifyFacts(
            apksig_version=version,
            full_range=full_range,
            modern_range=modern_range,
            unknown_signature_relevant_items=unknown_items(effective, facts.native_inventory),
        )

    def facts(self, sha: str, expected: str | None) -> tuple[EvaluationFacts, list[dict[str, Any]] | None]:
        facts, members = self.worker_facts(sha, expected)
        self.add_verification(facts)
        return facts, members

    # -- evaluation ---------------------------------------------------------------------------

    def evaluate(
        self,
        sha: str,
        expected: str | None,
        anchors: Mapping[str, Anchor],
        known_keys: Mapping[str, str],
    ) -> SampleResult:
        facts, members = self.facts(sha, expected)
        if facts.intake.format == "bundle" and members is not None and not (facts.archive and facts.archive.failed):
            return self._evaluate_bundle(facts, members, expected, anchors, known_keys)
        return SampleResult(decide(facts, anchors, known_keys), facts)

    def _evaluate_bundle(
        self,
        facts: EvaluationFacts,
        members: list[dict[str, Any]],
        expected: str | None,
        anchors: Mapping[str, Anchor],
        known_keys: Mapping[str, str],
    ) -> SampleResult:
        member_facts: list[tuple[dict[str, Any], EvaluationFacts, bool]] = []
        others: list[OtherMember] = []
        for m in members:
            role = m["role_hint"]
            if role == "apk":
                mf, _nested = self.facts(m["sha256"], None)
                if mf.intake.format == "apk":
                    member_facts.append((m, mf, True))
                else:
                    others.append(OtherMember(m["name"], m["sha256"], int(m["size"]), "payload", "zip"))
            elif role in ("payload", "obb"):
                others.append(OtherMember(m["name"], m["sha256"], int(m["size"]), role, m.get("type")))
        package = expected or choose_package(mf for _, mf, _ in member_facts)
        results: list[SampleResult] = []
        apk_results: list[MemberResult] = []
        for m, mf, _ in member_facts:
            mpkg = mf.manifest.package if mf.manifest and not mf.manifest.unreadable else None
            mf.expected_package = package if mpkg == package else None
            ev = decide(mf, anchors, known_keys)
            apk_results.append(MemberResult(m["name"], ev))
            results.append(SampleResult(ev, mf, parent_sha256=facts.sample_sha256))
        facts.expected_package = expected
        ev = decide_bundle(facts, package, apk_results, others, anchors)
        return SampleResult(ev, facts, members=results)


def choose_package(facts_iter: Any) -> str | None:
    """The package that owns the bundle: the most frequent package with a base (no split) member."""
    counts: Counter[str] = Counter()
    bases: set[str] = set()
    for mf in facts_iter:
        m = mf.manifest
        if m is None or m.unreadable or not m.package:
            continue
        counts[m.package] += 1
        if m.split is None:
            bases.add(m.package)
    candidates = sorted((p for p in counts if p in bases), key=lambda p: (-counts[p], p))
    return candidates[0] if candidates else None
