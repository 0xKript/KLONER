"""Run orchestration: hunt, verify, fetch, survey, reverify, explain (§13).

Every source is isolated (a failure in one never affects another) and every status reaches the
report (INV-10). Verdicts come only from ``decide()``; forensics, lookalikes and intel only add
labels and findings.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from kloner import __version__
from kloner.acquire.base import DisabledSource, Source, SourceError, sighting_from
from kloner.acquire.sources import build_source, download_offer
from kloner.app import Runtime
from kloner.forensics.metadata import cross_check
from kloner.forensics.runner import Forensics, select_reference
from kloner.impersonation.sweep import lookalikes, queries
from kloner.intel.census import correlate
from kloner.intel.db import verdict_json
from kloner.models import (
    HOSTILE,
    REVIEW,
    Anchor,
    Evaluation,
    Offer,
    Sighting,
    SourceStatus,
    Verdict,
)
from kloner.util.fingerprints import short_fp
from kloner.util.timeutil import now_iso
from kloner.util.timeutil import run_id as make_run_id
from kloner.verify.facts import SampleResult

DEFAULT_FAIL_ON = frozenset({"TAMPERED", "FORGED", "IMPERSONATOR"})


class UsageError(Exception):
    """Exit code 2."""


@dataclass
class SampleEntry:
    result: SampleResult
    expected: str | None
    sightings: list[Sighting] = field(default_factory=list)
    forensic_labels: list[str] = field(default_factory=list)
    intel_labels: list[str] = field(default_factory=list)
    finding: dict[str, Any] | None = None
    lookalikes: list[dict[str, Any]] = field(default_factory=list)
    seen_before: bool = False
    candidate: bool = False

    @property
    def evaluation(self) -> Evaluation:
        return self.result.evaluation


@dataclass
class RunReport:
    run_id: str
    command: str
    package: str | None
    started_utc: str
    finished_utc: str = ""
    anchor: Anchor | None = None
    sources: list[SourceStatus] = field(default_factory=list)
    samples: list[SampleEntry] = field(default_factory=list)
    intel: list[dict[str, Any]] = field(default_factory=list)
    exit_code: int = 0
    coverage: str = ""
    report_dir: Path | None = None
    new_only: bool = False
    fail_on: frozenset[str] = DEFAULT_FAIL_ON
    apksig_version: str | None = None
    config_sha256: str = ""
    notes: list[str] = field(default_factory=list)

    def all_entries(self) -> list[SampleEntry]:
        out: list[SampleEntry] = []
        for e in self.samples:
            out.append(e)
            for m in e.result.members:
                out.append(SampleEntry(result=m, expected=e.expected, sightings=[], seen_before=e.seen_before))
        return out

    def reported(self) -> list[SampleEntry]:
        return [e for e in self.samples if not (self.new_only and e.seen_before)]


# --------------------------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------------------------


def _isolated_discover(
    src: Source | DisabledSource, package: str, all_versions: bool, limit: int
) -> tuple[list[Offer], SourceStatus]:
    st = SourceStatus(source=src.name, status="OK")
    if isinstance(src, DisabledSource):
        st.status, st.reason = "DISABLED", src.reason
        return [], st
    try:
        offers = list(src.discover(package, all_versions=all_versions, limit=limit))
    except SourceError as e:
        st.status = e.status if e.status in ("BLOCKED", "ERROR", "NO_OFFERS", "DISABLED") else "ERROR"  # type: ignore[assignment]
        st.reason = e.reason
        return [], st
    except Exception as e:
        st.status, st.reason = "ERROR", f"{type(e).__name__}: {e}"
        return [], st
    st.offers = len(offers)
    if not offers:
        st.status = "NO_OFFERS"
    st.stores = sorted({o.store for o in offers if o.store})
    return offers, st


def _fetch_all(
    rt: Runtime, pairs: Sequence[tuple[Source, Offer]], statuses: dict[str, SourceStatus]
) -> list[tuple[Offer, Sighting]]:
    out: list[tuple[Offer, Sighting]] = []

    def one(pair: tuple[Source, Offer]) -> tuple[Offer, Any]:
        src, offer = pair
        try:
            return offer, src.fetch(offer, rt.quarantine)
        except SourceError as e:
            return offer, e
        except Exception as e:
            return offer, SourceError("ERROR", f"{type(e).__name__}: {e}")

    with ThreadPoolExecutor(max_workers=rt.config.network.concurrency) as pool:
        for offer, res in pool.map(one, pairs):
            st = statuses[offer.source]
            if isinstance(res, SourceError) or res.status != "OK" or res.sample_sha256 is None:
                st.failed += 1
                reason, status = res.reason, res.status
                if status == "BLOCKED":
                    st.status, st.reason = "BLOCKED", reason
                elif st.fetched == 0 and st.status == "OK":
                    st.reason = reason
                continue
            st.fetched += 1
            labels = ["INSECURE_TRANSPORT"] if (offer.download_url or "").lower().startswith("http://") else []
            sighting = sighting_from(offer, res, labels)
            rt.quarantine.write_evidence(res.sample_sha256, sighting.model_dump(mode="json"))
            out.append((offer, sighting))
    for st in statuses.values():
        if st.status == "OK" and st.offers and st.fetched == 0:
            st.status = "ERROR"
            st.reason = st.reason or "every download failed"
    return out


def _evaluate(
    rt: Runtime, items: Sequence[tuple[str, str | None]], anchors: dict[str, Anchor]
) -> dict[str, SampleResult]:
    pipe = rt.pipeline()
    kk = rt.known_keys

    def one(item: tuple[str, str | None]) -> tuple[str, SampleResult]:
        sha, expected = item
        return sha, pipe.evaluate(sha, expected, anchors, kk)

    with ThreadPoolExecutor(max_workers=rt.worker_count()) as pool:
        return dict(pool.map(one, items))


def coverage_statement(statuses: Sequence[SourceStatus], unique: int, sightings: int) -> str:
    worked = [s for s in statuses if s.status in ("OK", "NO_OFFERS")]
    parts = []
    for s in statuses:
        if s.status == "OK":
            extra = f" ({len(s.stores)} store{'s' if len(s.stores) != 1 else ''})" if len(s.stores) > 1 else ""
            parts.append(f"{s.source} OK{extra}")
        elif s.status == "NO_OFFERS":
            parts.append(f"{s.source} OK (no offers)")
        elif s.status == "DISABLED":
            parts.append(f"{s.source} disabled")
        elif s.status == "SKIPPED":
            parts.append(f"{s.source} skipped")
        else:
            parts.append(f"{s.source} {s.status}")
    return (
        f"Evaluated {unique} unique file{'s' if unique != 1 else ''} "
        f"({sightings} sighting{'s' if sightings != 1 else ''}) "
        f"from {len(worked)} of {len(statuses)} source{'s' if len(statuses) != 1 else ''} — {', '.join(parts)}."
    )


def exit_code_for(entries: Iterable[SampleEntry], fail_on: frozenset[str]) -> int:
    verdicts = {e.evaluation.verdict for e in entries}
    for e in entries:
        verdicts |= {m.evaluation.verdict for m in [SampleEntry(r, None) for r in e.result.members]}
    if any(v.value in fail_on for v in verdicts):
        return 10
    if verdicts & REVIEW:
        return 11
    return 0


# --------------------------------------------------------------------------------------------
# finishing: forensics, intel, persistence
# --------------------------------------------------------------------------------------------


def _forensics(rt: Runtime, rep: RunReport, anchors: dict[str, Anchor], acquire: Any = None) -> None:
    fx = Forensics(rt)
    genuine = [e.evaluation for e in rep.all_entries() if e.evaluation.verdict == Verdict.GENUINE]
    for row in rt.db.conn.execute("SELECT verdict_json FROM evaluations WHERE verdict='GENUINE'"):
        try:
            genuine.append(Evaluation.model_validate_json(row["verdict_json"]))
        except ValueError:
            continue
    for e in rep.all_entries():
        ev = e.evaluation
        if ev.format != "apk":
            continue
        own = rep.package is None or ev.package == rep.package
        if not (
            (own and ev.verdict in (Verdict.FORGED, Verdict.TAMPERED, Verdict.ANOMALY))
            or ev.verdict == Verdict.IMPERSONATOR
        ):
            continue
        anchor = anchors.get(ev.brand_package or ev.package or "")
        ref = select_reference(ev, genuine, anchor, rt.quarantine.has, acquire if own else None)
        finding = fx.analyze(ev, e.result.facts, ref)
        e.finding = finding
        e.forensic_labels = sorted(set(finding["labels"]))
        if anchor is not None:
            e.lookalikes = lookalikes(
                ev,
                e.result.facts,
                anchor,
                label_max_edit=rt.config.forensics.label_max_edit_distance,
                dhash_max=rt.config.forensics.dhash_max_distance,
            )


def _persist(rt: Runtime, rep: RunReport) -> None:
    db = rt.db
    for e in rep.samples:
        e.seen_before = db.seen_before(e.evaluation.sample_sha256, rep.run_id)
    for e in rep.all_entries():
        ev = e.evaluation
        db.put_sample(ev, e.result.parent_sha256)
        db.put_evaluation(ev, e.result.facts)
        db.put_run_sample(rep.run_id, ev, e.expected, e.result.parent_sha256)
        for s in e.sightings:
            db.put_sighting(rep.run_id, s, ",".join(s.labels) or "OK")
        if e.finding:
            db.put_finding(ev.sample_sha256, "forensics", e.finding)
            p = e.finding.get("payload")
            if p:
                db.put_payload(p["payload_id"], p["shape_id"], ev.sample_sha256, ev.package)
    for st in rep.sources:
        db.put_source_status(rep.run_id, st)
    db.commit()
    for e in rep.all_entries():
        labels, lines = correlate(db, e.evaluation, e.finding)
        e.intel_labels = labels
        rep.intel.extend({"sample_sha256": e.evaluation.sample_sha256, **ln} for ln in lines)


def finish(rt: Runtime, rep: RunReport, anchors: dict[str, Anchor], acquire: Any = None) -> RunReport:
    _forensics(rt, rep, anchors, acquire)
    _persist(rt, rep)
    unique = len({e.evaluation.sample_sha256 for e in rep.samples})
    sightings = sum(len(e.sightings) for e in rep.samples)
    rep.coverage = coverage_statement(rep.sources, unique, sightings)
    rep.exit_code = exit_code_for(rep.reported(), rep.fail_on)
    rep.finished_utc = now_iso()
    rt.db.finish_run(rep.run_id, rep.exit_code, rep.finished_utc)
    return rep


def _start(rt: Runtime, command: str, package: str | None, anchors: dict[str, Anchor]) -> RunReport:
    rid = make_run_id()
    tc = rt.toolchain()
    anchor = anchors.get(package) if package else None
    rep = RunReport(
        run_id=rid,
        command=command,
        package=package,
        started_utc=now_iso(),
        anchor=anchor,
        apksig_version=tc.apksig_version,
        config_sha256=rt.config.sha256(),
    )
    rt.db.start_run(
        rid,
        package,
        __version__,
        tc.apksig_version,
        anchor.record_sha256 if anchor else None,
        rep.config_sha256,
        rep.started_utc,
    )
    rt.db.put_run_anchors(rid, anchors.values())
    return rep


# --------------------------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------------------------


def run_hunt(
    rt: Runtime,
    package: str,
    *,
    sources: list[str] | None = None,
    all_versions: bool = False,
    max_per_source: int = 10,
    impersonators: bool = False,
    new_only: bool = False,
    require_corroborated: bool = False,
    fail_on: frozenset[str] = DEFAULT_FAIL_ON,
    local_paths: list[Path] | None = None,
    urls: list[str] | None = None,
) -> RunReport:
    anchors = rt.anchors.snapshot()
    anchor = anchors.get(package)
    if anchor is None:
        raise UsageError(
            f"no anchor for {package}. Pin the official identity first: "
            f"kloner anchor add {package} --from-url <official-apk-url> --vendor-domain <domain>"
        )
    if require_corroborated and anchor.corroboration != "CORROBORATED":
        raise UsageError(
            f"anchor {package} is {anchor.corroboration}; --require-corroborated refuses to run. "
            f"Add a second official method: kloner anchor add {package} --from-assetlinks <domain>"
        )
    rt.fast_doctor()
    rep = _start(rt, "hunt", package, anchors)
    rep.new_only, rep.fail_on = new_only, fail_on
    names = sources or rt.config.sources.enabled
    built = {n: build_source(rt, n, local_paths=local_paths, urls=urls) for n in names}
    statuses: dict[str, SourceStatus] = {}
    pairs: list[tuple[Source, Offer]] = []
    discovered: dict[str, list[Offer]] = {}
    for n, src in built.items():
        if n == "local" and not local_paths:
            statuses[n] = SourceStatus(source=n, status="SKIPPED", reason="no local paths given (--local)")
            continue
        if n == "url" and not urls:
            statuses[n] = SourceStatus(source=n, status="SKIPPED", reason="no URLs given (--url)")
            continue
        # Explicit inputs (local paths, URLs) are never capped; network sources are (--max-per-source).
        cap = 10**9 if n in ("local", "url") else max_per_source
        offers, st = _isolated_discover(src, package, all_versions, cap)
        statuses[n] = st
        discovered[n] = offers
        seen: set[str] = set()
        for o in offers[:cap]:
            key = o.download_url or o.handle or o.local_path or ""
            if key in seen:
                continue
            seen.add(key)
            pairs.append((src, o))
    fetched = _fetch_all(rt, pairs, statuses)

    # Re-fetch once over a fresh connection when a network sample looks corrupt or tampered (§8.3).
    by_sample: dict[str, list[tuple[Offer, Sighting]]] = {}
    for o, s in fetched:
        by_sample.setdefault(s.sample_sha256, []).append((o, s))
    results = _evaluate(rt, [(sha, package) for sha in by_sample], anchors)
    extra: list[tuple[Offer, Sighting]] = []
    for sha, sr in list(results.items()):
        ev = sr.evaluation
        corrupt = ev.verdict == Verdict.INVALID and any(r.startswith("R-G2-CORRUPT") for r in ev.reasons)
        if not (corrupt or ev.verdict == Verdict.TAMPERED):
            continue
        offer, sighting = by_sample[sha][0]
        if offer.source == "local" or not offer.download_url:
            continue
        fresh = rt.fresh_http()  # a new connection, as section 8.3 requires
        try:
            res = download_offer(
                fresh,
                offer.download_url,
                rt.quarantine,
                rt.config.limits.max_file_bytes,
                allow_http=offer.source == "url",
            )
        finally:
            fresh.close()
        if res.status == "OK" and res.sample_sha256 and res.sample_sha256 != sha:
            sighting.labels = sorted(set(sighting.labels) | {"UNSTABLE_SOURCE"})
            s2 = sighting_from(offer, res, ["UNSTABLE_SOURCE"])
            extra.append((offer, s2))
    for o, s in extra:
        by_sample.setdefault(s.sample_sha256, []).append((o, s))
    new = [(sha, package) for sha in by_sample if sha not in results]
    results.update(_evaluate(rt, new, anchors))

    for sha, pairs_ in by_sample.items():
        sr = results[sha]
        entry = SampleEntry(result=sr, expected=package)
        for offer, s in pairs_:
            mism = cross_check(offer.claimed, sr.evaluation, sr.facts, rt.quarantine.path_for(sha))
            if mism:
                s.labels = sorted(set(s.labels) | {"METADATA_MISMATCH"})
                s.claimed = s.claimed.model_copy()
                rep.notes.append(f"{offer.source}: METADATA_MISMATCH for {short_fp(sha)}: {'; '.join(mism)}")
            entry.sightings.append(s)
        rep.samples.append(entry)

    if impersonators:
        _impersonation_sweep(rt, rep, anchor, built, statuses, anchors, max_per_source)
    rep.sources = [statuses[n] for n in names if n in statuses]

    acquired: dict[int, Evaluation | None] = {}

    def acquire(vc: int) -> Evaluation | None:
        if vc in acquired:
            return acquired[vc]
        acquired[vc] = None
        for n, offers in discovered.items():
            src = built[n]
            for o in offers:
                if o.claimed.version_code == vc and not isinstance(src, DisabledSource):
                    res = src.fetch(o, rt.quarantine)
                    if res.status == "OK" and res.sample_sha256:
                        sr = rt.pipeline().evaluate(res.sample_sha256, package, anchors, rt.known_keys)
                        if sr.evaluation.verdict == Verdict.GENUINE:
                            acquired[vc] = sr.evaluation
                            return sr.evaluation
        return None

    return finish(rt, rep, anchors, acquire)


def _impersonation_sweep(
    rt: Runtime,
    rep: RunReport,
    anchor: Anchor,
    built: dict[str, Source | DisabledSource],
    statuses: dict[str, SourceStatus],
    anchors: dict[str, Anchor],
    limit: int,
) -> None:
    qs = queries(anchor)
    if not qs:
        rep.notes.append("impersonation sweep: the anchor has no labels or brand keywords to search for")
        return
    pairs: list[tuple[Source, Offer]] = []
    seen: set[tuple[str, str | None]] = set()
    for n, src in built.items():
        if isinstance(src, DisabledSource) or not src.supports_search:
            continue
        for q in qs:
            try:
                hits = list(src.search(q, limit=limit))
            except SourceError as e:
                statuses[n].reason = f"search: {e.reason}"
                continue
            except Exception as e:
                statuses[n].reason = f"search: {type(e).__name__}: {e}"
                continue
            for o in hits:
                if not o.package or o.package == anchor.package:
                    continue
                key = (o.package, o.claimed.version_name)
                if key in seen:
                    continue
                seen.add(key)
                pairs.append((src, o))
    fetched = _fetch_all(rt, pairs, statuses)
    shas = sorted({s.sample_sha256 for _, s in fetched})
    known = {e.evaluation.sample_sha256 for e in rep.samples}
    results = _evaluate(rt, [(sha, anchor.package) for sha in shas if sha not in known], anchors)
    for sha, sr in results.items():
        entry = SampleEntry(result=sr, expected=anchor.package, candidate=True)
        entry.sightings = [s for _, s in fetched if s.sample_sha256 == sha]
        entry.lookalikes = lookalikes(
            sr.evaluation,
            sr.facts,
            anchor,
            label_max_edit=rt.config.forensics.label_max_edit_distance,
            dhash_max=rt.config.forensics.dhash_max_distance,
        )
        rep.samples.append(entry)  # every evaluated candidate is reported (INV-10), not only hits
    impostors = sum(1 for sr in results.values() if sr.evaluation.verdict == Verdict.IMPERSONATOR)
    looks = sum(1 for e in rep.samples if e.candidate and e.lookalikes)
    rep.notes.append(
        f"impersonation sweep: {len(qs)} quer{'y' if len(qs) == 1 else 'ies'} "
        f"({', '.join(repr(q) for q in qs[:5])}), {len(pairs)} candidate offer(s), "
        f"{len(results)} candidate file(s) evaluated, {impostors} IMPERSONATOR, {looks} with lookalike signals"
    )


def run_verify(rt: Runtime, paths: list[Path], package: str | None, command: str = "verify") -> RunReport:
    anchors = rt.anchors.snapshot()
    rt.fast_doctor()
    rep = _start(rt, command, package, anchors)
    st = SourceStatus(source="local", status="OK")
    items: list[tuple[str, Path]] = []
    from kloner.acquire.sources import LocalSource

    src = LocalSource(paths, rt.config.limits.max_file_bytes)
    offers = list(src.discover(package or "", all_versions=False, limit=10**9))
    st.offers = len(offers)
    sightings: dict[str, list[Sighting]] = {}
    for o in offers:
        res = src.fetch(o, rt.quarantine)
        if res.sample_sha256:
            st.fetched += 1
            sightings.setdefault(res.sample_sha256, []).append(sighting_from(o, res))
            items.append((res.sample_sha256, Path(o.local_path or "")))
    if not offers:
        st.status = "NO_OFFERS"
    results = _evaluate(rt, [(sha, package) for sha in sightings], anchors)
    for sha, sr in results.items():
        rep.samples.append(SampleEntry(result=sr, expected=package, sightings=sightings[sha]))
    rep.sources = [st]
    return finish(rt, rep, anchors)


def run_fetch(rt: Runtime, urls: list[str], package: str | None) -> RunReport:
    anchors = rt.anchors.snapshot()
    rt.fast_doctor()
    rep = _start(rt, "fetch", package, anchors)
    src = build_source(rt, "url", urls=urls)
    assert not isinstance(src, DisabledSource)
    offers, st = _isolated_discover(src, package or "", False, len(urls))
    statuses = {"url": st}
    fetched = _fetch_all(rt, [(src, o) for o in offers], statuses)
    by: dict[str, list[Sighting]] = {}
    for _, s in fetched:
        by.setdefault(s.sample_sha256, []).append(s)
    results = _evaluate(rt, [(sha, package) for sha in by], anchors)
    for sha, sr in results.items():
        rep.samples.append(SampleEntry(result=sr, expected=package, sightings=by[sha]))
    rep.sources = [statuses["url"]]
    return finish(rt, rep, anchors)


@dataclass
class SurveyRow:
    cert_sha256: str
    subject: str | None
    verified: bool
    known_key: str | None
    samples: set[str] = field(default_factory=set)
    versions: set[str] = field(default_factory=set)
    sources: set[str] = field(default_factory=set)


def run_survey(
    rt: Runtime, package: str, sources: list[str] | None, max_per_source: int
) -> tuple[list[SurveyRow], list[SourceStatus], int]:
    """Signer census of a package with no anchor. It never writes an anchor (INV-3)."""
    rt.fast_doctor()
    names = sources or rt.config.sources.enabled
    statuses: dict[str, SourceStatus] = {}
    pairs: list[tuple[Source, Offer]] = []
    for n in names:
        if n in ("local", "url"):
            continue
        src = build_source(rt, n)
        offers, st = _isolated_discover(src, package, True, max_per_source)
        statuses[n] = st
        pairs += [(src, o) for o in offers[:max_per_source]]
    fetched = _fetch_all(rt, pairs, statuses)
    pipe = rt.pipeline()
    rows: dict[str, SurveyRow] = {}
    shas = sorted({s.sample_sha256 for _, s in fetched})
    for sha in shas:
        facts, _ = pipe.facts(sha, package)
        rng = facts.verify.full_range if facts.verify else None
        verified = {s.cert_sha256 for s in (rng.signers if rng and rng.verified else []) if s.cert_sha256}
        nat = facts.native_inventory.app_signer_certs() if facts.native_inventory else {}
        certs = facts.native_inventory.certs if facts.native_inventory else {}
        version = f"{facts.manifest.version_name} ({facts.manifest.version_code})" if facts.manifest else "?"
        for cert in set(nat) | verified:
            row = rows.setdefault(
                cert, SurveyRow(cert, certs[cert].subject if cert in certs else None, False, rt.known_keys.get(cert))
            )
            row.verified = row.verified or cert in verified
            row.samples.add(sha)
            row.versions.add(version)
            row.sources |= {s.source + (f":{s.store}" if s.store else "") for _, s in fetched if s.sample_sha256 == sha}
    return (
        sorted(rows.values(), key=lambda r: (-len(r.samples), r.cert_sha256)),
        [statuses[n] for n in statuses],
        len(shas),
    )


def reverify(rt: Runtime, run_id: str) -> tuple[bool, list[str], int]:
    """Recompute every verdict of a run from the quarantine and compare canonical JSON byte for byte."""
    db = rt.db
    if db.run(run_id) is None:
        raise UsageError(f"unknown run {run_id}")
    snapshot = {p: Anchor.model_validate(r) for p, r in db.run_anchor_snapshot(run_id).items()}
    rows = db.run_samples(run_id)
    rt.fast_doctor()
    pipe = rt.pipeline()
    diffs: list[str] = []
    checked = 0
    tops = [r for r in rows if not r["parent_sha256"]]
    for r in tops:
        sha = str(r["sample_sha256"])
        if not rt.quarantine.has(sha):
            diffs.append(f"{sha}: sample missing from the quarantine")
            continue
        sr = pipe.evaluate(sha, r["expected_package"], snapshot, rt.known_keys)
        for res in [sr, *sr.members]:
            ev = res.evaluation
            stored = db.evaluation(ev.sample_sha256, ev.anchor_record_sha256 or "")
            checked += 1
            if stored is None:
                diffs.append(f"{ev.sample_sha256}: no stored verdict for anchor {ev.anchor_record_sha256}")
            elif stored["verdict_json"] != verdict_json(ev):
                diffs.append(
                    f"{ev.sample_sha256}: verdict JSON differs (stored {stored['verdict']}, now {ev.verdict.value})"
                )
    return not diffs, diffs, checked


def explain(rt: Runtime, sha: str, run_id: str | None = None) -> dict[str, Any]:
    db = rt.db
    anchor_sha = None
    if run_id:
        for r in db.run_samples(run_id):
            if r["sample_sha256"] == sha:
                break
        else:
            raise UsageError(f"sample {sha} is not part of run {run_id}")
    row = db.evaluation(sha, anchor_sha)
    if row is None:
        raise UsageError(f"no evaluation of {sha}; evaluate it first: kloner verify <file>")
    ev = json.loads(row["verdict_json"])
    facts = db.facts_json(sha, ev.get("anchor_record_sha256"))
    findings = db.conn.execute("SELECT data_json FROM findings WHERE sample_sha256=?", (sha,)).fetchall()
    return {
        "evaluation": ev,
        "facts": facts,
        "findings": [json.loads(f["data_json"]) for f in findings],
        "sightings": [dict(s) for s in db.sightings(sha)],
    }


def notify_webhook(url: str, summary: dict[str, Any], user_agent: str) -> str | None:
    try:
        r = httpx.post(url, json=summary, timeout=30, headers={"User-Agent": user_agent})
        if r.status_code >= 400:
            return f"webhook returned HTTP {r.status_code}"
    except httpx.HTTPError as e:
        return f"webhook failed: {e}"
    return None


def hostile(entries: Iterable[SampleEntry]) -> list[SampleEntry]:
    return [e for e in entries if e.evaluation.verdict in HOSTILE]
