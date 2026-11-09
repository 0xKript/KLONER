"""Anchor lifecycle (§7.7): refresh, export, import, adopt-rotation."""

from __future__ import annotations

import json
from pathlib import Path

from rich.console import Console

from kloner.anchor import corroborate, hygiene
from kloner.anchor.methods import (
    AnchorError,
    MethodResult,
    from_assetlinks,
    from_fdroid,
    from_fingerprints,
    from_url,
    merge,
)
from kloner.anchor.store import record_hash, seal
from kloner.app import Runtime
from kloner.models import Anchor, CertInfo, Evidence, Identity, LineageEntry, Verdict
from kloner.util.fingerprints import short_fp
from kloner.util.timeutil import now_iso


def _require(rt: Runtime, package: str) -> Anchor:
    a = rt.anchors.get(package)
    if a is None:
        raise AnchorError(f"no anchor for {package}. Create one: kloner anchor add {package} --from-url …", exit_code=2)
    return a


def refresh(rt: Runtime, package: str, *, accept: bool, console: Console) -> bool:
    """Re-run the automatic methods recorded as evidence; persist only with --accept."""
    current = _require(rt, package)
    candidate = current.model_copy(deep=True)
    done: set[tuple[str, str]] = set()
    results: list[MethodResult] = []
    for ident in current.identities:
        for ev in ident.evidence:
            key = (ev.method, ev.url or "")
            if key in done:
                continue
            done.add(key)
            try:
                if ev.method == "url" and ev.url:
                    domains = [p.split(" inside ", 1)[1] for p in [ev.detail or ""] if " inside " in p]
                    doms = [d.strip() for d in (domains[0].split(",") if domains else [])]
                    results.append(from_url(rt, package, ev.url, doms or [ev.url.split("/")[2]]))
                elif ev.method == "fingerprint" and ev.url:
                    fps = [
                        i.cert_sha256
                        for i in current.identities
                        if any(e.method == "fingerprint" and e.url == ev.url for e in i.evidence)
                    ]
                    results.append(from_fingerprints(rt, package, fps, ev.url))
                elif ev.method == "assetlinks" and ev.url:
                    results.append(from_assetlinks(rt, package, ev.url.split("/")[2]))
                elif ev.method == "fdroid":
                    results.append(from_fdroid(rt, package))
            except AnchorError as e:
                console.print(f"[red]refresh {ev.method} {ev.url or ''} failed:[/] {e}")
                return True
    for res in results:
        candidate, _ = merge(candidate, res, package=package, known_keys=rt.known_keys)
    before, after = current.trusted(), candidate.trusted()
    lin_before = [e.cert_sha256 for e in current.lineage]
    lin_after = [e.cert_sha256 for e in candidate.lineage]
    changed = before != after or lin_before != lin_after
    if not changed:
        console.print(f"No identity change for {package} ({len(results)} method(s) re-run).")
        if accept:
            rt.anchors.save(candidate)
        return False
    console.print(
        "[bold yellow]The vendor publication changed.[/] This is either a key rotation or a vendor-site "
        "compromise; KLONER never decides that alone."
    )
    for c in sorted(after - before):
        console.print(f"  + {short_fp(c)} {c}")
    for c in sorted(before - after):
        console.print(f"  - {short_fp(c)} {c}")
    if lin_before != lin_after:
        console.print(f"  lineage: {' → '.join(map(short_fp, lin_before))} ⇒ {' → '.join(map(short_fp, lin_after))}")
    if accept:
        rt.anchors.save(candidate)
        console.print("Accepted and written.")
    return True


def export_anchor(rt: Runtime, package: str, file: Path) -> None:
    a = _require(rt, package)
    file.write_text(
        json.dumps(a.model_dump(mode="json", by_alias=True), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def import_anchor(rt: Runtime, file: Path) -> Anchor:
    data = json.loads(file.read_text(encoding="utf-8"))
    incoming = Anchor.model_validate(data)
    infos: dict[str, CertInfo] = {}
    hygiene.check(incoming.identities, rt.known_keys, infos)
    incoming.corroboration = corroborate.level(incoming)
    existing = rt.anchors.get(incoming.package)
    if existing is not None:
        have = existing.trusted() | {e.cert_sha256 for e in existing.lineage}
        new = incoming.trusted() | {e.cert_sha256 for e in incoming.lineage}
        if not have & new:
            raise AnchorError(
                f"CONFLICT: the imported anchor for {incoming.package} shares no identity with the existing one; "
                "nothing was written",
                exit_code=3,
            )
    seal(incoming)
    if record_hash(incoming) != incoming.record_sha256:  # pragma: no cover - seal() guarantees it
        raise AnchorError("record hash could not be recomputed", exit_code=3)
    return rt.anchors.save(incoming)


def adopt_rotation(rt: Runtime, package: str, sample_sha256: str) -> Anchor:
    """Persist a rotation that a GENUINE sample proves under R1/R2, with that sample as evidence."""
    anchor = _require(rt, package)
    if not rt.quarantine.has(sample_sha256):
        raise AnchorError(f"sample {sample_sha256} is not in the quarantine", exit_code=2)
    sr = rt.pipeline().evaluate(sample_sha256, package, {package: anchor}, rt.known_keys)
    ev = sr.evaluation
    if ev.verdict != Verdict.GENUINE:
        raise AnchorError(f"the sample is {ev.verdict.value}, not GENUINE: {ev.explanation}", exit_code=3)
    rotated = [s for s in ev.signers if s.trust in ("R1", "R2")]
    if not rotated:
        raise AnchorError("the sample proves no rotation: every signer is already in the anchor", exit_code=2)
    infos = sr.facts.native_inventory.certs if sr.facts.native_inventory else {}
    now = now_iso()
    lineage = []
    rng = sr.facts.verify.full_range if sr.facts.verify else None
    if rng is not None and rng.lineage:
        lineage = [LineageEntry(cert_sha256=c.cert_sha256, capabilities=c.capabilities) for c in rng.lineage]
    res = MethodResult(
        klass="LINEAGE_PROOF", method="adopt-rotation", lineage=lineage, infos=dict(infos), sample_sha256=sample_sha256
    )
    for s in rotated:
        info = infos.get(s.cert_sha256)
        res.identities.append(
            Identity(
                id="pending",
                label="rotated",
                cert_sha256=s.cert_sha256,
                cert_der_b64=info.der_b64 if info else None,
                subject=s.subject,
                issuer=s.issuer,
                key_algorithm=s.key_algorithm,
                key_bits=s.key_bits,
                role="current",
                evidence=[
                    Evidence(
                        klass="LINEAGE_PROOF",
                        method="adopt-rotation",
                        file_sha256=sample_sha256,
                        retrieved_utc=now,
                        observed=f"admitted by {s.trust} from a trusted key",
                    )
                ],
            )
        )
    merged, _ = merge(anchor, res, package=package, known_keys=rt.known_keys)
    return rt.anchors.save(merged)
