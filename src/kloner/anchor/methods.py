"""Anchor creation methods (§7.2) and merging rules (§7.4).

Trust comes only from official provenance (INV-3). Identities recorded from an APK are exactly the
signers apksig verified, plus certificates of an apksig-verified proof-of-rotation lineage. A
certificate that only the native parser saw (an unverified v1 signer on API 24+, a sniffed block)
never becomes an identity: such a source APK is refused.
"""

from __future__ import annotations

import html
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote

from kloner.acquire.http import HttpError, host_of, vendor_domain_policy
from kloner.anchor import corroborate, hygiene
from kloner.app import Runtime
from kloner.decide import decide
from kloner.models import (
    Anchor,
    AnchorDecision,
    Brand,
    CertInfo,
    EvaluationFacts,
    Evidence,
    Identity,
    LineageEntry,
    ReleaseRef,
    Verdict,
    VerifyRange,
)
from kloner.util import proc
from kloner.util.fingerprints import FingerprintError, normalize_fingerprint, short_fp
from kloner.util.timeutil import now_iso

STRONG_CLASSES = frozenset({"VENDOR_HTTPS", "PLAY_API", "STORE_INSTALL", "FDROID_INDEX"})
OFFICIAL_INSTALLERS = frozenset({"com.android.vending", "com.huawei.appmarket"})
_HEX_FP = re.compile(r"(?<![0-9A-Fa-f:])((?:[0-9A-Fa-f]{2}[:\s\-]?){31}[0-9A-Fa-f]{2})(?![0-9A-Fa-f:])")
_TAG = re.compile(r"<[^>]+>")
_WS = re.compile(r"\s+")
FDROID_REPO = "https://f-droid.org/repo"
DAL_API = "https://digitalassetlinks.googleapis.com/v1/statements:list"


class AnchorError(Exception):
    def __init__(self, message: str, exit_code: int = 2) -> None:
        super().__init__(message)
        self.exit_code = exit_code


class AnchorConflict(AnchorError):
    def __init__(self, message: str) -> None:
        super().__init__(message, exit_code=3)


@dataclass
class MethodResult:
    klass: str
    method: str
    identities: list[Identity] = field(default_factory=list)
    lineage: list[LineageEntry] = field(default_factory=list)
    release_refs: list[ReleaseRef] = field(default_factory=list)
    labels: list[str] = field(default_factory=list)
    icons: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    infos: dict[str, CertInfo] = field(default_factory=dict)
    sample_sha256: str | None = None


# --------------------------------------------------------------------------------------------
# APK-based evidence
# --------------------------------------------------------------------------------------------


def _effective(facts: EvaluationFacts) -> VerifyRange | None:
    v = facts.verify
    if v is None or v.engine_failure or v.full_range is None:
        return None
    if v.full_range.verified:
        return v.full_range
    if v.modern_range is not None and v.modern_range.verified:
        return v.modern_range
    return None


def apk_evidence(
    rt: Runtime,
    sha: str,
    package: str,
    klass: str,
    method: str,
    *,
    url: str | None = None,
    final_url: str | None = None,
    detail: str | None = None,
) -> MethodResult:
    """Run the full pipeline on a source APK and turn its verified signers into identities."""
    sr = rt.pipeline().evaluate(sha, package, {}, rt.known_keys)
    facts = sr.facts
    if facts.intake.format != "apk":
        raise AnchorError(
            f"the source file is not an APK ({facts.intake.format or facts.intake.reason}); "
            "give the base APK of the package",
            exit_code=3,
        )
    if facts.archive is None or facts.archive.failed:
        raise AnchorError(f"the source APK is not intact: {sr.evaluation.explanation}", exit_code=3)
    m = facts.manifest
    if m is None or m.unreadable or m.parsers_disagree:
        raise AnchorError(f"the source APK fails manifest identity: {sr.evaluation.explanation}", exit_code=3)
    if m.package != package:
        raise AnchorError(f"the source APK is package {m.package}, not {package}", exit_code=3)
    rng = _effective(facts)
    if rng is None:
        raise AnchorError(f"the source APK does not verify: {sr.evaluation.explanation}", exit_code=3)
    verified = sorted({s.cert_sha256 for s in rng.signers if s.cert_sha256 and not s.ignored})
    lineage = [LineageEntry(cert_sha256=c.cert_sha256, capabilities=c.capabilities) for c in (rng.lineage or [])]
    if not lineage:
        for s in rng.signers:
            if s.scheme in ("v31", "v3") and s.lineage:
                lineage = [LineageEntry(cert_sha256=c.cert_sha256, capabilities=c.capabilities) for c in s.lineage]
                break
    trusted = set(verified) | {e.cert_sha256 for e in lineage}
    probe = Anchor(
        package=package,
        created_utc="probe",
        refreshed_utc="probe",
        lineage=lineage,
        identities=[Identity(id=f"p{i}", cert_sha256=c) for i, c in enumerate(sorted(trusted))],
    )
    ev = decide(facts, {package: probe}, rt.known_keys)
    if ev.verdict != Verdict.GENUINE:
        raise AnchorError(
            f"the source APK does not pass the full pipeline ({ev.verdict.value}): {ev.explanation}", exit_code=3
        )
    infos = facts.native_inventory.certs if facts.native_inventory else {}
    now = now_iso()
    lin = [e.cert_sha256 for e in lineage]
    schemes = ", ".join(s for s, ok in sorted(rng.schemes.items()) if ok)
    res = MethodResult(klass=klass, method=method, lineage=lineage, infos=dict(infos), sample_sha256=sha)
    for cert in sorted(trusted):
        info = infos.get(cert)
        role = "legacy" if cert in lin[:-1] else "current"
        observed = f"apksig-verified signer ({schemes})" if cert in verified else "apksig-verified lineage certificate"
        res.identities.append(
            _identity(
                cert,
                info,
                role,
                Evidence(
                    klass=klass,
                    method=method,
                    url=url,
                    final_url=final_url,
                    file_sha256=sha,
                    retrieved_utc=now,
                    observed=observed,
                    detail=detail,
                ),
            )
        )
    res.release_refs.append(
        ReleaseRef(
            version_code=m.version_code or 0,
            version_name=m.version_name,
            file_sha256=sha,
            signers=verified,
            provenance=klass,
            observed_utc=now,
        )
    )
    if facts.brand is not None:
        res.labels = list(facts.brand.labels)
        res.icons = list(facts.brand.icon_hashes)
    return res


def _identity(cert: str, info: CertInfo | None, role: str, evidence: Evidence) -> Identity:
    return Identity(
        id="pending",
        label=role,
        cert_sha256=cert,
        cert_der_b64=info.der_b64 if info else None,
        subject=info.subject if info else None,
        issuer=info.issuer if info else None,
        serial=info.serial if info else None,
        not_before=info.not_before if info else None,
        not_after=info.not_after if info else None,
        key_algorithm=info.key_algorithm if info else None,
        key_bits=info.key_bits if info else None,
        role=role,
        evidence=[evidence],
    )


def from_url(rt: Runtime, package: str, url: str, domains: list[str]) -> MethodResult:
    if not domains:
        raise AnchorError("--from-url needs at least one --vendor-domain")
    if not url.lower().startswith("https://"):
        raise AnchorError("--from-url requires an HTTPS URL (vendor provenance needs valid TLS)", exit_code=3)
    policy = vendor_domain_policy(domains)
    http = rt.http()
    try:
        with rt.quarantine.sink(rt.config.limits.max_file_bytes) as s:
            dl = http.download(url, s, redirect_policy=policy)
        sha, size = rt.quarantine.finalize(s)
    except HttpError as e:
        raise AnchorError(f"vendor download failed: {e.detail}", exit_code=3) from e
    rt.quarantine.write_evidence(
        sha,
        {
            "sample_sha256": sha,
            "size": size,
            "source": "anchor:url",
            "download_url": url,
            "final_url": dl.final_url,
            "redirect_chain": dl.chain,
            "http_status": dl.status,
            "content_type": dl.content_type,
            "retrieved_utc": now_iso(),
            "tls_verified": dl.tls_verified,
            "client_profile": {"user_agent": http.user_agent, "proxy": http.proxy},
        },
    )
    return apk_evidence(
        rt,
        sha,
        package,
        "VENDOR_HTTPS",
        "url",
        url=url,
        final_url=dl.final_url,
        detail=f"final host {host_of(dl.final_url)} inside {', '.join(domains)}",
    )


def from_apk(rt: Runtime, package: str, path: Path) -> MethodResult:
    sha, _ = rt.quarantine.ingest_file(path, rt.config.limits.max_file_bytes)
    res = apk_evidence(rt, sha, package, "USER", "apk", detail=f"local file {path.name}")
    res.notes.append("a local file cannot prove provenance: these identities stay USER-asserted")
    return res


# --------------------------------------------------------------------------------------------
# Published fingerprints
# --------------------------------------------------------------------------------------------


def extract_fingerprints(content: bytes) -> set[str]:
    text = html.unescape(_TAG.sub(" ", content.decode("utf-8", errors="replace")))
    text = _WS.sub(" ", text)  # fingerprints are often split over lines (found in the live trial)
    found: set[str] = set()
    for m in _HEX_FP.finditer(text):
        try:
            found.add(normalize_fingerprint(m.group(1)))
        except FingerprintError:
            continue
    return found


def from_fingerprints(rt: Runtime, package: str, values: list[str], evidence_url: str | None) -> MethodResult:
    try:
        fps = [normalize_fingerprint(v) for v in values]
    except FingerprintError as e:
        raise AnchorError(str(e)) from e
    now = now_iso()
    if evidence_url is None:
        res = MethodResult(klass="USER", method="fingerprint")
        res.notes.append("no --evidence-url: the fingerprints are USER-asserted")
        for fp in fps:
            res.identities.append(
                _identity(
                    fp,
                    None,
                    "current",
                    Evidence(klass="USER", method="fingerprint", retrieved_utc=now, observed="typed by the owner"),
                )
            )
        return res
    if not evidence_url.lower().startswith("https://"):
        raise AnchorError("--evidence-url must be HTTPS", exit_code=3)
    try:
        doc = rt.http().get_document(evidence_url, 16 << 20)
    except HttpError as e:
        raise AnchorError(f"evidence page fetch failed: {e.detail}", exit_code=3) from e
    published = extract_fingerprints(doc.content)
    missing = [fp for fp in fps if fp not in published]
    if missing:
        raise AnchorError(
            f"fingerprint(s) not found on {evidence_url}: {', '.join(short_fp(m) for m in missing)}", exit_code=3
        )
    res = MethodResult(klass="VENDOR_PUBLISHED", method="fingerprint")
    for fp in fps:
        res.identities.append(
            _identity(
                fp,
                None,
                "current",
                Evidence(
                    klass="VENDOR_PUBLISHED",
                    method="fingerprint",
                    url=evidence_url,
                    final_url=doc.final_url,
                    retrieved_utc=now,
                    observed="fingerprint published on the vendor page",
                ),
            )
        )
    return res


def parse_assetlinks(data: Any, package: str) -> set[str]:
    if not isinstance(data, list):
        raise AnchorError("assetlinks.json is not a JSON list of statements", exit_code=3)
    out: set[str] = set()
    for st in data:
        if not isinstance(st, dict):
            continue
        target = st.get("target")
        if not isinstance(target, dict):
            continue
        if target.get("namespace") != "android_app" or target.get("package_name") != package:
            continue
        for fp in target.get("sha256_cert_fingerprints") or []:
            if isinstance(fp, str):
                try:
                    out.add(normalize_fingerprint(fp))
                except FingerprintError:
                    continue
    return out


def from_assetlinks(rt: Runtime, package: str, domain: str) -> MethodResult:
    domain = domain.strip().strip("/").lower()
    if "/" in domain or ":" in domain:
        raise AnchorError("--from-assetlinks takes a bare domain, e.g. example.com")
    url = f"https://{domain}/.well-known/assetlinks.json"
    try:
        doc = rt.http().get_document(url, rt.config.parse_limits().max_assetlinks_bytes, follow=False)
        data = json.loads(doc.content)
    except HttpError as e:
        raise AnchorError(f"assetlinks fetch failed: {e.detail}", exit_code=3) from e
    except json.JSONDecodeError as e:
        raise AnchorError(f"assetlinks.json is not valid JSON: {e}", exit_code=3) from e
    fps = parse_assetlinks(data, package)
    if not fps:
        raise AnchorError(f"{url} lists no android_app statement for {package}", exit_code=3)
    detail = "Google Digital Asset Links API cross-check not available"
    try:
        api = rt.http().get_document(
            f"{DAL_API}?source.web.site={quote('https://' + domain, safe='')}"
            "&relation=delegate_permission/common.handle_all_urls",
            4 << 20,
        )
        statements = json.loads(api.content).get("statements", [])
        api_fps = set()
        for st in statements:
            app = (st.get("target") or {}).get("androidApp") or {}
            if app.get("packageName") == package:
                cert = (app.get("certificate") or {}).get("sha256Fingerprint")
                if cert:
                    api_fps.add(normalize_fingerprint(cert))
        detail = (
            "confirmed by the Google Digital Asset Links API"
            if fps <= api_fps
            else "Google Digital Asset Links API did not confirm every fingerprint"
        )
    except (HttpError, json.JSONDecodeError, FingerprintError, AttributeError):
        pass
    now = now_iso()
    res = MethodResult(klass="VENDOR_PUBLISHED", method="assetlinks")
    for fp in sorted(fps):
        res.identities.append(
            _identity(
                fp,
                None,
                "current",
                Evidence(
                    klass="VENDOR_PUBLISHED",
                    method="assetlinks",
                    url=url,
                    final_url=doc.final_url,
                    retrieved_utc=now,
                    observed="sha256_cert_fingerprints in assetlinks.json",
                    detail=detail,
                ),
            )
        )
    return res


# --------------------------------------------------------------------------------------------
# F-Droid
# --------------------------------------------------------------------------------------------


def fdroid_versions(rt: Runtime, package: str) -> list[dict[str, Any]]:
    from kloner.acquire.fdroid import FdroidIndex

    return FdroidIndex(rt).versions(package)


def from_fdroid(rt: Runtime, package: str) -> MethodResult:
    from kloner.acquire.fdroid import FdroidIndex

    index = FdroidIndex(rt)
    versions = index.versions(package)
    if not versions:
        raise AnchorError(f"{package} is not in the F-Droid repository index", exit_code=3)
    latest = versions[0]
    signers = set(latest["signers"])
    try:
        sha, final_url = index.download(latest)
    except HttpError as e:
        raise AnchorError(f"F-Droid download failed: {e.detail}", exit_code=3) from e
    res = apk_evidence(
        rt,
        sha,
        package,
        "FDROID_INDEX",
        "fdroid",
        url=latest["url"],
        final_url=final_url,
        detail=f"index signer {', '.join(short_fp(s) for s in sorted(signers))}",
    )
    verified = set(res.release_refs[0].signers)
    if not verified or not verified <= signers:
        raise AnchorError(
            "the APK's verified signer does not match the F-Droid index signer "
            f"({', '.join(short_fp(s) for s in sorted(verified))} vs "
            f"{', '.join(short_fp(s) for s in sorted(signers))})",
            exit_code=3,
        )
    return res


# --------------------------------------------------------------------------------------------
# Device install and Google Play
# --------------------------------------------------------------------------------------------

_INSTALLER = re.compile(r"installerPackageName=([\w.]+)")


def parse_pm_path(text: str) -> list[str]:
    return [ln.strip()[len("package:") :] for ln in text.splitlines() if ln.strip().startswith("package:")]


def parse_installer(dumpsys: str) -> str | None:
    m = _INSTALLER.search(dumpsys)
    return m.group(1) if m and m.group(1) != "null" else None


def from_device(rt: Runtime, package: str, serial: str | None) -> MethodResult:
    tc = rt.toolchain()
    if not tc.adb:
        raise AnchorError("adb not found in the Android SDK platform-tools", exit_code=2)
    base = [tc.adb] + (["-s", serial] if serial else [])
    res = proc.run([*base, "shell", "pm", "path", package], timeout_s=60)
    paths = parse_pm_path(res.text())
    if not res.ok or not paths:
        raise AnchorError(f"package {package} is not installed on the device ({res.err_text().strip()})", exit_code=2)
    dump = proc.run([*base, "shell", "dumpsys", "package", package], timeout_s=60).text()
    installer = parse_installer(dump)
    klass = "STORE_INSTALL" if installer in OFFICIAL_INSTALLERS else "USER"
    pulled: list[str] = []
    import tempfile

    with tempfile.TemporaryDirectory(dir=rt.quarantine.incoming) as tmp:
        for i, remote in enumerate(paths):
            local = Path(tmp) / f"part{i}"
            r = proc.run([*base, "pull", remote, str(local)], timeout_s=600)
            if not r.ok or not local.is_file():
                raise AnchorError(f"adb pull {remote} failed: {r.err_text().strip()}", exit_code=2)
            sha, _ = rt.quarantine.ingest_file(local, rt.config.limits.max_file_bytes)
            pulled.append(sha)
    results = []
    for sha in pulled:
        sr = rt.pipeline().evaluate(sha, package, {}, rt.known_keys)
        results.append((sha, sr))
    base_sha = next((sha for sha, sr in results if sr.facts.manifest and sr.facts.manifest.split is None), None)
    if base_sha is None:
        raise AnchorError("no base APK among the pulled files", exit_code=3)
    out = apk_evidence(rt, base_sha, package, klass, "device", detail=f"installer {installer or 'unknown'}")
    for sha, _sr in results:
        if sha == base_sha:
            continue
        split = apk_evidence(rt, sha, package, klass, "device", detail="split APK")
        if set(split.release_refs[0].signers) != set(out.release_refs[0].signers):
            raise AnchorError("installed split APKs are signed differently from the base APK", exit_code=3)
    if klass == "USER":
        out.notes.append(f"installer {installer or 'unknown'} is not an official store: identities stay USER")
    return out


def from_play(rt: Runtime, package: str) -> MethodResult:
    from kloner.acquire.apkeep import play_download
    from kloner.acquire.base import SourceError

    try:
        sha, detail = play_download(rt, package)
    except SourceError as e:
        raise AnchorError(f"Google Play download unavailable: {e.reason}", exit_code=2) from e
    return apk_evidence(rt, sha, package, "PLAY_API", "play", detail=detail)


# --------------------------------------------------------------------------------------------
# Merging (§7.4)
# --------------------------------------------------------------------------------------------


def merge_lineage(a: list[LineageEntry], b: list[LineageEntry]) -> list[LineageEntry]:
    ca, cb = [e.cert_sha256 for e in a], [e.cert_sha256 for e in b]
    if not ca:
        return b
    if not cb:
        return a

    def contains(big: list[str], small: list[str]) -> bool:
        return any(big[i : i + len(small)] == small for i in range(len(big) - len(small) + 1))

    if contains(cb, ca):
        return b
    if contains(ca, cb):
        return a
    for k in range(min(len(ca), len(cb)) - 1, 0, -1):
        for candidate in ((a + b[k:]) if ca[-k:] == cb[:k] else None, (b + a[k:]) if cb[-k:] == ca[:k] else None):
            if candidate is None:
                continue
            certs = [e.cert_sha256 for e in candidate]
            if len(set(certs)) == len(certs):  # a lineage never repeats a certificate
                return candidate
    raise AnchorConflict("the new evidence carries a signing lineage that contradicts the anchor's lineage")


def _same_evidence(x: Evidence, y: Evidence) -> bool:
    return (x.klass, x.method, x.url, x.file_sha256) == (y.klass, y.method, y.url, y.file_sha256)


def merge(
    existing: Anchor | None,
    res: MethodResult,
    *,
    package: str,
    known_keys: dict[str, str],
    declare_additional: bool = False,
    reason: str | None = None,
    label: str | None = None,
    brand_labels: list[str] | None = None,
    brand_keywords: list[str] | None = None,
) -> tuple[Anchor, list[str]]:
    notes = list(res.notes) + hygiene.check(res.identities, known_keys, res.infos)
    now = now_iso()
    anchor = existing.model_copy(deep=True) if existing else Anchor(package=package, created_utc=now, refreshed_utc=now)
    have = anchor.trusted() | {e.cert_sha256 for e in anchor.lineage}
    new = {i.cert_sha256 for i in res.identities} | {e.cert_sha256 for e in res.lineage}
    additional = False
    if existing is not None and not (have & new):
        if not declare_additional:
            raise AnchorConflict(
                "CONFLICT: the new evidence shares no identity with the anchor "
                f"(anchor: {', '.join(short_fp(c) for c in sorted(have))}; new: "
                f"{', '.join(short_fp(c) for c in sorted(new))}). Nothing was written. If this is a legitimate "
                'second signing identity, re-run with --declare-additional-identity --reason "<why>"'
            )
        if not reason:
            raise AnchorError("--declare-additional-identity requires --reason")
        additional = True
    elif declare_additional:
        notes.append("--declare-additional-identity ignored: the evidence shares an identity with the anchor")

    if res.lineage and not additional:
        anchor.lineage = merge_lineage(anchor.lineage, res.lineage)
    next_id = 1 + max((int(i.id.split("-")[1]) for i in anchor.identities if i.id.startswith("id-")), default=0)
    for ident in res.identities:
        cur = anchor.identity(ident.cert_sha256)
        if cur is not None:
            for ev in ident.evidence:
                if not any(_same_evidence(ev, e) for e in cur.evidence):
                    cur.evidence.append(ev)
            for fld in (
                "cert_der_b64",
                "subject",
                "issuer",
                "serial",
                "not_before",
                "not_after",
                "key_algorithm",
                "key_bits",
            ):
                if getattr(cur, fld) is None and getattr(ident, fld) is not None:
                    setattr(cur, fld, getattr(ident, fld))
            continue
        ident.id = f"id-{next_id}"
        next_id += 1
        if additional:
            ident.declared_additional = True
            ident.declared_reason = reason
            ident.role = "additional"
            ident.label = label or "additional"
            anchor.decisions.append(
                AnchorDecision(utc=now, action="declare-additional-identity", identity=ident.id, reason=reason or "")
            )
        elif label:
            ident.label = label
        anchor.identities.append(ident)

    lin = [e.cert_sha256 for e in anchor.lineage]
    for ident in anchor.identities:
        if ident.declared_additional:
            continue
        role = "legacy" if ident.cert_sha256 in lin[:-1] else "current"
        if ident.label in ("current", "legacy"):
            ident.label = role
        ident.role = role

    seen = {r.file_sha256 for r in anchor.release_refs}
    anchor.release_refs += [r for r in res.release_refs if r.file_sha256 not in seen]
    anchor.release_refs.sort(key=lambda r: (r.version_code, r.file_sha256))
    brand = anchor.brand
    if res.klass in STRONG_CLASSES:
        brand.labels = sorted(set(brand.labels) | set(res.labels))
        brand.icon_asset_sha256 = sorted(set(brand.icon_asset_sha256) | set(res.icons))
    brand.brand_labels = sorted(set(brand.brand_labels) | set(brand_labels or []))
    brand.keywords = sorted(set(brand.keywords) | set(brand_keywords or []))
    anchor.brand = Brand.model_validate(brand.model_dump())
    anchor.refreshed_utc = now
    anchor.corroboration = corroborate.level(anchor)
    return anchor, notes
