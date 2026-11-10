"""Command-line interface (§13). Simple on the outside, rigorous on the inside.

Every error message ends with the next command to run. Exit codes: 0 clean, 10 hostile, 11 review,
2 usage/configuration, 3 anchor conflict or hygiene, 4 verifier unavailable, 5 internal error.
"""

from __future__ import annotations

import contextlib
import json
import os
import sys
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any, NoReturn, TypeVar

import typer
from rich.console import Console

from kloner import __version__
from kloner.config import DEFAULT_CONFIG_TOML, default_home
from kloner.util.timeutil import run_id as make_run_id

if TYPE_CHECKING:
    from kloner.app import Runtime

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    rich_markup_mode=None,
    help="KLONER — prove every copy of an Android app genuine or not.",
)
anchor_app = typer.Typer(no_args_is_help=True, help="Manage trust anchors (official signing identities).")
intel_app = typer.Typer(no_args_is_help=True, help="Correlations across runs and packages.")
export_app = typer.Typer(no_args_is_help=True, help="Export samples for analyst sharing.")
app.add_typer(anchor_app, name="anchor")
app.add_typer(intel_app, name="intel")
app.add_typer(export_app, name="export")

EXIT_USAGE, EXIT_ANCHOR, EXIT_VERIFIER, EXIT_INTERNAL = 2, 3, 4, 5
T = TypeVar("T")


class State:
    home: Path = default_home()
    json: bool = False
    quiet: bool = False
    debug: bool = False
    no_color: bool = False
    workers: int | None = None
    rate: float | None = None
    console: Console = Console()


S = State()


def _utf8_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconf = getattr(stream, "reconfigure", None)
        if reconf is not None:
            with contextlib.suppress(ValueError, OSError):
                reconf(encoding="utf-8", errors="replace")


@app.callback(invoke_without_command=True)
def main_callback(
    ctx: typer.Context,
    home: Annotated[Path | None, typer.Option("--home", help="KLONER home (default ~/.kloner)")] = None,
    json_out: Annotated[bool, typer.Option("--json", help="Machine-readable JSON output")] = False,
    quiet: Annotated[bool, typer.Option("--quiet")] = False,
    debug: Annotated[bool, typer.Option("--debug")] = False,
    no_color: Annotated[bool, typer.Option("--no-color")] = False,
    workers: Annotated[int | None, typer.Option("--workers", min=1, max=64)] = None,
    rate: Annotated[float | None, typer.Option("--rate", help="Requests per second per host")] = None,
    version: Annotated[bool, typer.Option("--version", help="Print the version and exit")] = False,
) -> None:
    _utf8_stdio()
    if version:
        typer.echo(f"kloner {__version__}")
        raise typer.Exit(0)
    S.home = home or default_home()
    S.json, S.quiet, S.debug, S.no_color, S.workers, S.rate = json_out, quiet, debug, no_color, workers, rate
    S.console = Console(no_color=no_color, quiet=quiet, highlight=False, soft_wrap=False)


def _runtime(proxy: str | None = None, user_agent: str | None = None) -> Runtime:
    from kloner.app import Runtime
    from kloner.util.logging import setup_logging

    rt = Runtime.open(S.home, workers=S.workers, proxy=proxy, user_agent_override=user_agent)
    if S.rate is not None:
        rt.config.network.rate_per_host = S.rate
    setup_logging(S.home, make_run_id(), S.debug)
    return rt


def _fail(msg: str, code: int) -> None:
    Console(stderr=True, highlight=False, soft_wrap=True).print(f"[bold red]error:[/] {msg}")
    raise typer.Exit(code)


def _guard(fn: Callable[[], T]) -> T:
    """Map KLONER exceptions onto exit codes; never show a traceback unless --debug."""
    from kloner.anchor.hygiene import HygieneError
    from kloner.anchor.methods import AnchorError
    from kloner.anchor.store import AnchorIntegrityError
    from kloner.app import VerifierUnavailable
    from kloner.hunt import UsageError
    from kloner.toolchain import ToolchainError

    try:
        return fn()
    except typer.Exit:
        raise
    except VerifierUnavailable as e:
        _fail(f"the authoritative verifier is unavailable: {e}", EXIT_VERIFIER)
    except ToolchainError as e:
        _fail(f"{e}. Run: kloner setup", EXIT_VERIFIER)
    except (HygieneError, AnchorIntegrityError) as e:
        _fail(str(e), EXIT_ANCHOR)
    except AnchorError as e:
        _fail(str(e), e.exit_code)
    except (UsageError, ValueError) as e:
        _fail(str(e), EXIT_USAGE)
    except KeyboardInterrupt:
        _fail("interrupted", EXIT_INTERNAL)
    except Exception as e:
        if S.debug:
            raise
        _fail(f"internal error: {type(e).__name__}: {e}. Re-run with --debug and report it.", EXIT_INTERNAL)
    raise AssertionError("unreachable")


# --------------------------------------------------------------------------------------------
# setup / doctor / selftest
# --------------------------------------------------------------------------------------------


@app.command()
def setup(
    accept_android_sdk_license: Annotated[
        bool,
        typer.Option(
            help="Accept the Android SDK License Agreement for the pinned packages without a prompt. Read it first: "
            "https://developer.android.com/studio/terms"
        ),
    ] = False,
    upgrade: Annotated[bool, typer.Option(help="Re-resolve and re-pin every component")] = False,
    no_apkeep: Annotated[bool, typer.Option("--no-apkeep", help="Do not download apkeep")] = False,
) -> None:
    """Install and pin the toolchain (JDK check, build-tools, apksig bridge, apkeep)."""

    def run() -> None:
        from kloner.toolchain import ToolchainError
        from kloner.toolchain import setup as do_setup
        from kloner.toolchain_install import ensure_build_tools

        S.home.mkdir(parents=True, exist_ok=True)
        cfg = S.home / "config.toml"
        if not cfg.exists():
            cfg.write_text(DEFAULT_CONFIG_TOML, encoding="utf-8")
        try:
            tc, notes = do_setup(S.home, install_apkeep_binary=not no_apkeep, user_agent=f"kloner/{__version__}")
        except ToolchainError as e:
            if "build-tools" not in str(e):
                raise
            ensure_build_tools(S.home, accept_license=accept_android_sdk_license, console=S.console)
            tc, notes = do_setup(S.home, install_apkeep_binary=not no_apkeep, user_agent=f"kloner/{__version__}")
        S.console.print(f"[green]PASS[/] JDK: {tc.java_version}")
        S.console.print(f"[green]PASS[/] build-tools {tc.build_tools_version} at {tc.build_tools}")
        S.console.print(f"[green]PASS[/] apksig: {tc.apksig_version}")
        S.console.print(f"[green]PASS[/] bridge compiled: {tc.bridge_classes}")
        S.console.print(
            f"{'[green]PASS[/]' if tc.apkeep else '[yellow]WARN[/]'} apkeep: {tc.apkeep or 'not installed'}"
        )
        for n in notes:
            S.console.print(f"[yellow]note[/] {n}")
        S.console.print("Next: kloner doctor")

    _guard(run)


@app.command()
def doctor() -> None:
    """Check every component, the bridge round-trip, permissions and source reachability."""

    def run() -> None:
        from kloner.doctor import run_doctor

        rt = _runtime()
        checks = run_doctor(rt)
        if S.json:
            typer.echo(json.dumps([c.__dict__ for c in checks], indent=2))
        else:
            for c in checks:
                color = "green" if c.status == "PASS" else ("yellow" if c.status == "WARN" else "red")
                S.console.print(f"[{color}]{c.status}[/] {c.name}: {c.detail}" + (f" — fix: {c.fix}" if c.fix else ""))
        if any(c.status == "FAIL" and c.critical for c in checks):
            raise typer.Exit(EXIT_VERIFIER)

    _guard(run)


@app.command()
def selftest(
    quick: Annotated[bool, typer.Option("--quick", help="Core cases only")] = False,
    full: Annotated[bool, typer.Option("--full", help="Everything, with larger property/fuzz budgets")] = False,
) -> None:
    """Regenerate the synthetic corpus from KLONER's own fixtures and check every expected verdict."""

    def run() -> None:
        from kloner.selftest.runner import run_selftest

        rt = _runtime()
        ok = run_selftest(rt, mode="full" if full else ("quick" if quick else "standard"), console=S.console)
        raise typer.Exit(0 if ok else 1)

    _guard(run)


# --------------------------------------------------------------------------------------------
# anchors
# --------------------------------------------------------------------------------------------


@anchor_app.command("add", context_settings={"allow_extra_args": False})
def anchor_add(
    package: Annotated[str, typer.Argument(help="Android package name")],
    extra_fingerprints: Annotated[
        list[str] | None, typer.Argument(help="More fingerprints after --from-fingerprint")
    ] = None,
    from_device: Annotated[bool, typer.Option("--from-device")] = False,
    serial: Annotated[str | None, typer.Option("--serial")] = None,
    from_play: Annotated[bool, typer.Option("--from-play")] = False,
    from_url: Annotated[str | None, typer.Option("--from-url")] = None,
    vendor_domain: Annotated[list[str] | None, typer.Option("--vendor-domain")] = None,
    from_fingerprint: Annotated[list[str] | None, typer.Option("--from-fingerprint")] = None,
    evidence_url: Annotated[str | None, typer.Option("--evidence-url")] = None,
    from_assetlinks: Annotated[str | None, typer.Option("--from-assetlinks")] = None,
    from_fdroid: Annotated[bool, typer.Option("--from-fdroid")] = False,
    from_apk: Annotated[Path | None, typer.Option("--from-apk", exists=True, dir_okay=False)] = None,
    label: Annotated[str | None, typer.Option("--label")] = None,
    brand_label: Annotated[list[str] | None, typer.Option("--brand-label")] = None,
    brand_keyword: Annotated[list[str] | None, typer.Option("--brand-keyword")] = None,
    declare_additional_identity: Annotated[bool, typer.Option("--declare-additional-identity")] = False,
    reason: Annotated[str | None, typer.Option("--reason")] = None,
) -> None:
    """Create or extend the anchor of PACKAGE from an official provenance method."""

    def run() -> None:
        from kloner.anchor import methods
        from kloner.anchor.store import valid_package
        from kloner.hunt import UsageError

        if not valid_package(package):
            raise UsageError(f"not a valid Android package name: {package}")
        chosen = [
            bool(from_device),
            bool(from_play),
            bool(from_url),
            bool(from_fingerprint),
            bool(from_assetlinks),
            bool(from_fdroid),
            bool(from_apk),
        ]
        if sum(chosen) != 1:
            raise UsageError(
                "choose exactly one method: --from-device | --from-play | --from-url | "
                "--from-fingerprint | --from-assetlinks | --from-fdroid | --from-apk"
            )
        if extra_fingerprints and not from_fingerprint:
            raise UsageError(f"unexpected arguments: {' '.join(extra_fingerprints)}")
        rt = _runtime()
        if from_url:
            res = methods.from_url(rt, package, from_url, list(vendor_domain or []))
        elif from_fingerprint:
            res = methods.from_fingerprints(
                rt, package, list(from_fingerprint) + list(extra_fingerprints or []), evidence_url
            )
        elif from_assetlinks:
            res = methods.from_assetlinks(rt, package, from_assetlinks)
        elif from_fdroid:
            res = methods.from_fdroid(rt, package)
        elif from_apk:
            res = methods.from_apk(rt, package, from_apk)
        elif from_device:
            res = methods.from_device(rt, package, serial)
        else:
            res = methods.from_play(rt, package)
        store = rt.anchors
        anchor, notes = methods.merge(
            store.get(package),
            res,
            package=package,
            known_keys=rt.known_keys,
            declare_additional=declare_additional_identity,
            reason=reason,
            label=label,
            brand_labels=list(brand_label or []),
            brand_keywords=list(brand_keyword or []),
        )
        anchor = store.save(anchor)
        from kloner.report.anchor import render_anchor

        render_anchor(anchor, S.console, as_json=S.json)
        for n in notes:
            S.console.print(f"[yellow]note[/] {n}")
        S.console.print(f"Next: kloner hunt {package}")

    _guard(run)


@anchor_app.command("show")
def anchor_show(package: str) -> None:
    """Show an anchor: identities, lineage, evidence, corroboration, record hash."""

    def run() -> None:
        from kloner.hunt import UsageError
        from kloner.report.anchor import render_anchor

        rt = _runtime()
        a = rt.anchors.get(package)
        if a is None:
            raise UsageError(f"no anchor for {package}. Create one: kloner anchor add {package} --from-url …")
        render_anchor(a, S.console, as_json=S.json)

    _guard(run)


@anchor_app.command("list")
def anchor_list() -> None:
    """List anchors."""

    def run() -> None:
        rt = _runtime()
        rows = rt.anchors.list()
        if S.json:
            typer.echo(
                json.dumps(
                    [
                        {
                            "package": a.package,
                            "corroboration": a.corroboration,
                            "identities": len(a.identities),
                            "record_sha256": a.record_sha256,
                        }
                        for a in rows
                    ],
                    indent=2,
                )
            )
            return
        if not rows:
            S.console.print(
                "No anchors. Create one: kloner anchor add <package> --from-url <official-apk-url> "
                "--vendor-domain <domain>"
            )
        for a in rows:
            S.console.print(
                f"{a.package}  {a.corroboration}  {len(a.identities)} identit"
                f"{'y' if len(a.identities) == 1 else 'ies'}  #{a.record_sha256[:12]}"
            )

    _guard(run)


@anchor_app.command("refresh")
def anchor_refresh(package: str, accept: Annotated[bool, typer.Option("--accept")] = False) -> None:
    """Re-run the automatic methods recorded in the anchor and show the difference."""

    def run() -> None:
        from kloner.anchor.lifecycle import refresh

        rt = _runtime()
        changed = refresh(rt, package, accept=accept, console=S.console)
        if changed and not accept:
            S.console.print(f"Nothing written. If the change is expected: kloner anchor refresh {package} --accept")

    _guard(run)


@anchor_app.command("export")
def anchor_export(package: str, file: Path) -> None:
    """Export an anchor as portable JSON."""

    def run() -> None:
        from kloner.anchor.lifecycle import export_anchor

        rt = _runtime()
        export_anchor(rt, package, file)
        S.console.print(f"Exported {package} to {file}. Import elsewhere with: kloner anchor import {file}")

    _guard(run)


@anchor_app.command("import")
def anchor_import(file: Annotated[Path, typer.Argument(exists=True, dir_okay=False)]) -> None:
    """Import an anchor; hygiene is re-validated and the hash recomputed."""

    def run() -> None:
        from kloner.anchor.lifecycle import import_anchor
        from kloner.report.anchor import render_anchor

        rt = _runtime()
        a = import_anchor(rt, file)
        render_anchor(a, S.console, as_json=S.json)

    _guard(run)


@anchor_app.command("adopt-rotation")
def anchor_adopt_rotation(package: str, sample_sha256: str) -> None:
    """Persist a key rotation proven (R1/R2) by a specific GENUINE sample."""

    def run() -> None:
        from kloner.anchor.lifecycle import adopt_rotation
        from kloner.report.anchor import render_anchor

        rt = _runtime()
        a = adopt_rotation(rt, package, sample_sha256)
        render_anchor(a, S.console, as_json=S.json)

    _guard(run)


# --------------------------------------------------------------------------------------------
# hunt / verify / fetch / survey
# --------------------------------------------------------------------------------------------


def _emit(rt: Any, rep: Any, out: Path | None, formats: list[str]) -> int:
    from kloner.report import write_reports
    from kloner.report.jsonout import build
    from kloner.report.terminal import render

    doc = build(rep)
    out_dir = out or (S.home / "runs" / rep.run_id)
    file_formats = [f for f in formats if f != "terminal"] or []
    paths = write_reports(doc, out_dir, file_formats) if file_formats else []
    rt.db.put_run_meta(rep.run_id, rep.command, str(out_dir))
    if S.json:
        typer.echo(json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=False))
    elif "terminal" in formats:
        render(doc, S.console, [str(p) for p in paths])
    return int(rep.exit_code)


def _sources(value: str | None) -> list[str] | None:
    if not value:
        return None
    from kloner.acquire.sources import ALL_SOURCES

    names = [s.strip() for s in value.split(",") if s.strip()]
    bad = [n for n in names if n not in ALL_SOURCES]
    if bad:
        raise ValueError(f"unknown source(s): {', '.join(bad)}; choose from {', '.join(ALL_SOURCES)}")
    return names


@app.command()
def hunt(
    package: str,
    sources: Annotated[str | None, typer.Option("--sources", help="Comma-separated source list")] = None,
    all_versions: Annotated[bool, typer.Option("--all-versions")] = False,
    max_per_source: Annotated[int, typer.Option("--max-per-source", min=1)] = 10,
    impersonators: Annotated[bool, typer.Option("--impersonators")] = False,
    new_only: Annotated[bool, typer.Option("--new-only")] = False,
    require_corroborated: Annotated[bool, typer.Option("--require-corroborated")] = False,
    proxy: Annotated[str | None, typer.Option("--proxy")] = None,
    user_agent: Annotated[str | None, typer.Option("--user-agent", help="Override for multi-vantage tests")] = None,
    out: Annotated[Path | None, typer.Option("--out")] = None,
    fmt: Annotated[str, typer.Option("--format")] = "terminal,json,md,html,iocs",
    fail_on: Annotated[str | None, typer.Option("--fail-on")] = None,
    notify_webhook: Annotated[str | None, typer.Option("--notify-webhook")] = None,
    local: Annotated[
        list[Path] | None, typer.Option("--local", help="Files or directories for the local source")
    ] = None,
    url: Annotated[list[str] | None, typer.Option("--url", help="Direct links for the url source")] = None,
) -> None:
    """Sweep the sources for copies of PACKAGE and prove each one genuine or not."""

    def run() -> int:
        from kloner.hunt import DEFAULT_FAIL_ON, hostile, run_hunt
        from kloner.hunt import notify_webhook as notify
        from kloner.report import parse_formats
        from kloner.report.jsonout import build

        formats = parse_formats(fmt)
        fail = frozenset(x.strip().upper() for x in fail_on.split(",")) if fail_on else DEFAULT_FAIL_ON
        names = _sources(sources)
        if local and names is None:
            names = None
        rt = _runtime(proxy=proxy, user_agent=user_agent)
        try:
            rep = run_hunt(
                rt,
                package,
                sources=names,
                all_versions=all_versions,
                max_per_source=max_per_source,
                impersonators=impersonators,
                new_only=new_only,
                require_corroborated=require_corroborated,
                fail_on=fail,
                local_paths=list(local or []),
                urls=list(url or []),
            )
            code = _emit(rt, rep, out, formats)
            if notify_webhook and hostile(rep.reported()):
                doc = build(rep)
                err = notify(
                    notify_webhook,
                    {"run": doc["run"], "summary": doc["summary"], "coverage": doc["coverage"]["statement"]},
                    rt.user_agent(),
                )
                if err:
                    S.console.print(f"[yellow]note[/] {err}")
            return code
        finally:
            rt.close()

    raise typer.Exit(_guard(run))


@app.command()
def verify(
    paths: Annotated[list[Path], typer.Argument(exists=True)],
    package: Annotated[str | None, typer.Option("--package")] = None,
    fmt: Annotated[str, typer.Option("--format")] = "terminal",
    out: Annotated[Path | None, typer.Option("--out")] = None,
) -> None:
    """Evaluate local files. Without --package every brand profile is checked (SOC triage)."""

    def run() -> int:
        from kloner.hunt import run_verify
        from kloner.report import parse_formats

        rt = _runtime()
        try:
            rep = run_verify(rt, list(paths), package)
            return _emit(rt, rep, out, parse_formats(fmt))
        finally:
            rt.close()

    raise typer.Exit(_guard(run))


@app.command()
def fetch(
    urls: Annotated[list[str], typer.Argument()],
    package: Annotated[str | None, typer.Option("--package")] = None,
    fmt: Annotated[str, typer.Option("--format")] = "terminal",
    out: Annotated[Path | None, typer.Option("--out")] = None,
) -> None:
    """Fetch direct links (smishing, chats, websites) into the quarantine and evaluate them."""

    def run() -> int:
        from kloner.hunt import run_fetch
        from kloner.report import parse_formats

        rt = _runtime()
        try:
            rep = run_fetch(rt, list(urls), package)
            return _emit(rt, rep, out, parse_formats(fmt))
        finally:
            rt.close()

    raise typer.Exit(_guard(run))


@app.command()
def survey(
    package: str,
    sources: Annotated[str | None, typer.Option("--sources")] = None,
    max_per_source: Annotated[int, typer.Option("--max-per-source", min=1)] = 10,
) -> None:
    """Signer census of a package that has no anchor. Shows signers; never writes an anchor."""

    def run() -> None:
        from kloner.hunt import run_survey
        from kloner.util.fingerprints import short_fp

        rt = _runtime()
        try:
            rows, statuses, n = run_survey(rt, package, _sources(sources), max_per_source)
        finally:
            rt.close()
        if S.json:
            typer.echo(
                json.dumps(
                    {
                        "package": package,
                        "files": n,
                        "sources": [s.model_dump(mode="json") for s in statuses],
                        "signers": [
                            {
                                "cert_sha256": r.cert_sha256,
                                "subject": r.subject,
                                "apksig_verified": r.verified,
                                "known_key": r.known_key,
                                "samples": len(r.samples),
                                "versions": sorted(r.versions),
                                "sources": sorted(r.sources),
                            }
                            for r in rows
                        ],
                    },
                    indent=2,
                )
            )
            return
        S.console.print(
            f"Survey of {package}: {n} files · sources: " + ", ".join(f"{s.source} {s.status}" for s in statuses)
        )
        for r in rows:
            kk = f" KNOWN_PUBLIC_KEY:{r.known_key}" if r.known_key else ""
            S.console.print(
                f"{short_fp(r.cert_sha256)} {r.cert_sha256}  {len(r.samples)} file(s)  "
                f"{'verified' if r.verified else 'unverified'}{kk}  {r.subject or ''}"
            )
            S.console.print(f"    versions: {', '.join(sorted(r.versions))}  sources: {', '.join(sorted(r.sources))}")
        S.console.print(
            "No verdicts: a survey cannot tell which signer is official. Pin the official identity "
            f"through an official method, e.g.: kloner anchor add {package} --from-url <vendor-apk-url> "
            "--vendor-domain <vendor-domain>"
        )

    _guard(run)


@app.command()
def diff(
    sample: str,
    against: Annotated[str, typer.Option("--against")],
) -> None:
    """Forensic diff of one sample against another (sha256 in the quarantine, or a file)."""

    def run() -> None:
        from kloner.forensics.capabilities import capabilities
        from kloner.forensics.diff import diff_views
        from kloner.forensics.overlap import overlap
        from kloner.forensics.runner import Forensics

        rt = _runtime()

        def resolve(x: str) -> str:
            p = Path(x)
            if p.is_file():
                sha, _ = rt.quarantine.ingest_file(p, rt.config.limits.max_file_bytes)
                return sha
            if not rt.quarantine.has(x):
                raise ValueError(f"{x} is neither a file nor a sample in the quarantine")
            return x

        fx = Forensics(rt)
        a, b = resolve(sample), resolve(against)
        sv, rv = fx.view(a), fx.view(b)
        d = diff_views(sv, rv)
        caps = capabilities(d)
        cfg = rt.config.forensics
        ov = overlap(sv, rv, cfg.repackaged_min_jaccard, cfg.impostor_max_jaccard)
        if S.json:
            typer.echo(json.dumps({"diff": d, "capabilities": caps, "overlap": ov}, indent=2, sort_keys=True))
            return
        m = d["manifest"]
        S.console.print(f"[bold]{a[:12]} vs {b[:12]}[/]")
        S.console.print(
            f"Permissions +{len(m['permissions']['added'])} -{len(m['permissions']['removed'])}: "
            f"{', '.join(m['permissions']['added'][:20])}"
        )
        S.console.print(f"Components +{len(m['components_added'])} -{len(m['components_removed'])}")
        c = d["code"]
        S.console.print(
            f"Classes +{len(c['classes_added'])} -{len(c['classes_removed'])} ~{len(c['classes_modified'])}"
        )
        S.console.print(
            "New network indicators: "
            f"{sum(len(v) for k, v in c['new_indicators'].items() if k in ('urls', 'domains', 'ips'))}"
        )
        S.console.print(
            f"Code overlap (heuristic): classes {ov['j_class']:.2f}, resources {ov['j_res']:.2f}"
            + (f" → {ov['label']} range" if ov["label"] else "")
        )
        line = str(caps["line"])
        if ov["label"] == "IMPOSTOR":
            # The files share little code: what one has and the other lacks is its own code, not an injection.
            line = line.replace("Injected: ", "Only in the sample (different code base, not an injection): ", 1)
        S.console.print(line)

    _guard(run)


@app.command()
def explain(sample_sha256: str, run: Annotated[str | None, typer.Option("--run")] = None) -> None:
    """Print the full gate-by-gate trace of a sample's evaluation."""

    def go() -> None:
        from kloner.hunt import explain as do_explain
        from kloner.report.explain import render_explain

        rt = _runtime()
        data = do_explain(rt, sample_sha256, run)
        if S.json:
            typer.echo(json.dumps(data, indent=2, sort_keys=True, default=str))
        else:
            render_explain(data, S.console)

    _guard(go)


@app.command()
def reverify(run_id: str) -> None:
    """Recompute every verdict of a run offline and compare the canonical JSON byte for byte."""

    def go() -> int:
        from kloner.hunt import reverify as do_reverify

        rt = _runtime()
        try:
            ok, diffs, n = do_reverify(rt, run_id)
        finally:
            rt.close()
        if ok:
            S.console.print(f"[green]IDENTICAL[/] {n} verdict(s) of run {run_id} reproduced byte for byte")
            return 0
        for d in diffs:
            S.console.print(f"[red]DIFFERS[/] {d}")
        return 1

    raise typer.Exit(_guard(go))


@app.command()
def report(
    run_id: str,
    fmt: Annotated[str, typer.Option("--format")] = "md",
    out: Annotated[Path | None, typer.Option("--out")] = None,
) -> None:
    """Re-render the report of a past run."""

    def go() -> None:
        from kloner.report import FILE_NAMES, parse_formats

        rt = _runtime()
        meta = rt.db.run_meta(run_id)
        if meta is None:
            raise ValueError(f"unknown run {run_id}; list runs in {S.home / 'runs'}")
        src = Path(meta["report_dir"]) / "report.json"
        if not src.is_file():
            raise ValueError(f"the run's JSON report is missing ({src})")
        doc = json.loads(src.read_text(encoding="utf-8"))
        from kloner.report import html, ioc, markdown, stix

        for f in parse_formats(fmt):
            renderers: dict[str, Callable[[dict[str, Any]], str]] = {
                "md": markdown.render,
                "html": html.render,
                "csv": ioc.samples_csv,
                "iocs": ioc.iocs_txt,
                "stix21": stix.bundle,
                "json": lambda d: json.dumps(d, indent=2, sort_keys=True),
            }
            if f == "terminal":
                from kloner.report.terminal import render

                render(doc, S.console)
                continue
            text = renderers[f](doc)
            if out:
                out.write_text(text, encoding="utf-8")
                S.console.print(f"Wrote {out}")
            else:
                dest = Path(meta["report_dir"]) / FILE_NAMES[f]
                dest.write_text(text, encoding="utf-8")
                S.console.print(f"Wrote {dest}")

    _guard(go)


@export_app.command("samples")
def export_samples(
    run: Annotated[str, typer.Option("--run")],
    # The malware-handling convention, not a secret (section 8.4).
    zip_password: Annotated[str, typer.Option("--zip-password")] = "infected",  # noqa: S107  # nosec B107
    out: Annotated[Path | None, typer.Option("--out")] = None,
) -> None:
    """Package a run's hostile samples for analyst sharing (password-protected ZIP, on explicit request)."""

    def go() -> None:
        from kloner.export import export_samples as do_export

        rt = _runtime()
        path, n = do_export(rt, run, zip_password, out)
        S.console.print(f"Wrote {n} sample(s) to {path} (password '{zip_password}'). Never run or install them.")

    _guard(go)


# --------------------------------------------------------------------------------------------
# intel
# --------------------------------------------------------------------------------------------


@intel_app.command("signer")
def intel_signer(cert_sha256: str) -> None:
    """Every package and sample a certificate signed."""
    _guard(lambda: _intel_rows("signer", cert_sha256))


@intel_app.command("payload")
def intel_payload(payload_id: str) -> None:
    """Every sample that carries a payload (payload_id or shape_id)."""
    _guard(lambda: _intel_rows("payload", payload_id))


@intel_app.command("package")
def intel_package(package: str) -> None:
    """Every sample of a package across runs."""
    _guard(lambda: _intel_rows("package", package))


@intel_app.command("sources")
def intel_sources() -> None:
    """Per source: GENUINE, hostile and invalid counts and metadata mismatches over time."""
    _guard(lambda: _intel_rows("sources", ""))


def _intel_rows(kind: str, key: str) -> None:
    rt = _runtime()
    db = rt.db
    rows = {
        "signer": lambda: db.signer_census(key),
        "payload": lambda: db.payload_census(key),
        "package": lambda: db.package_census(key),
        "sources": db.source_census,
    }[kind]()
    data = [dict(r) for r in rows]
    if S.json:
        typer.echo(json.dumps(data, indent=2, default=str))
        return
    if not data:
        S.console.print("No records.")
    for r in data:
        S.console.print("  ".join(f"{k}={v}" for k, v in r.items()))


def main() -> None:
    try:
        app()
    except SystemExit as e:
        exit_keeping_code(e.code)
    exit_keeping_code(0)


def exit_keeping_code(code: str | int | None) -> NoReturn:
    """Exit with the run's own code even when the reader closed stdout early (``kloner … | head``).

    Python would turn the failed final flush into exit status 120, which is not a KLONER exit code;
    CI depends on 0/10/11. Reports and the database are already written at this point.
    """
    try:
        sys.stdout.flush()
    except (BrokenPipeError, ValueError):
        with contextlib.suppress(OSError, ValueError):
            devnull = os.open(os.devnull, os.O_WRONLY)
            os.dup2(devnull, sys.stdout.fileno())
    sys.exit(code)


if __name__ == "__main__":
    main()
