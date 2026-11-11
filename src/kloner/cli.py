"""Command-line interface (§13). Simple on the outside, rigorous on the inside.

Every error message ends with the next command to run. Exit codes: 0 clean, 10 hostile, 11 review,
2 usage/configuration, 3 anchor conflict or hygiene, 4 verifier unavailable, 5 internal error.
The screens are drawn by ``kloner.ui`` and the report renderers (D-069); ``--json`` output is unchanged by them.
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
import typer.rich_utils as _typer_rich
from rich.console import Console, Group
from rich.text import Text
from typer.core import TyperGroup

from kloner import __version__, ui
from kloner.config import DEFAULT_CONFIG_TOML, default_home
from kloner.util.timeutil import run_id as make_run_id

if TYPE_CHECKING:
    from kloner.app import Runtime

# --------------------------------------------------------------------------------------------
# help screens: KLONER's greens, commands grouped by the three steps of the workflow (D-069)
# --------------------------------------------------------------------------------------------

_typer_rich.STYLE_OPTION = f"bold {ui.BRIGHT}"
_typer_rich.STYLE_SWITCH = f"bold {ui.GREEN}"
_typer_rich.STYLE_NEGATIVE_OPTION = f"bold {ui.AMBER}"
_typer_rich.STYLE_NEGATIVE_SWITCH = f"bold {ui.AMBER}"
_typer_rich.STYLE_TYPES = ui.MUTED
_typer_rich.STYLE_TYPES_SEPARATOR = ui.MUTED
_typer_rich.STYLE_USAGE = f"bold {ui.GREEN}"
_typer_rich.STYLE_USAGE_COMMAND = f"bold {ui.BRIGHT}"
_typer_rich.STYLE_HELPTEXT_FIRST_LINE = f"bold {ui.PALE}"
_typer_rich.STYLE_HELPTEXT = ui.SOFT
_typer_rich.STYLE_OPTION_HELP = ui.SOFT
_typer_rich.STYLE_OPTION_DEFAULT = ui.MUTED
_typer_rich.STYLE_OPTION_ENVVAR = ui.MUTED
_typer_rich.STYLE_REQUIRED_SHORT = ui.RED
_typer_rich.STYLE_REQUIRED_LONG = ui.RED
_typer_rich.STYLE_OPTIONS_PANEL_BORDER = ui.BORDER
_typer_rich.STYLE_COMMANDS_PANEL_BORDER = ui.GREEN
_typer_rich.STYLE_COMMANDS_TABLE_FIRST_COLUMN = f"bold {ui.BRIGHT}"
_typer_rich.STYLE_ERRORS_PANEL_BORDER = ui.RED
_typer_rich.STYLE_ERRORS_SUGGESTION = ui.MUTED
_typer_rich.STYLE_ABORTED = ui.RED
_typer_rich.RICH_HELP = f"Try [bold {ui.BRIGHT}]'{{command_path}} {{help_option}}'[/] for help."

STEP1 = "Step 1 · Anchor — pin the official signing identity"
STEP2 = "Step 2 · Hunt — find copies and prove each one"
STEP3 = "Step 3 · Inspect — understand one copy"
SETUP = "Setup and health"
INTEL = "Intel and sharing"
_G, _B, _P, _M = ui.GREEN, ui.BRIGHT, ui.PALE, ui.MUTED

MAIN_HELP = f"""Find forged, trojanized and tampered copies of any Android app, and prove every verdict.

[bold {_B}]How it works[/]
[bold {_G}]1  Anchor[/]   pin the vendor's real signing key, once, from an official source
   [{_P}]kloner anchor add <package> --from-url <official-apk-url> --vendor-domain <domain>[/]
[bold {_G}]2  Hunt[/]     sweep stores and mirrors for copies; every copy gets a verdict
   [{_P}]kloner hunt <package>[/]
[bold {_G}]3  Inspect[/]  understand one copy: why it got its verdict, and what it changed
   [{_P}]kloner explain <sha256>[/]    [{_P}]kloner diff <sha256> --against <official-sha256>[/]

[{_M}]First time? Run [bold {_P}]kloner setup[/], then [bold {_P}]kloner doctor[/].
Nothing KLONER downloads is ever installed or run.[/]"""


def _examples(*lines: str) -> str:
    return f"[bold {_B}]Examples[/]\n" + "\n".join(f"  [{_P}]{x}[/]" for x in lines)


class _StepOrder(TyperGroup):
    """Lists the commands in the order of the workflow: anchor, hunt, inspect, then setup and intel."""

    ORDER = (
        "anchor",
        "hunt",
        "verify",
        "fetch",
        "survey",
        "explain",
        "diff",
        "report",
        "reverify",
        "setup",
        "doctor",
        "selftest",
        "intel",
        "export",
    )

    def list_commands(self, ctx: Any) -> list[str]:
        names = list(self.commands)
        return sorted(names, key=lambda n: self.ORDER.index(n) if n in self.ORDER else len(self.ORDER))


app = typer.Typer(
    cls=_StepOrder,
    add_completion=False,
    no_args_is_help=True,
    rich_markup_mode="rich",
    help=MAIN_HELP,
)
anchor_app = typer.Typer(
    no_args_is_help=True,
    rich_markup_mode="rich",
    help="Pin, show and manage official signing identities (anchors).\n\n"
    "An anchor is the vendor's real signing key for one package, with the evidence for it. It is the only source "
    "of trust: nothing seen on a mirror can ever add a key.",
    epilog=_examples(
        "kloner anchor add org.thoughtcrime.securesms --from-url <official-apk-url> --vendor-domain signal.org",
        "kloner anchor add org.wikipedia --from-assetlinks en.wikipedia.org",
        "kloner anchor show org.wikipedia",
    ),
)
intel_app = typer.Typer(
    no_args_is_help=True,
    rich_markup_mode="rich",
    help="Correlations across runs: who signed what, shared payloads, source quality.",
)
export_app = typer.Typer(
    no_args_is_help=True,
    rich_markup_mode="rich",
    help="Package a run's hostile samples for analysts (a password-protected ZIP).",
)
app.add_typer(anchor_app, name="anchor", rich_help_panel=STEP1)
app.add_typer(intel_app, name="intel", rich_help_panel=INTEL)
app.add_typer(export_app, name="export", rich_help_panel=INTEL)

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
    home: Annotated[
        Path | None,
        typer.Option(
            "--home", help="Where KLONER keeps anchors, the quarantine, the database and runs (default ~/.kloner)."
        ),
    ] = None,
    json_out: Annotated[bool, typer.Option("--json", help="Machine-readable JSON instead of the screen.")] = False,
    quiet: Annotated[
        bool, typer.Option("--quiet", help="No screen output; errors still print, and --json is unaffected.")
    ] = False,
    debug: Annotated[
        bool, typer.Option("--debug", help="Show tracebacks of internal errors and log debug detail.")
    ] = False,
    no_color: Annotated[
        bool, typer.Option("--no-color", help="Plain text without colors (NO_COLOR works too).")
    ] = False,
    workers: Annotated[
        int | None, typer.Option("--workers", min=1, max=64, help="Parallel verification workers (default: config).")
    ] = None,
    rate: Annotated[
        float | None, typer.Option("--rate", help="Requests per second per host (default: config).")
    ] = None,
    version: Annotated[bool, typer.Option("--version", help="Print the version and exit.")] = False,
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


def _working(message: str) -> contextlib.AbstractContextManager[None]:
    """A spinner on stderr while a long step runs; never with --json or --quiet, never on stdout."""
    return ui.working(message, enabled=not (S.json or S.quiet))


def _note_to_stderr(text: str) -> None:
    """With --json, stdout carries the JSON document alone; human notes go to stderr."""
    Console(stderr=True, highlight=False, soft_wrap=True, no_color=S.no_color).print(
        Text.assemble(("note: ", f"bold {ui.AMBER}"), (text, ui.SOFT))
    )


def _fail(msg: str, code: int) -> None:
    Console(stderr=True, highlight=False, soft_wrap=True).print(
        Text.assemble(("✗ error: ", f"bold {ui.RED}"), (msg, ui.PALE))
    )
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


def _status_rows(rows: list[tuple[str, str, str, str]]) -> None:
    """A PASS/WARN/FAIL table: status, component, detail, and the fix under it when there is one."""
    t = ui.table()
    t.add_column("STATUS", no_wrap=True)
    t.add_column("CHECK", no_wrap=True, style=f"bold {ui.PALE}")
    t.add_column("DETAIL", overflow="fold", style=ui.SOFT)
    for status, name, detail, fix in rows:
        icon = ui.STATUS.get(status, ("•", ""))[0]
        style = {"PASS": ui.GREEN, "WARN": ui.AMBER, "FAIL": ui.RED}.get(status, ui.SOFT)
        cell: Text | Group = Text(detail, style=ui.SOFT)
        if fix:
            cell = Group(Text(detail, style=ui.SOFT), Text.assemble(("fix: ", f"bold {ui.AMBER}"), (fix, ui.PALE)))
        t.add_row(Text(f"{icon} {status}", style=f"bold {style}"), name, cell)
    S.console.print(t)


def _status_summary(statuses: list[str]) -> Text:
    parts = []
    for word, color in (("PASS", ui.GREEN), ("WARN", ui.AMBER), ("FAIL", ui.RED)):
        n = statuses.count(word)
        icon = ui.STATUS[word][0]
        parts.append(Text.assemble((f"{icon} ", color), (f"{n} ", f"bold {ui.PALE}"), (word, color)))
    return Text("   ").join(parts)


# --------------------------------------------------------------------------------------------
# setup / doctor / selftest
# --------------------------------------------------------------------------------------------


@app.command(rich_help_panel=SETUP, epilog=_examples("kloner setup", "kloner setup --accept-android-sdk-license"))
def setup(
    accept_android_sdk_license: Annotated[
        bool,
        typer.Option(
            help="Accept the Android SDK License Agreement for the pinned packages without a prompt. Read it first: "
            "https://developer.android.com/studio/terms"
        ),
    ] = False,
    upgrade: Annotated[bool, typer.Option(help="Re-resolve and re-pin every component.")] = False,
    no_apkeep: Annotated[
        bool, typer.Option("--no-apkeep", help="Do not download apkeep (apkpure and googleplay stay disabled).")
    ] = False,
) -> None:
    """Install and pin the toolchain: the JDK check, Android build-tools, the apksig bridge and apkeep.

    Run it once on a new machine, then [bold]kloner doctor[/].
    """

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
        rows = [
            ("PASS", "JDK", tc.java_version, ""),
            ("PASS", "build-tools", f"{tc.build_tools_version} at {tc.build_tools}", ""),
            ("PASS", "apksig", tc.apksig_version, ""),
            ("PASS", "bridge", f"compiled: {tc.bridge_classes}", ""),
        ]
        if tc.apkeep and tc.apkeep_error:
            rows.append(("WARN", "apkeep", f"{tc.apkeep} cannot run on this system ({tc.apkeep_error})", ""))
        else:
            rows.append(("PASS" if tc.apkeep else "WARN", "apkeep", tc.apkeep or "not installed", ""))
        ui.heading(S.console, "setup")
        S.console.print()
        _status_rows(rows)
        for n in notes:
            ui.note(S.console, n)
        ui.next_steps(S.console, [("kloner doctor", "check every component, the bridge and the sources")])

    _guard(run)


@app.command(rich_help_panel=SETUP, epilog=_examples("kloner doctor", "kloner --json doctor"))
def doctor() -> None:
    """Check every component, the bridge round-trip, permissions and source reachability, each with a fix."""

    def run() -> None:
        from kloner.doctor import run_doctor

        rt = _runtime()
        with _working("Checking every component and source…"):
            checks = run_doctor(rt)
        if S.json:
            typer.echo(json.dumps([c.__dict__ for c in checks], indent=2))
        else:
            ui.heading(S.console, "doctor")
            S.console.print()
            _status_rows([(c.status, c.name, c.detail, c.fix or "") for c in checks])
            statuses = [c.status for c in checks]
            blocked = any(c.status == "FAIL" and c.critical for c in checks)
            S.console.print()
            verdict = (
                Text("✗ Not ready: fix the FAIL lines above.", style=f"bold {ui.RED}")
                if blocked
                else (
                    Text("✓ Ready, with warnings: read the WARN lines above.", style=f"bold {ui.AMBER}")
                    if "WARN" in statuses or "FAIL" in statuses
                    else Text("✓ Ready.", style=f"bold {ui.GREEN}")
                )
            )
            S.console.print(Text.assemble(_status_summary(statuses), ("     ", ""), verdict))
            if blocked:
                ui.next_steps(S.console, [("kloner setup", "install or repair the toolchain")])
            else:
                ui.next_steps(
                    S.console,
                    [
                        ("kloner selftest", "prove the whole pipeline on KLONER's own test files"),
                        (
                            "kloner anchor add <package> --from-url <official-apk-url> --vendor-domain <domain>",
                            "step 1: pin the official identity of the app you want to protect",
                        ),
                    ],
                )
        if any(c.status == "FAIL" and c.critical for c in checks):
            raise typer.Exit(EXIT_VERIFIER)

    _guard(run)


@app.command(
    rich_help_panel=SETUP, epilog=_examples("kloner selftest --quick", "kloner selftest", "kloner selftest --full")
)
def selftest(
    quick: Annotated[bool, typer.Option("--quick", help="Core cases only, the fastest check.")] = False,
    full: Annotated[bool, typer.Option("--full", help="Everything, with larger property and fuzz budgets.")] = False,
) -> None:
    """Rebuild the synthetic test corpus from KLONER's own fixtures and check every expected verdict."""

    def run() -> None:
        from kloner.selftest.runner import run_selftest

        rt = _runtime()
        ui.heading(S.console, "selftest", "full" if full else ("quick" if quick else "standard"))
        ok = run_selftest(rt, mode="full" if full else ("quick" if quick else "standard"), console=S.console)
        raise typer.Exit(0 if ok else 1)

    _guard(run)


# --------------------------------------------------------------------------------------------
# anchors
# --------------------------------------------------------------------------------------------

_METHOD = "Official method (choose exactly one)"
_BRAND = "Brand profile (for the impersonation sweep)"
_SECOND = "A second official identity"


@anchor_app.command(
    "add",
    context_settings={"allow_extra_args": False},
    epilog=_examples(
        "kloner anchor add org.thoughtcrime.securesms --from-url <official-apk-url> --vendor-domain signal.org",
        "kloner anchor add org.thoughtcrime.securesms --from-fingerprint <sha256> --evidence-url https://signal.org/android/apk/",
        "kloner anchor add org.wikipedia --from-assetlinks en.wikipedia.org",
        "kloner anchor add org.wikipedia --from-fdroid",
        "kloner anchor add com.duckduckgo.mobile.android --from-fdroid --declare-additional-identity "
        "--reason 'F-Droid signs its own builds' --label f-droid",
    ),
)
def anchor_add(
    package: Annotated[str, typer.Argument(help="Android package name, for example org.thoughtcrime.securesms.")],
    extra_fingerprints: Annotated[
        list[str] | None, typer.Argument(help="More fingerprints after --from-fingerprint.")
    ] = None,
    from_device: Annotated[
        bool,
        typer.Option(
            "--from-device",
            help="The app installed from an official store on a USB device (adb).",
            rich_help_panel=_METHOD,
        ),
    ] = False,
    serial: Annotated[
        str | None, typer.Option("--serial", help="Which device, when several are connected.", rich_help_panel=_METHOD)
    ] = None,
    from_play: Annotated[
        bool,
        typer.Option(
            "--from-play",
            help="Google Play through apkeep (needs KLONER_PLAY_EMAIL and KLONER_PLAY_AAS_TOKEN).",
            rich_help_panel=_METHOD,
        ),
    ] = False,
    from_url: Annotated[
        str | None,
        typer.Option(
            "--from-url",
            help="The vendor's own APK over HTTPS; every redirect must stay inside --vendor-domain.",
            rich_help_panel=_METHOD,
        ),
    ] = None,
    vendor_domain: Annotated[
        list[str] | None,
        typer.Option(
            "--vendor-domain", help="The domain --from-url must stay in (repeatable).", rich_help_panel=_METHOD
        ),
    ] = None,
    from_fingerprint: Annotated[
        list[str] | None,
        typer.Option(
            "--from-fingerprint",
            help="A SHA-256 certificate fingerprint the vendor publishes (more may follow as arguments).",
            rich_help_panel=_METHOD,
        ),
    ] = None,
    evidence_url: Annotated[
        str | None,
        typer.Option(
            "--evidence-url", help="The vendor's HTTPS page that lists those fingerprints.", rich_help_panel=_METHOD
        ),
    ] = None,
    from_assetlinks: Annotated[
        str | None,
        typer.Option(
            "--from-assetlinks",
            help="The vendor domain whose /.well-known/assetlinks.json names the app's key.",
            rich_help_panel=_METHOD,
        ),
    ] = None,
    from_fdroid: Annotated[
        bool,
        typer.Option("--from-fdroid", help="F-Droid's signed repository index and its build.", rich_help_panel=_METHOD),
    ] = False,
    from_apk: Annotated[
        Path | None,
        typer.Option(
            "--from-apk",
            exists=True,
            dir_okay=False,
            help="A local APK. Its origin cannot be proven: the anchor stays USER_ASSERTED.",
            rich_help_panel=_METHOD,
        ),
    ] = None,
    label: Annotated[
        str | None,
        typer.Option("--label", help="A short name for a new identity, for example f-droid.", rich_help_panel=_SECOND),
    ] = None,
    brand_label: Annotated[
        list[str] | None,
        typer.Option(
            "--brand-label",
            help="A brand-distinctive app name; only these count for EXACT_LABEL (repeatable).",
            rich_help_panel=_BRAND,
        ),
    ] = None,
    brand_keyword: Annotated[
        list[str] | None,
        typer.Option(
            "--brand-keyword",
            help="A search term for sources that search by name (repeatable).",
            rich_help_panel=_BRAND,
        ),
    ] = None,
    declare_additional_identity: Annotated[
        bool,
        typer.Option(
            "--declare-additional-identity",
            help="Record evidence that shares no key with the anchor as a second official identity.",
            rich_help_panel=_SECOND,
        ),
    ] = False,
    reason: Annotated[
        str | None,
        typer.Option(
            "--reason", help="Why the second identity is legitimate; required with it.", rich_help_panel=_SECOND
        ),
    ] = None,
) -> None:
    """Create or extend the anchor of PACKAGE from one official provenance method.

    Step 1: the anchor pins the keys a GENUINE copy must be signed with.
    Two independent official methods make it CORROBORATED.
    Evidence that shares no key with the anchor is a CONFLICT, and nothing is written.
    """

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
        with _working(f"Collecting the official identity of {package}…"):
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

        render_anchor(anchor, S.console, as_json=S.json, command="anchor add")
        if S.json:  # stdout carries the JSON alone; the notes go to stderr
            for n in notes:
                _note_to_stderr(n)
            return
        if notes:
            S.console.print()
        for n in notes:
            ui.note(S.console, n)
        ui.next_steps(
            S.console, [(f"kloner hunt {package}", "step 2: sweep stores and mirrors for copies, and prove each one")]
        )

    _guard(run)


@anchor_app.command(
    "show", epilog=_examples("kloner anchor show org.wikipedia", "kloner --json anchor show org.wikipedia")
)
def anchor_show(package: Annotated[str, typer.Argument(help="The package whose anchor to show.")]) -> None:
    """Show an anchor: identities, evidence, lineage, releases, brand and the record hash."""

    def run() -> None:
        from kloner.hunt import UsageError
        from kloner.report.anchor import render_anchor

        rt = _runtime()
        a = rt.anchors.get(package)
        if a is None:
            raise UsageError(f"no anchor for {package}. Create one: kloner anchor add {package} --from-url …")
        render_anchor(a, S.console, as_json=S.json, command="anchor show")

    _guard(run)


@anchor_app.command("list")
def anchor_list() -> None:
    """List every anchor with its trust level."""

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
        ui.heading(S.console, "anchor list")
        S.console.print()
        if not rows:
            S.console.print(Text("No anchors yet.", style=ui.SOFT))
            ui.next_steps(
                S.console,
                [
                    (
                        "kloner anchor add <package> --from-url <official-apk-url> --vendor-domain <domain>",
                        "step 1: pin the official identity of an app",
                    )
                ],
            )
            return
        t = ui.table("PACKAGE", "TRUST", "IDENTITIES", "RECORD")
        for a in rows:
            t.add_row(
                Text(a.package, style=f"bold {ui.PALE}"),
                ui.corroboration_pill(a.corroboration),
                str(len(a.identities)),
                Text(f"#{a.record_sha256[:12]}", style=ui.SOFT),
            )
        S.console.print(t)

    _guard(run)


@anchor_app.command(
    "refresh", epilog=_examples("kloner anchor refresh org.wikipedia", "kloner anchor refresh org.wikipedia --accept")
)
def anchor_refresh(
    package: Annotated[str, typer.Argument(help="The package whose anchor to refresh.")],
    accept: Annotated[bool, typer.Option("--accept", help="Write the result; without it nothing is written.")] = False,
) -> None:
    """Re-run the automatic methods recorded in the anchor and show what changed."""

    def run() -> None:
        from kloner.anchor.lifecycle import refresh

        rt = _runtime()
        ui.heading(S.console, "anchor refresh", package)
        S.console.print()
        changed = refresh(rt, package, accept=accept, console=S.console)
        if changed and not accept:
            ui.next_steps(
                S.console,
                [(f"kloner anchor refresh {package} --accept", "only if the change is expected: nothing was written")],
            )

    _guard(run)


@anchor_app.command("export")
def anchor_export(
    package: Annotated[str, typer.Argument(help="The package whose anchor to export.")],
    file: Annotated[Path, typer.Argument(help="The JSON file to write.")],
) -> None:
    """Export an anchor as portable JSON."""

    def run() -> None:
        from kloner.anchor.lifecycle import export_anchor

        rt = _runtime()
        export_anchor(rt, package, file)
        ui.done(S.console, f"Exported {package} to {file}.")
        ui.next_steps(
            S.console, [(f"kloner anchor import {file}", "on another machine: hygiene and the hash are re-checked")]
        )

    _guard(run)


@anchor_app.command("import")
def anchor_import(
    file: Annotated[
        Path, typer.Argument(exists=True, dir_okay=False, help="An anchor JSON from kloner anchor export.")
    ],
) -> None:
    """Import an anchor; hygiene is re-validated and the hash recomputed."""

    def run() -> None:
        from kloner.anchor.lifecycle import import_anchor
        from kloner.report.anchor import render_anchor

        rt = _runtime()
        a = import_anchor(rt, file)
        render_anchor(a, S.console, as_json=S.json, command="anchor import")

    _guard(run)


@anchor_app.command("adopt-rotation")
def anchor_adopt_rotation(
    package: Annotated[str, typer.Argument(help="The anchored package.")],
    sample_sha256: Annotated[str, typer.Argument(help="A GENUINE sample whose v3 lineage proves the rotation.")],
) -> None:
    """Persist a key rotation proven (R1/R2) by a specific GENUINE sample."""

    def run() -> None:
        from kloner.anchor.lifecycle import adopt_rotation
        from kloner.report.anchor import render_anchor

        rt = _runtime()
        a = adopt_rotation(rt, package, sample_sha256)
        render_anchor(a, S.console, as_json=S.json, command="anchor adopt-rotation")

    _guard(run)


# --------------------------------------------------------------------------------------------
# hunt / verify / fetch / survey
# --------------------------------------------------------------------------------------------

_SWEEP = "What to sweep"
_OUTPUT = "Output"
_NETWORK = "Network"
_FORMATS = "Comma-separated: terminal, json, md, html, csv, iocs, stix21."


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


@app.command(
    rich_help_panel=STEP2,
    epilog=_examples(
        "kloner hunt org.thoughtcrime.securesms",
        "kloner hunt org.wikipedia --all-versions --impersonators",
        "kloner hunt org.thoughtcrime.securesms --sources url,fdroid --url <official-apk-url>",
        "kloner hunt com.example.app --sources local --local ./downloads",
    ),
)
def hunt(
    package: Annotated[str, typer.Argument(help="The anchored package to hunt, for example org.wikipedia.")],
    sources: Annotated[
        str | None,
        typer.Option(
            "--sources",
            help="Comma-separated: local, url, apkpure, aptoide, fdroid, huawei, googleplay (default: enabled ones).",
            rich_help_panel=_SWEEP,
        ),
    ] = None,
    all_versions: Annotated[
        bool,
        typer.Option(
            "--all-versions", help="Every version the sources offer, not only the latest.", rich_help_panel=_SWEEP
        ),
    ] = False,
    max_per_source: Annotated[
        int,
        typer.Option(
            "--max-per-source",
            min=1,
            help="At most this many files per source (local and url are not capped).",
            rich_help_panel=_SWEEP,
        ),
    ] = 10,
    impersonators: Annotated[
        bool,
        typer.Option(
            "--impersonators",
            help="Also look for other packages that copy the brand: icon, label, lookalike names.",
            rich_help_panel=_SWEEP,
        ),
    ] = False,
    new_only: Annotated[
        bool, typer.Option("--new-only", help="Report only files no earlier run has seen.", rich_help_panel=_SWEEP)
    ] = False,
    require_corroborated: Annotated[
        bool,
        typer.Option(
            "--require-corroborated", help="Refuse to run unless the anchor is CORROBORATED.", rich_help_panel=_SWEEP
        ),
    ] = False,
    proxy: Annotated[
        str | None, typer.Option("--proxy", help="Send source requests through this proxy.", rich_help_panel=_NETWORK)
    ] = None,
    user_agent: Annotated[
        str | None, typer.Option("--user-agent", help="Override for multi-vantage tests.", rich_help_panel=_NETWORK)
    ] = None,
    out: Annotated[
        Path | None,
        typer.Option(
            "--out", help="Folder for the report files (default: <home>/runs/<run id>).", rich_help_panel=_OUTPUT
        ),
    ] = None,
    fmt: Annotated[
        str, typer.Option("--format", help=_FORMATS, rich_help_panel=_OUTPUT)
    ] = "terminal,json,md,html,iocs",
    fail_on: Annotated[
        str | None,
        typer.Option(
            "--fail-on",
            help="Verdicts that set exit code 10 (default: TAMPERED, FORGED, IMPERSONATOR).",
            rich_help_panel=_OUTPUT,
        ),
    ] = None,
    notify_webhook: Annotated[
        str | None,
        typer.Option(
            "--notify-webhook",
            help="POST the run summary to this URL when hostile copies are found.",
            rich_help_panel=_OUTPUT,
        ),
    ] = None,
    local: Annotated[
        list[Path] | None,
        typer.Option("--local", help="Files or folders for the local source.", rich_help_panel=_SWEEP),
    ] = None,
    url: Annotated[
        list[str] | None,
        typer.Option("--url", help="Direct links for the url source (repeatable).", rich_help_panel=_SWEEP),
    ] = None,
) -> None:
    """Sweep the sources for copies of PACKAGE and prove each one genuine or not.

    Step 2: it needs an anchor first (kloner anchor add).
    Every file goes into the quarantine; nothing is ever installed or run.
    Each file is judged against the anchor with the cryptography Android itself uses.
    """

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
            with _working(f"Hunting copies of {package}: sweeping the sources and verifying every file…"):
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
                if err and S.json:
                    _note_to_stderr(err)
                elif err:
                    ui.note(S.console, err)
            return code
        finally:
            rt.close()

    raise typer.Exit(_guard(run))


@app.command(
    rich_help_panel=STEP2,
    epilog=_examples(
        "kloner verify ./suspicious.apk --package org.thoughtcrime.securesms", "kloner verify ./inbox/*.apk"
    ),
)
def verify(
    paths: Annotated[list[Path], typer.Argument(exists=True, help="APK, XAPK, APKM, APKS or ZIP files, or folders.")],
    package: Annotated[
        str | None,
        typer.Option(
            "--package", help="Judge against this package's anchor; without it every anchored brand is checked."
        ),
    ] = None,
    fmt: Annotated[str, typer.Option("--format", help=_FORMATS)] = "terminal",
    out: Annotated[Path | None, typer.Option("--out", help="Folder for the report files.")] = None,
) -> None:
    """Evaluate files you already have. Without --package every brand profile is checked (SOC triage)."""

    def run() -> int:
        from kloner.hunt import run_verify
        from kloner.report import parse_formats

        rt = _runtime()
        try:
            with _working("Verifying…"):
                rep = run_verify(rt, list(paths), package)
            return _emit(rt, rep, out, parse_formats(fmt))
        finally:
            rt.close()

    raise typer.Exit(_guard(run))


@app.command(
    rich_help_panel=STEP2, epilog=_examples("kloner fetch https://example.com/app.apk --package com.example.app")
)
def fetch(
    urls: Annotated[list[str], typer.Argument(help="Direct download links.")],
    package: Annotated[str | None, typer.Option("--package", help="Judge against this package's anchor.")] = None,
    fmt: Annotated[str, typer.Option("--format", help=_FORMATS)] = "terminal",
    out: Annotated[Path | None, typer.Option("--out", help="Folder for the report files.")] = None,
) -> None:
    """Fetch direct links (smishing, chats, websites) into the quarantine and evaluate them."""

    def run() -> int:
        from kloner.hunt import run_fetch
        from kloner.report import parse_formats

        rt = _runtime()
        try:
            with _working("Fetching into the quarantine and verifying…"):
                rep = run_fetch(rt, list(urls), package)
            return _emit(rt, rep, out, parse_formats(fmt))
        finally:
            rt.close()

    raise typer.Exit(_guard(run))


@app.command(
    rich_help_panel=STEP2, epilog=_examples("kloner survey com.spotify.music --sources aptoide --max-per-source 20")
)
def survey(
    package: Annotated[str, typer.Argument(help="Any package, anchored or not.")],
    sources: Annotated[
        str | None, typer.Option("--sources", help="Comma-separated sources (default: the enabled ones).")
    ] = None,
    max_per_source: Annotated[
        int, typer.Option("--max-per-source", min=1, help="At most this many files per source.")
    ] = 10,
) -> None:
    """Signer census of a package that has no anchor. Shows who signs the copies; never writes an anchor."""

    def run() -> None:
        from kloner.hunt import run_survey

        rt = _runtime()
        try:
            with _working(f"Surveying the signers of {package}…"):
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
        ui.heading(S.console, "survey", package)
        S.console.print()
        chips = Text("    ").join(
            ui.source_chip(s.source, s.status, f"{s.fetched}/{s.offers}" if s.status == "OK" else "") for s in statuses
        )
        ui.kv(S.console, [("Files", str(n)), ("Sources", chips)])
        ui.section(S.console, "Signers", "every key that signed a copy, most files first")
        t = ui.table()
        t.add_column("SIGNER (SHA-256)", overflow="fold", max_width=34, style=f"bold {ui.PALE}")
        t.add_column("FILES", justify="right", no_wrap=True)
        t.add_column("VERIFIED", no_wrap=True)
        t.add_column("SUBJECT", overflow="fold", style=ui.SOFT)
        t.add_column("VERSIONS", overflow="fold", style=ui.SOFT)
        t.add_column("SOURCES", overflow="fold", style=ui.SOFT)
        for r in rows:
            verified = (
                Text("✓ verified", style=f"bold {ui.GREEN}")
                if r.verified
                else Text("✗ unverified", style=f"bold {ui.RED}")
            )
            subject = Text(r.subject or "", style=ui.SOFT)
            if r.known_key:
                subject.append(f"  KNOWN_PUBLIC_KEY:{r.known_key}", style=f"bold {ui.RED}")
            t.add_row(
                r.cert_sha256,
                str(len(r.samples)),
                verified,
                subject,
                ", ".join(sorted(r.versions)),
                ", ".join(sorted(r.sources)),
            )
        if rows:
            S.console.print(t)
        else:
            S.console.print(Text("  No signed files found.", style=ui.MUTED))
        S.console.print()
        S.console.print(
            ui.panel(
                Text(
                    "A survey cannot tell which signer is official. Pin the official identity through an official "
                    "method; then a hunt gives every copy a verdict.",
                    style=ui.SOFT,
                ),
                "No verdicts",
                tone="review",
            )
        )
        ui.next_steps(
            S.console,
            [(f"kloner anchor add {package} --from-url <vendor-apk-url> --vendor-domain <vendor-domain>", "step 1")],
        )

    _guard(run)


@app.command(
    rich_help_panel=STEP3,
    epilog=_examples(
        "kloner diff <suspicious-sha256> --against <official-sha256>",
        "kloner diff ./suspicious.apk --against ./official.apk",
    ),
)
def diff(
    sample: Annotated[str, typer.Argument(help="The copy to examine: a file, or a sha256 in the quarantine.")],
    against: Annotated[
        str, typer.Option("--against", help="The reference, usually the official build: a file or a sha256.")
    ],
) -> None:
    """Compare a copy with another build, usually the official one: what it adds, removes and changes."""

    def run() -> None:
        from kloner.forensics.capabilities import DISPLAY, capabilities, for_overlap
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
        with _working("Unpacking both files in a sandboxed worker and comparing them…"):
            a, b = resolve(sample), resolve(against)
            sv, rv = fx.view(a), fx.view(b)
        d = diff_views(sv, rv)
        caps = capabilities(d)
        cfg = rt.config.forensics
        ov = overlap(sv, rv, cfg.repackaged_min_jaccard, cfg.impostor_max_jaccard)
        if S.json:
            typer.echo(json.dumps({"diff": d, "capabilities": caps, "overlap": ov}, indent=2, sort_keys=True))
            return
        from kloner.report.diffview import render_diff

        render_diff(S.console, a, b, sv, rv, d, caps, ov, for_overlap(str(caps["line"]), ov["label"]), DISPLAY)

    _guard(run)


@app.command(rich_help_panel=STEP3, epilog=_examples("kloner explain <sha256>", "kloner --json explain <sha256>"))
def explain(
    sample_sha256: Annotated[str, typer.Argument(help="The sample's full SHA-256, as printed in a report.")],
    run: Annotated[str | None, typer.Option("--run", help="Only within this run.")] = None,
) -> None:
    """Show why a sample got its verdict: every gate, reason, label, signer and where it was seen."""

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


@app.command(rich_help_panel=STEP3, epilog=_examples("kloner reverify 2026-11-10T21-17-48Z"))
def reverify(run_id: Annotated[str, typer.Argument(help="The run id, printed on every report.")]) -> None:
    """Recompute every verdict of a run offline and compare the canonical JSON byte for byte."""

    def go() -> int:
        from kloner.hunt import reverify as do_reverify

        rt = _runtime()
        try:
            with _working(f"Recomputing every verdict of run {run_id} offline…"):
                ok, diffs, n = do_reverify(rt, run_id)
        finally:
            rt.close()
        ui.heading(S.console, "reverify", run_id)
        S.console.print()
        if ok:
            S.console.print(
                Text.assemble(
                    (" ✓ IDENTICAL ", ui.VERDICTS["GENUINE"][1]),
                    (f"  {n} verdict(s) of run {run_id} reproduced byte for byte", ui.SOFT),
                )
            )
            return 0
        S.console.print(
            Text.assemble((" ✗ DIFFERS ", ui.VERDICTS["FORGED"][1]), (f"  {len(diffs)} difference(s)", ui.SOFT))
        )
        for d in diffs:
            S.console.print(Text.assemble(("  DIFFERS ", f"bold {ui.RED}"), (str(d), ui.SOFT)))
        return 1

    raise typer.Exit(_guard(go))


@app.command(
    rich_help_panel=STEP3,
    epilog=_examples("kloner report <run-id> --format terminal", "kloner report <run-id> --format md,html"),
)
def report(
    run_id: Annotated[str, typer.Argument(help="The run id, printed on every report.")],
    fmt: Annotated[str, typer.Option("--format", help=_FORMATS)] = "md",
    out: Annotated[Path | None, typer.Option("--out", help="Write to this file instead of the run's folder.")] = None,
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
                ui.done(S.console, f"Wrote {out}")
            else:
                dest = Path(meta["report_dir"]) / FILE_NAMES[f]
                dest.write_text(text, encoding="utf-8")
                ui.done(S.console, f"Wrote {dest}")

    _guard(go)


_ZIPPW = "The ZIP password; 'infected' is the malware-sharing convention."


@export_app.command("samples")
def export_samples(
    run: Annotated[str, typer.Option("--run", help="The run whose hostile samples to package.")],
    # The malware-handling convention, not a secret (section 8.4).
    zip_password: Annotated[str, typer.Option("--zip-password", help=_ZIPPW)] = "infected",  # noqa: S107  # nosec B107
    out: Annotated[Path | None, typer.Option("--out", help="The ZIP file to write.")] = None,
) -> None:
    """Package a run's hostile samples for analyst sharing (password-protected ZIP, on explicit request)."""

    def go() -> None:
        from kloner.export import export_samples as do_export

        rt = _runtime()
        path, n = do_export(rt, run, zip_password, out)
        ui.done(S.console, f"Wrote {n} sample(s) to {path} (password '{zip_password}').")
        S.console.print(Text("  Never run or install them.", style=f"bold {ui.RED}"))

    _guard(go)


# --------------------------------------------------------------------------------------------
# intel
# --------------------------------------------------------------------------------------------


@intel_app.command("signer")
def intel_signer(cert_sha256: Annotated[str, typer.Argument(help="A signer certificate's SHA-256.")]) -> None:
    """Every package and sample a certificate signed."""
    _guard(lambda: _intel_rows("signer", cert_sha256))


@intel_app.command("payload")
def intel_payload(payload_id: Annotated[str, typer.Argument(help="A payload_id or shape_id from a report.")]) -> None:
    """Every sample that carries a payload (payload_id or shape_id)."""
    _guard(lambda: _intel_rows("payload", payload_id))


@intel_app.command("package")
def intel_package(package: Annotated[str, typer.Argument(help="Any package name.")]) -> None:
    """Every sample of a package across runs."""
    _guard(lambda: _intel_rows("package", package))


@intel_app.command("sources")
def intel_sources() -> None:
    """Per source: GENUINE, hostile and invalid counts and metadata mismatches over time."""
    _guard(lambda: _intel_rows("sources", ""))


def _intel_cell(key: str, value: Any) -> Text:
    if key.endswith("_json") and isinstance(value, str):
        with contextlib.suppress(ValueError):
            parsed = json.loads(value)
            if isinstance(parsed, list):
                return ui.labels_line([str(x) for x in parsed]) if parsed else Text("—", style=ui.MUTED)
    if key == "verdict" and isinstance(value, str):
        return ui.verdict_text(value)
    if value is None:
        return Text("—", style=ui.MUTED)
    return Text(str(value), style=ui.SOFT)


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
    ui.heading(S.console, f"intel {kind}", key or None)
    S.console.print()
    if not data:
        S.console.print(Text("No records.", style=ui.SOFT))
        return
    cols = list(data[0])
    t = ui.table()
    for col in cols:
        t.add_column(col.removesuffix("_json").replace("_", " ").upper(), overflow="fold")
    for r in data:
        t.add_row(*(_intel_cell(k, r.get(k)) for k in cols))
    S.console.print(t)


def main() -> None:
    # The startup banner goes to stderr and only to a person at a terminal (D-067). It can never change stdout or
    # the exit code: any failure while printing it is ignored.
    with contextlib.suppress(Exception):
        from kloner import banner

        banner.show(sys.argv[1:], __version__)
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
