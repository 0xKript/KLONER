"""``kloner doctor`` (§16.4): every component and version, the bridge round-trip, the apksig floor,
write permissions and network reachability of the enabled sources, each with a fix."""

from __future__ import annotations

import os
import platform
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

import httpx

from kloner import __version__
from kloner.app import Runtime
from kloner.toolchain import (
    APKEEP_VERSION,
    APKSIGNER_JAR_SHA256,
    BUILD_TOOLS_FLOOR,
    ToolchainError,
    apkeep_asset,
    apkeep_runs,
    bridge_round_trip,
    load_toolchain,
    parse_revision,
)
from kloner.util import proc
from kloner.util.hashing import sha256_file

PROBES = {
    "aptoide": "https://ws75.aptoide.com/api/7/app/getMeta?package_name=org.fdroid.fdroid",
    "fdroid": "https://f-droid.org/repo/entry.json",
    "apkpure": "https://api.pureapk.com/",
    "googleplay": "https://play.google.com/",
}


@dataclass
class Check:
    name: str
    status: str  # PASS | WARN | FAIL
    detail: str
    fix: str = ""
    critical: bool = False


def run_doctor(rt: Runtime, network: bool = True) -> list[Check]:
    out: list[Check] = []
    out.append(Check("kloner", "PASS", f"version {__version__}, home {rt.home}"))
    try:
        tc = load_toolchain(rt.home)
    except ToolchainError as e:
        out.append(Check("toolchain", "FAIL", str(e), "kloner setup", critical=True))
        return out
    res = proc.run([tc.java, "-version"], timeout_s=30, env=proc.minimal_env())
    first = (res.err_text() or res.text()).strip().splitlines()[:1]
    out.append(
        Check(
            "jdk",
            "PASS" if res.ok else "FAIL",
            first[0] if first else "java did not run",
            "" if res.ok else "install a JDK 17+ (Temurin) and run kloner setup",
            critical=not res.ok,
        )
    )
    rev = parse_revision(tc.build_tools_version)
    out.append(
        Check(
            "build-tools",
            "PASS" if rev >= BUILD_TOOLS_FLOOR else "FAIL",
            f"{tc.build_tools_version} at {tc.build_tools} (floor 35.0.0)",
            "" if rev >= BUILD_TOOLS_FLOOR else "kloner setup --upgrade",
            critical=rev < BUILD_TOOLS_FLOOR,
        )
    )
    try:
        jar_ok = sha256_file(Path(tc.apksigner_jar)) in APKSIGNER_JAR_SHA256.get(tc.build_tools_version, frozenset())
    except OSError:
        jar_ok = False
    out.append(
        Check(
            "apksig",
            "PASS" if jar_ok else "FAIL",
            tc.apksig_version,
            "" if jar_ok else "reinstall build-tools and run kloner setup",
            critical=not jar_ok,
        )
    )
    try:
        info = bridge_round_trip(tc)
        out.append(
            Check(
                "bridge",
                "PASS",
                f"round-trip OK (bridge {info.get('bridge_version')}, java {info.get('java_version')})",
            )
        )
    except ToolchainError as e:
        out.append(Check("bridge", "FAIL", str(e), "kloner setup", critical=True))
    a = proc.run([tc.aapt2, "version"], timeout_s=30, env=proc.minimal_env())
    out.append(
        Check(
            "aapt2",
            "PASS" if a.ok else "FAIL",
            (a.text() or a.err_text()).strip()[:120],
            "" if a.ok else "kloner setup",
            critical=not a.ok,
        )
    )
    if tc.apkeep and Path(tc.apkeep).is_file():
        # Run it: a binary with the right checksum can still fail to start (glibc too old, D-068).
        why = apkeep_runs(tc.apkeep)
        if why is None:
            out.append(Check("apkeep", "PASS", f"{tc.apkeep_version} at {tc.apkeep}"))
        else:
            out.append(
                Check(
                    "apkeep",
                    "WARN",
                    f"{tc.apkeep_version} cannot run on this system ({why}): apkpure and googleplay sources are "
                    "disabled",
                )
            )
    else:
        if apkeep_asset() is None:
            detail = f"apkeep {APKEEP_VERSION} publishes no build for {platform.system()} {platform.machine()}"
            out.append(Check("apkeep", "WARN", f"{detail}: apkpure and googleplay sources are disabled"))
        else:
            out.append(
                Check("apkeep", "WARN", "not installed: apkpure and googleplay sources are disabled", "kloner setup")
            )
    try:
        rt.quarantine.root.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=rt.quarantine.incoming, delete=True) as f:
            f.write(b"ok")
        out.append(Check("permissions", "PASS", f"quarantine writable at {rt.quarantine.root}"))
    except OSError as e:
        out.append(Check("permissions", "FAIL", str(e), f"make {rt.home} writable", critical=True))
    if sys.platform == "darwin":
        out.append(
            Check(
                "isolation",
                "WARN",
                "macOS: workers run with timeouts and the JVM heap cap, but without POSIX address-space/CPU "
                "limits (D-061)",
                "use the Docker image for authoritative runs",
            )
        )
    elif os.name == "nt":
        out.append(
            Check(
                "isolation",
                "WARN",
                "native Windows: workers run with timeouts and the JVM heap cap, but without POSIX "
                "address-space/CPU limits",
                "use WSL2 or the Docker image for authoritative runs",
            )
        )
    else:
        out.append(Check("isolation", "PASS", "POSIX resource limits applied to workers"))
    if network:
        for name in rt.config.sources.enabled:
            url = PROBES.get(name)
            if url is None:
                continue
            try:
                r = httpx.get(url, timeout=15, headers={"User-Agent": rt.user_agent()}, follow_redirects=False)
                ok = r.status_code < 500
                out.append(Check(f"source:{name}", "PASS" if ok else "WARN", f"HTTP {r.status_code} from {url}"))
            except httpx.HTTPError as e:
                out.append(Check(f"source:{name}", "WARN", f"unreachable: {type(e).__name__}", "check network/proxy"))
    return out
