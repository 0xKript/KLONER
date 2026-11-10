"""Toolchain resolution, ``kloner setup`` and ``kloner doctor`` (§16.4).

Pinned components (confirmed in docs/DECISIONS.md):

* Android SDK build-tools 36.0.0: ``lib/apksigner.jar`` (contains apksig), ``aapt2``, ``lib/d8.jar``.
  Floor: build-tools 35.0.0 (v3.1 and source-stamp support). KLONER refuses to run below it (INV-7).
* ``platforms/android-36/android.jar`` for building fixtures.
* apkeep 1.1.0 (EFF), checksum-verified against the digests GitHub publishes for the release.
* A JDK 17 or newer.
"""

from __future__ import annotations

import json
import os
import platform
import re
import shutil
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from kloner.util import proc
from kloner.util.hashing import sha256_file
from kloner.util.timeutil import now_iso

PINNED_BUILD_TOOLS = "36.0.0"
BUILD_TOOLS_FLOOR = (35, 0, 0)
PINNED_PLATFORM = "android-36"

# SHA-256 of lib/apksigner.jar per build-tools revision (recorded in docs/DECISIONS.md).
APKSIGNER_JAR_SHA256: dict[str, frozenset[str]] = {
    "36.0.0": frozenset({"3716d9311e55d2b0918a2fd9d54ba9e406c5f6abeea700b287f11259bc163dec"}),
}

APKEEP_VERSION = "1.1.0"
APKEEP_ASSETS: dict[tuple[str, str], tuple[str, str]] = {
    ("windows", "x86_64"): (
        "apkeep-x86_64-pc-windows-msvc.exe",
        "fb61e52fa48c321bbbb6d899dd06abf1705e3dbd74f07813bd2784279766ff6f",
    ),
    ("linux", "x86_64"): (
        "apkeep-x86_64-unknown-linux-gnu",
        "badd7ad9fa7d2f32abe01eaf33b7ff086361a95bbc000a33bf44b630d4bf2140",
    ),
    ("linux", "aarch64"): (
        "apkeep-aarch64-unknown-linux-gnu",
        "1a2e959842bbca4bc8db455b8132cc6f37534d70f2384409096268d8fc442ae8",
    ),
}
APKEEP_URL = "https://github.com/EFForg/apkeep/releases/download/{version}/{asset}"

BRIDGE_CLASS = "KlonerApksigBridge"
BRIDGE_VERSION = "2"  # must equal KlonerApksigBridge.BRIDGE_VERSION; a stale compiled bridge is refused
JAVA_MIN_MAJOR = 17


class ToolchainError(Exception):
    """The authoritative verifier or another required component is missing or unusable."""


@dataclass
class Toolchain:
    home: str
    java: str
    javac: str | None
    java_version: str
    sdk_root: str
    build_tools: str
    build_tools_version: str
    apksigner_jar: str
    apksigner_jar_sha256: str
    aapt2: str
    d8_jar: str
    platform_jar: str | None
    bridge_classes: str
    apkeep: str | None = None
    apkeep_version: str | None = None
    apkeep_error: str | None = None  # why the installed apkeep cannot run here (D-068)
    adb: str | None = None
    created_utc: str = field(default_factory=now_iso)

    @property
    def apksig_version(self) -> str:
        return f"build-tools {self.build_tools_version} (apksigner.jar sha256:{self.apksigner_jar_sha256[:12]})"

    def classpath(self) -> str:
        return os.pathsep.join([self.bridge_classes, self.apksigner_jar])

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(asdict(self), indent=2, sort_keys=True), encoding="utf-8")

    @classmethod
    def load(cls, path: Path) -> Toolchain:
        data = json.loads(path.read_text(encoding="utf-8"))
        known = set(cls.__dataclass_fields__)
        return cls(**{k: v for k, v in data.items() if k in known})


def toolchain_dir(home: Path) -> Path:
    """``<home>/toolchain``, or ``$KLONER_TOOLCHAIN``: the Docker image keeps it outside the data volume (D-051)."""
    env = os.environ.get("KLONER_TOOLCHAIN")
    return Path(env) if env else home / "toolchain"


def lock_path(home: Path) -> Path:
    return toolchain_dir(home) / "toolchain.json"


def _exe(p: Path) -> Path:
    if os.name == "nt":
        for suffix in (".exe", ".bat", ".cmd"):
            if p.with_suffix(suffix).exists():
                return p.with_suffix(suffix)
    return p


def parse_revision(text: str) -> tuple[int, int, int]:
    m = re.match(r"^\s*(\d+)(?:\.(\d+))?(?:\.(\d+))?", text)
    if not m:
        return (0, 0, 0)
    return (int(m.group(1)), int(m.group(2) or 0), int(m.group(3) or 0))


def java_major(version_output: str) -> int | None:
    m = re.search(r'version "(\d+)(?:\.(\d+))?', version_output)
    if not m:
        return None
    major = int(m.group(1))
    return int(m.group(2) or 0) if major == 1 else major


def find_java() -> tuple[Path, Path | None, str]:
    candidates: list[Path] = []
    for env in ("KLONER_JAVA_HOME", "JAVA_HOME"):
        if os.environ.get(env):
            candidates.append(Path(os.environ[env]) / "bin")
    found = shutil.which("java")
    if found:
        candidates.append(Path(found).parent)
    if os.name == "nt":
        for base in (Path(r"C:\Program Files\Java"), Path(r"C:\Program Files\Eclipse Adoptium")):
            if base.is_dir():
                candidates += sorted((d / "bin" for d in base.iterdir() if d.is_dir()), reverse=True)
    else:
        candidates += [Path("/opt/java/openjdk/bin"), Path("/usr/lib/jvm/default-java/bin")]
    for bindir in candidates:
        java = _exe(bindir / "java")
        if not java.exists():
            continue
        res = proc.run([java, "-version"], timeout_s=30, env=proc.minimal_env())
        out = res.err_text() + res.text()
        major = java_major(out)
        if major is not None and major >= JAVA_MIN_MAJOR:
            javac = _exe(bindir / "javac")
            first = out.strip().splitlines()[0] if out.strip() else ""
            return java, (javac if javac.exists() else None), first
    raise ToolchainError(f"no JDK {JAVA_MIN_MAJOR}+ found (set JAVA_HOME; Temurin is recommended)")


def sdk_candidates(home: Path) -> list[Path]:
    out: list[Path] = []
    for env in ("KLONER_ANDROID_SDK", "ANDROID_HOME", "ANDROID_SDK_ROOT"):
        if os.environ.get(env):
            out.append(Path(os.environ[env]))
    out.append(toolchain_dir(home) / "android-sdk")
    local = os.environ.get("LOCALAPPDATA")
    if local:
        out.append(Path(local) / "Android" / "Sdk")
    out += [Path.home() / "Android" / "Sdk", Path.home() / "Library" / "Android" / "sdk", Path("/opt/android-sdk")]
    return out


def find_build_tools(home: Path) -> tuple[Path, Path, str]:
    """Return (sdk_root, build_tools_dir, revision) for the pinned build-tools."""
    seen_lower: list[str] = []
    for sdk in sdk_candidates(home):
        bt = sdk / "build-tools" / PINNED_BUILD_TOOLS
        if (bt / "lib" / "apksigner.jar").is_file():
            return sdk, bt, PINNED_BUILD_TOOLS
        if (sdk / "build-tools").is_dir():
            seen_lower += [d.name for d in (sdk / "build-tools").iterdir() if d.is_dir()]
    hint = f" (found: {', '.join(sorted(set(seen_lower)))})" if seen_lower else ""
    raise ToolchainError(f"Android SDK build-tools {PINNED_BUILD_TOOLS} not found{hint}")


def extract_compile_classpath(apksigner_jar: Path, dest: Path) -> int:
    """javac rejects the pinned jar's STORED-with-zero-CRC manifest entry, so compile against its classes."""
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    n = 0
    with zipfile.ZipFile(apksigner_jar) as z:
        for info in z.infolist():
            name = info.filename
            if name.startswith("com/android/apksig/") and name.endswith(".class") and ".." not in name:
                target = dest / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(z.read(info))
                n += 1
    return n


def bridge_source() -> Path:
    here = Path(__file__).resolve().parent
    for cand in (here / "bridge" / "KlonerApksigBridge.java", here.parents[1] / "bridge" / "KlonerApksigBridge.java"):
        if cand.is_file():
            return cand
    raise ToolchainError("bridge source KlonerApksigBridge.java is missing from the installation")


def compile_bridge(home: Path, javac: Path, apksigner_jar: Path, jar_sha: str) -> Path:
    out = toolchain_dir(home) / "bridge" / jar_sha[:16]
    classes = out / "classes"
    cp = out / "compile-classpath"
    extract_compile_classpath(apksigner_jar, cp)
    if classes.exists():
        shutil.rmtree(classes)
    classes.mkdir(parents=True)
    res = proc.run(
        [javac, "-Xlint:all", "-Werror", "--release", "17", "-cp", cp, "-d", classes, bridge_source()],
        timeout_s=300,
        env=proc.minimal_env(),
    )
    if not res.ok:
        raise ToolchainError(f"bridge compilation failed: {res.err_text()[-2000:]}")
    return classes


def apkeep_asset() -> tuple[str, str] | None:
    system = platform.system().lower()
    machine = platform.machine().lower()
    machine = {"amd64": "x86_64", "arm64": "aarch64"}.get(machine, machine)
    return APKEEP_ASSETS.get((system, machine))


def install_apkeep(home: Path, user_agent: str) -> tuple[Path, str]:
    import httpx

    asset = apkeep_asset()
    if asset is None:
        raise ToolchainError(f"no pinned apkeep build for {platform.system()} {platform.machine()}")
    name, digest = asset
    dest_dir = toolchain_dir(home) / "apkeep" / APKEEP_VERSION
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / ("apkeep.exe" if name.endswith(".exe") else "apkeep")
    if dest.is_file() and sha256_file(dest) == digest:
        return dest, APKEEP_VERSION
    url = APKEEP_URL.format(version=APKEEP_VERSION, asset=name)
    tmp = dest.with_suffix(".part")
    with httpx.stream("GET", url, follow_redirects=True, timeout=120, headers={"User-Agent": user_agent}) as r:
        r.raise_for_status()
        with tmp.open("wb") as f:
            for chunk in r.iter_bytes():
                f.write(chunk)
    got = sha256_file(tmp)
    if got != digest:
        tmp.unlink(missing_ok=True)
        raise ToolchainError(f"apkeep checksum mismatch: expected {digest}, got {got}")
    os.replace(tmp, dest)
    if os.name != "nt":
        os.chmod(dest, 0o700)
    return dest, APKEEP_VERSION


def apkeep_runs(path: str) -> str | None:
    """None if ``apkeep --version`` runs here, else why not (D-068).

    A file with the right checksum can still fail to start: apkeep 1.1.0's Linux build needs glibc 2.38, which
    Debian bookworm (glibc 2.36) does not have.
    """
    res = proc.run([path, "--version"], timeout_s=30, env=proc.minimal_env())
    if res.ok:
        return None
    lines = [x.strip() for x in (res.err_text() or res.text()).splitlines() if x.strip()]
    why = lines[0] if lines else ("timed out" if res.timed_out else f"exit status {res.returncode}")
    return why[:300]


def find_apkeep(home: Path) -> tuple[Path, str] | None:
    asset = apkeep_asset()
    if asset:
        cand = (
            toolchain_dir(home) / "apkeep" / APKEEP_VERSION / ("apkeep.exe" if asset[0].endswith(".exe") else "apkeep")
        )
        if cand.is_file() and sha256_file(cand) == asset[1]:
            return cand, APKEEP_VERSION
    return None


def setup(home: Path, *, install_apkeep_binary: bool, user_agent: str) -> tuple[Toolchain, list[str]]:
    """Resolve and pin every component, compile the bridge, write the toolchain lock."""
    notes: list[str] = []
    java, javac, java_version = find_java()
    if javac is None:
        raise ToolchainError("a JDK (with javac) is required to compile the apksig bridge; a JRE is not enough")
    sdk, bt, revision = find_build_tools(home)
    jar = bt / "lib" / "apksigner.jar"
    jar_sha = sha256_file(jar)
    if jar_sha not in APKSIGNER_JAR_SHA256.get(revision, frozenset()):
        raise ToolchainError(
            f"build-tools {revision} apksigner.jar has SHA-256 {jar_sha}, which is not the pinned value; "
            "reinstall build-tools with sdkmanager"
        )
    aapt2 = _exe(bt / "aapt2")
    if not aapt2.exists():
        raise ToolchainError(f"aapt2 missing from {bt}")
    platform_jar = sdk / "platforms" / PINNED_PLATFORM / "android.jar"
    classes = compile_bridge(home, javac, jar, jar_sha)
    adb = _exe(sdk / "platform-tools" / "adb")
    tc = Toolchain(
        home=str(home),
        java=str(java),
        javac=str(javac),
        java_version=java_version,
        sdk_root=str(sdk),
        build_tools=str(bt),
        build_tools_version=revision,
        apksigner_jar=str(jar),
        apksigner_jar_sha256=jar_sha,
        aapt2=str(aapt2),
        d8_jar=str(bt / "lib" / "d8.jar"),
        platform_jar=str(platform_jar) if platform_jar.is_file() else None,
        bridge_classes=str(classes),
        adb=str(adb) if adb.exists() else None,
    )
    if install_apkeep_binary:
        try:
            path, ver = install_apkeep(home, user_agent)
            tc.apkeep, tc.apkeep_version = str(path), ver
        except Exception as e:
            notes.append(f"apkeep not installed: {e}")
    else:
        found = find_apkeep(home)
        if found:
            tc.apkeep, tc.apkeep_version = str(found[0]), found[1]
    if tc.apkeep:
        tc.apkeep_error = apkeep_runs(tc.apkeep)
        if tc.apkeep_error:
            notes.append(
                f"apkeep {tc.apkeep_version} cannot run on this system ({tc.apkeep_error}): the apkpure and "
                "googleplay sources are disabled"
            )
    if tc.platform_jar is None:
        notes.append(f"{PINNED_PLATFORM} android.jar not found: fixtures cannot be rebuilt (selftest still works)")
    tc.save(lock_path(home))
    return tc, notes


def load_toolchain(home: Path) -> Toolchain:
    path = lock_path(home)
    if not path.is_file():
        raise ToolchainError("toolchain not set up; run: kloner setup")
    tc = Toolchain.load(path)
    if parse_revision(tc.build_tools_version) < BUILD_TOOLS_FLOOR:
        raise ToolchainError(f"build-tools {tc.build_tools_version} is below the floor 35.0.0; run: kloner setup")
    return tc


def bridge_round_trip(tc: Toolchain, timeout_s: float = 60) -> dict[str, Any]:
    res = proc.run(
        [tc.java, "-cp", tc.classpath(), BRIDGE_CLASS, "--version"], timeout_s=timeout_s, env=proc.minimal_env()
    )
    if not res.ok:
        raise ToolchainError(f"bridge did not start: {res.err_text()[-800:]}")
    data: dict[str, Any] = json.loads(res.text())
    if data.get("apksig_jar_sha256") != tc.apksigner_jar_sha256:
        raise ToolchainError("the bridge loaded a different apksig than the pinned one")
    if data.get("bridge_version") != BRIDGE_VERSION:
        raise ToolchainError(
            f"the compiled apksig bridge is version {data.get('bridge_version')}, this KLONER needs "
            f"{BRIDGE_VERSION}; run: kloner setup"
        )
    return data


__all__ = [
    "APKSIGNER_JAR_SHA256",
    "BUILD_TOOLS_FLOOR",
    "PINNED_BUILD_TOOLS",
    "Toolchain",
    "ToolchainError",
    "bridge_round_trip",
    "load_toolchain",
    "setup",
]
