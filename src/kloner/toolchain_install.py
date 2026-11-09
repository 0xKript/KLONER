"""Android SDK installation for ``kloner setup`` when no pinned build-tools are present (§16.4).

Downloads the pinned Android command-line tools (checksum from Google's repository manifest
repository2-3.xml), shows the Android SDK license and requires acceptance, then installs the
pinned build-tools, platform and platform-tools with sdkmanager into ~/.kloner/toolchain.
"""

from __future__ import annotations

import hashlib
import os
import platform
import shutil
import sys
import zipfile
from pathlib import Path

import httpx
from rich.console import Console

from kloner.toolchain import PINNED_BUILD_TOOLS, PINNED_PLATFORM, ToolchainError, find_java, toolchain_dir
from kloner.util import proc

REPO = "https://dl.google.com/android/repository/"
# cmdline-tools;20.0 (revision 14742923): SHA-1 as published in repository2-3.xml.
CMDLINE_TOOLS: dict[str, tuple[str, str]] = {
    "linux": ("commandlinetools-linux-14742923_latest.zip", "48833c34b761c10cb20bcd16582129395d121b27"),
    "windows": ("commandlinetools-win-14742923_latest.zip", "16b3f45ddb3d85ea6bbe6a1c0b47146daf0db450"),
    "darwin": ("commandlinetools-mac-14742923_latest.zip", "cc27cca4b84bfdbc7df17e3d0a01d0c640d8ee71"),
}
PACKAGES = (f"build-tools;{PINNED_BUILD_TOOLS}", f"platforms;{PINNED_PLATFORM}", "platform-tools")


def _download(url: str, dest: Path, sha1: str) -> None:
    h = hashlib.sha1(usedforsecurity=False)
    tmp = dest.with_suffix(".part")
    with httpx.stream("GET", url, timeout=300, follow_redirects=True) as r:
        r.raise_for_status()
        with tmp.open("wb") as f:
            for chunk in r.iter_bytes():
                h.update(chunk)
                f.write(chunk)
    if h.hexdigest() != sha1:
        tmp.unlink(missing_ok=True)
        raise ToolchainError(f"checksum mismatch for {url}")
    os.replace(tmp, dest)


def _safe_extract(zip_path: Path, dest: Path) -> None:
    root = dest.resolve()
    with zipfile.ZipFile(zip_path) as z:
        for info in z.infolist():
            target = (dest / info.filename).resolve()
            if not str(target).startswith(str(root)):
                raise ToolchainError(f"unsafe path in {zip_path.name}: {info.filename}")
        z.extractall(dest)


def ensure_build_tools(home: Path, *, accept_license: bool, console: Console) -> Path:
    system = platform.system().lower()
    if system not in CMDLINE_TOOLS:
        raise ToolchainError(f"no pinned Android command-line tools for {platform.system()}")
    sdk = toolchain_dir(home) / "android-sdk"
    tools = sdk / "cmdline-tools" / "latest"
    sdkmanager = tools / "bin" / ("sdkmanager.bat" if system == "windows" else "sdkmanager")
    if not sdkmanager.exists():
        name, sha1 = CMDLINE_TOOLS[system]
        dl = toolchain_dir(home) / name
        dl.parent.mkdir(parents=True, exist_ok=True)
        console.print(f"Downloading Android command-line tools ({name}) from Google…")
        _download(REPO + name, dl, sha1)
        staging = sdk / "cmdline-tools" / "_staging"
        shutil.rmtree(staging, ignore_errors=True)
        staging.mkdir(parents=True)
        _safe_extract(dl, staging)
        shutil.rmtree(tools, ignore_errors=True)
        (staging / "cmdline-tools").rename(tools)
        shutil.rmtree(staging, ignore_errors=True)
        if system != "windows":
            for f in (tools / "bin").iterdir():
                f.chmod(0o755)
    java, _, _ = find_java()
    env = proc.minimal_env({"JAVA_HOME": str(java.parent.parent)})
    lic = proc.run([sdkmanager, f"--sdk_root={sdk}", "--licenses"], timeout_s=300, env=env, input_bytes=b"n\n" * 20)
    console.print(lic.text()[-6000:])
    if not accept_license:
        if not sys.stdin.isatty():
            raise ToolchainError(
                "the Android SDK license must be accepted to install build-tools; read it above and re-run: "
                "kloner setup --accept-android-sdk-license"
            )
        answer = console.input("Do you accept the Android SDK license shown above? [y/N] ").strip().lower()
        if answer not in ("y", "yes"):
            raise ToolchainError("Android SDK license not accepted; nothing was installed")
    res = proc.run([sdkmanager, f"--sdk_root={sdk}", "--licenses"], timeout_s=300, env=env, input_bytes=b"y\n" * 20)
    if not res.ok:
        raise ToolchainError(f"sdkmanager --licenses failed: {res.err_text()[-500:]}")
    res = proc.run([sdkmanager, f"--sdk_root={sdk}", "--install", *PACKAGES], timeout_s=3600, env=env)
    if not res.ok:
        raise ToolchainError(f"sdkmanager install failed: {res.err_text()[-1000:]}")
    return sdk
