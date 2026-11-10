"""Android SDK installation for ``kloner setup`` when no pinned build-tools are present (§16.4).

Downloads the pinned Android command-line tools (checksum from Google's repository manifest
repository2-3.xml), shows the Android SDK license and requires acceptance, then installs the
pinned build-tools, platform and platform-tools with sdkmanager into ~/.kloner/toolchain.

Acceptance is never silent (D-065). It comes from the person running setup: an answer at the prompt, the
``--accept-android-sdk-license`` flag (Docker: the ``ACCEPT_ANDROID_SDK_LICENSE=yes`` build argument), or a license
file they accepted earlier. Only the licenses the pinned packages require are accepted, through sdkmanager's own
install prompt, and their text is printed. Without any of these and without a terminal, setup stops before
downloading anything.
"""

from __future__ import annotations

import hashlib
import os
import platform
import re
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
LICENSE_URL = "https://developer.android.com/studio/terms"
# sdkmanager's install prompt: "License <id>:", a dashed rule, the text, a dashed rule, "Accept? (y/N):".
_LICENSE_PROMPT = re.compile(r"License ([\w.-]+):\s*\n-{10,}\n(.*?)\n-{10,}", re.S)


def license_prompts(output: str) -> list[tuple[str, str]]:
    """The (license id, text) pairs sdkmanager asked about while installing, in order."""
    return [(m.group(1), m.group(2).strip()) for m in _LICENSE_PROMPT.finditer(output.replace("\r", "\n"))]


def license_refusal() -> str:
    return (
        f"the Android SDK license must be accepted to install build-tools. Read it at {LICENSE_URL}, then re-run: "
        "kloner setup --accept-android-sdk-license (Docker: docker build --build-arg ACCEPT_ANDROID_SDK_LICENSE=yes "
        "-t kloner .)"
    )


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
    # A license accepted earlier by the same person is recorded under <sdk>/licenses (Google's documented way to
    # provision CI machines) and needs no prompt.
    accepted_before = (sdk / "licenses" / "android-sdk-license").is_file()
    if not accepted_before and not accept_license and not sys.stdin.isatty():
        raise ToolchainError(license_refusal())  # nothing was downloaded
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
        dl.unlink(missing_ok=True)  # the extracted tools are kept; the 170 MB archive is not needed again
        if system != "windows":
            for f in (tools / "bin").iterdir():
                f.chmod(0o755)
    java, _, _ = find_java()
    env = proc.minimal_env({"JAVA_HOME": str(java.parent.parent)})
    install: list[str | Path] = [sdkmanager, f"--sdk_root={sdk}", "--install", *PACKAGES]
    answers: bytes | None = None
    if not accepted_before:
        if not accept_license:
            # Show the license the pinned packages require. Answering "n" installs and accepts nothing.
            shown = license_prompts(proc.run(install, timeout_s=600, env=env, input_bytes=b"n\n" * 8).text())
            for lic_id, text in shown:
                console.print(f"License {lic_id}:\n{text}\n", markup=False, highlight=False)
            if not shown:
                console.print(f"The Android SDK License Agreement: {LICENSE_URL}")
            answer = console.input("Do you accept the Android SDK license shown above? [y/N] ").strip().lower()
            if answer not in ("y", "yes"):
                raise ToolchainError("Android SDK license not accepted; nothing was installed")
        # One "y" per license prompt of the pinned packages; sdkmanager asks about nothing else during an install.
        answers = b"y\n" * 8
    res = proc.run(install, timeout_s=3600, env=env, input_bytes=answers)
    if answers is not None:
        for lic_id, text in license_prompts(res.text()):
            console.print(f"License {lic_id}:\n{text}\n", markup=False, highlight=False)
            console.print(f"Accepted {lic_id} for {', '.join(PACKAGES)} ({LICENSE_URL}).")
    # sdkmanager exits 0 even when it skips packages whose license was not accepted.
    if not res.ok or not (sdk / "build-tools" / PINNED_BUILD_TOOLS).is_dir():
        tail = (res.err_text() or res.text())[-1000:]
        raise ToolchainError(f"sdkmanager did not install {PACKAGES[0]}: {tail}")
    return sdk
