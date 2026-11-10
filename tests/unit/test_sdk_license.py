"""Android SDK license acceptance in ``kloner setup`` (D-065): explicit, limited to the pinned packages, never silent.

sdkmanager is replaced by a fake that answers like the real one (cmdline-tools 20.0): an install prints
"License android-sdk-license:", the text between dashed rules and "Accept? (y/N):", and installs nothing on "n".
"""

from __future__ import annotations

import io
import sys
from pathlib import Path
from typing import Any

import pytest
from rich.console import Console

from kloner import toolchain_install as ti
from kloner.toolchain import PINNED_BUILD_TOOLS, ToolchainError
from kloner.util.proc import ProcResult

PROMPT = (
    "Loading package information...\r[=====      ] 25% Computing updates...\r\n"
    "License android-sdk-license:\n"
    "---------------------------------------\n"
    "Terms and Conditions\n\nThis is the Android Software Development Kit License Agreement\n\n1. Introduction\n"
    "---------------------------------------\n"
    "Accept? (y/N): "
)


class FakeSdkManager:
    def __init__(self, sdk: Path) -> None:
        self.sdk = sdk
        self.calls: list[tuple[list[str], bytes | None]] = []

    def __call__(self, argv: Any, *, input_bytes: bytes | None = None, **_: Any) -> ProcResult:
        args = [str(a) for a in argv]
        self.calls.append((args, input_bytes))
        if "--install" not in args:
            raise AssertionError(f"unexpected sdkmanager call: {args}")
        licensed = (self.sdk / "licenses" / "android-sdk-license").is_file()
        out = "" if licensed else PROMPT
        if licensed or (input_bytes or b"").startswith(b"y"):
            (self.sdk / "licenses").mkdir(parents=True, exist_ok=True)
            (self.sdk / "licenses" / "android-sdk-license").write_text("\n24333f8a63b6825ea9c5514f83c2829b004d1fee")
            (self.sdk / "build-tools" / PINNED_BUILD_TOOLS).mkdir(parents=True, exist_ok=True)
            out += "y\n[=======] 100% Unzipping...\n" if not licensed else "[=======] 100% Unzipping...\n"
        else:
            out += "Skipping following packages as the license is not accepted:\nAndroid SDK Build-Tools 36\n"
        # The real sdkmanager exits 0 even when it skips packages.
        return ProcResult(tuple(args), 0, out.encode(), b"", False, 0.1)


@pytest.fixture
def sdk_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path, FakeSdkManager]:
    monkeypatch.delenv("KLONER_TOOLCHAIN", raising=False)
    home = tmp_path / "home"
    sdk = home / "toolchain" / "android-sdk"
    tools_bin = sdk / "cmdline-tools" / "latest" / "bin"
    tools_bin.mkdir(parents=True)
    (tools_bin / "sdkmanager").write_text("")
    (tools_bin / "sdkmanager.bat").write_text("")
    fake = FakeSdkManager(sdk)
    monkeypatch.setattr(ti.proc, "run", fake)
    monkeypatch.setattr(ti, "find_java", lambda: (tmp_path / "jdk" / "bin" / "java", None, "17"))

    def no_download(*_: Any) -> None:
        raise AssertionError("nothing may be downloaded")

    monkeypatch.setattr(ti, "_download", no_download)
    return home, sdk, fake


def _console(answer: str | None = None) -> tuple[Console, io.StringIO]:
    buf = io.StringIO()
    con = Console(file=buf, width=200, color_system=None)
    if answer is not None:
        con.input = lambda *_a, **_k: answer  # type: ignore[method-assign]
    return con, buf


def _tty(monkeypatch: pytest.MonkeyPatch, value: bool) -> None:
    monkeypatch.setattr(sys.stdin, "isatty", lambda: value, raising=False)


def test_without_acceptance_setup_stops_before_downloading(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("KLONER_TOOLCHAIN", raising=False)
    _tty(monkeypatch, False)

    def no_download(*_: Any) -> None:
        raise AssertionError("nothing may be downloaded before the license is accepted")

    monkeypatch.setattr(ti, "_download", no_download)
    con, _ = _console()
    with pytest.raises(ToolchainError) as e:
        ti.ensure_build_tools(tmp_path / "home", accept_license=False, console=con)
    msg = str(e.value)
    assert ti.LICENSE_URL in msg and "--accept-android-sdk-license" in msg and "ACCEPT_ANDROID_SDK_LICENSE=yes" in msg


def test_the_flag_accepts_only_what_the_pinned_packages_require(
    sdk_env: tuple[Path, Path, FakeSdkManager], monkeypatch: pytest.MonkeyPatch
) -> None:
    home, sdk, fake = sdk_env
    _tty(monkeypatch, False)
    con, out = _console()
    assert ti.ensure_build_tools(home, accept_license=True, console=con) == sdk
    assert len(fake.calls) == 1  # no "sdkmanager --licenses": the other SDK licenses stay unaccepted
    args, answers = fake.calls[0]
    assert "--install" in args and all(p in args for p in ti.PACKAGES)
    assert answers is not None and answers.startswith(b"y\n")
    text = out.getvalue()
    assert "This is the Android Software Development Kit License Agreement" in text  # printed, so never silent
    assert "Accepted android-sdk-license" in text


def test_the_prompt_shows_the_license_and_no_accepts_nothing(
    sdk_env: tuple[Path, Path, FakeSdkManager], monkeypatch: pytest.MonkeyPatch
) -> None:
    home, sdk, fake = sdk_env
    _tty(monkeypatch, True)
    con, out = _console(answer="n")
    with pytest.raises(ToolchainError, match="not accepted; nothing was installed"):
        ti.ensure_build_tools(home, accept_license=False, console=con)
    assert len(fake.calls) == 1 and (fake.calls[0][1] or b"").startswith(b"n\n")
    assert "This is the Android Software Development Kit License Agreement" in out.getvalue()
    assert not (sdk / "licenses").exists() and not (sdk / "build-tools").exists()


def test_the_prompt_yes_installs(sdk_env: tuple[Path, Path, FakeSdkManager], monkeypatch: pytest.MonkeyPatch) -> None:
    home, sdk, fake = sdk_env
    _tty(monkeypatch, True)
    con, _ = _console(answer="y")
    assert ti.ensure_build_tools(home, accept_license=False, console=con) == sdk
    assert [(a or b"")[:2] for _, a in fake.calls] == [b"n\n", b"y\n"]
    assert (sdk / "build-tools" / PINNED_BUILD_TOOLS).is_dir()


def test_a_license_accepted_earlier_needs_no_prompt(
    sdk_env: tuple[Path, Path, FakeSdkManager], monkeypatch: pytest.MonkeyPatch
) -> None:
    home, sdk, fake = sdk_env
    (sdk / "licenses").mkdir(parents=True)
    (sdk / "licenses" / "android-sdk-license").write_text("\n24333f8a63b6825ea9c5514f83c2829b004d1fee")
    _tty(monkeypatch, False)
    con, out = _console()
    assert ti.ensure_build_tools(home, accept_license=False, console=con) == sdk
    assert len(fake.calls) == 1 and fake.calls[0][1] is None  # nothing answered on anyone's behalf
    assert "Accepted" not in out.getvalue()


def test_a_skipped_install_is_an_error(
    sdk_env: tuple[Path, Path, FakeSdkManager], monkeypatch: pytest.MonkeyPatch
) -> None:
    home, _sdk, fake = sdk_env
    _tty(monkeypatch, True)
    con, _ = _console(answer="y")

    def skip(argv: Any, *, input_bytes: bytes | None = None, **_: Any) -> ProcResult:
        fake.calls.append(([str(a) for a in argv], input_bytes))
        out = PROMPT + "Skipping following packages as the license is not accepted:\nAndroid SDK Build-Tools 36\n"
        return ProcResult(tuple(str(a) for a in argv), 0, out.encode(), b"", False, 0.1)

    monkeypatch.setattr(ti.proc, "run", skip)
    with pytest.raises(ToolchainError, match="did not install"):
        ti.ensure_build_tools(home, accept_license=False, console=con)


def test_license_prompts_are_parsed_from_sdkmanager_output() -> None:
    prompts = ti.license_prompts(PROMPT.replace("\n", "\r\n"))
    assert [p[0] for p in prompts] == ["android-sdk-license"]
    assert prompts[0][1].startswith("Terms and Conditions")
