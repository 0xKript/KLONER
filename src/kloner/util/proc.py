"""Supervised external processes (§16.3).

Every external tool (apksig bridge, aapt2, apkeep, adb, workers) is started with an argument
list (never a shell), a minimal environment, a timeout and, on POSIX, resource limits.
"""

from __future__ import annotations

import os

# argument lists only; see run()
import subprocess  # nosec B404
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

IS_WINDOWS = os.name == "nt"
# macOS: no preexec_fn. Running Python between fork and exec is unsafe there once system frameworks are
# loaded, and macOS does not enforce address-space limits; workers keep their timeouts (D-061).
IS_MACOS = sys.platform == "darwin"
_WINDOWS_KEEP = ("SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "TEMP", "TMP", "PATHEXT", "NUMBER_OF_PROCESSORS")


@dataclass(frozen=True)
class ProcResult:
    argv: tuple[str, ...]
    returncode: int | None
    stdout: bytes
    stderr: bytes
    timed_out: bool
    duration_s: float
    truncated: bool = False

    @property
    def ok(self) -> bool:
        return not self.timed_out and self.returncode == 0

    def text(self) -> str:
        return self.stdout.decode("utf-8", errors="replace")

    def err_text(self) -> str:
        return self.stderr.decode("utf-8", errors="replace")


def minimal_env(extra: Mapping[str, str] | None = None) -> dict[str, str]:
    """A small, explicit environment: nothing inherited that could alter tool behavior."""
    env: dict[str, str] = {}
    if IS_WINDOWS:
        for key in _WINDOWS_KEEP:
            if key in os.environ:
                env[key] = os.environ[key]
        root = os.environ.get("SYSTEMROOT", r"C:\Windows")
        env["PATH"] = rf"{root}\System32;{root}"
    else:
        env["PATH"] = "/usr/local/bin:/usr/bin:/bin"
        env["LANG"] = "C.UTF-8"
        env["LC_ALL"] = "C.UTF-8"
        if "TMPDIR" in os.environ:
            env["TMPDIR"] = os.environ["TMPDIR"]
    if extra:
        env.update(extra)
    return env


def _posix_limits(address_space: int | None, cpu_seconds: int | None) -> Callable[[], None] | None:
    if IS_WINDOWS or IS_MACOS or (address_space is None and cpu_seconds is None):
        return None

    def apply() -> None:  # pragma: no cover - runs in the child
        import importlib

        resource = importlib.import_module("resource")
        setrlimit = resource.setrlimit
        if address_space is not None:
            setrlimit(resource.RLIMIT_AS, (address_space, address_space))
        if cpu_seconds is not None:
            setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))

    return apply


def run(
    argv: Sequence[str | Path],
    *,
    timeout_s: float,
    input_bytes: bytes | None = None,
    env: Mapping[str, str] | None = None,
    cwd: Path | None = None,
    address_space: int | None = None,
    cpu_seconds: int | None = None,
    max_output: int = 256 << 20,
) -> ProcResult:
    """Run a tool with an argument list. Never raises on tool failure; returns a ProcResult."""
    args = tuple(str(a) for a in argv)
    start = time.monotonic()
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if IS_WINDOWS else 0
    try:
        # fixed argument list, no shell
        proc = subprocess.Popen(  # noqa: S603  # nosec B603
            args,
            stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=dict(env) if env is not None else minimal_env(),
            cwd=str(cwd) if cwd else None,
            preexec_fn=_posix_limits(address_space, cpu_seconds),
            creationflags=creationflags,
        )
    except OSError as e:
        return ProcResult(args, None, b"", str(e).encode(), False, time.monotonic() - start)
    timed_out = False
    try:
        out, err = proc.communicate(input=input_bytes, timeout=timeout_s)
    except subprocess.TimeoutExpired:
        timed_out = True
        proc.kill()
        out, err = proc.communicate()
    truncated = len(out) > max_output or len(err) > max_output
    return ProcResult(
        args, proc.returncode, out[:max_output], err[:max_output], timed_out, time.monotonic() - start, truncated
    )


def popen_pipes(
    argv: Sequence[str | Path],
    *,
    env: Mapping[str, str] | None = None,
    address_space: int | None = None,
) -> subprocess.Popen[bytes]:
    """Start a long-lived tool (the bridge in --serve mode) with stdin/stdout pipes."""
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if IS_WINDOWS else 0
    # fixed argument list, no shell
    return subprocess.Popen(  # noqa: S603  # nosec B603
        [str(a) for a in argv],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=dict(env) if env is not None else minimal_env(),
        preexec_fn=_posix_limits(address_space, None),
        creationflags=creationflags,
    )


def python_executable() -> str:
    return sys.executable
