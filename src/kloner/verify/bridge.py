"""Supervisor for the Java apksig bridge in ``--serve`` mode (§9.1).

One JVM per client; requests are JSON lines. A per-request timeout or a crash kills the JVM; the
next request starts a fresh one. A failed request yields ERROR for that sample only.
"""

from __future__ import annotations

import json
import queue
import threading
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

# typing only
from subprocess import Popen  # nosec B404
from typing import IO

from kloner.models import BridgeResult
from kloner.toolchain import BRIDGE_CLASS, Toolchain
from kloner.util import proc

MAX_RESPONSE_BYTES = 64 << 20


class BridgeFailure(Exception):
    """The bridge could not produce a verification result (timeout, crash, protocol error)."""


def _reader(stream: IO[bytes], q: queue.Queue[bytes | None]) -> None:
    try:
        for line in iter(stream.readline, b""):
            q.put(line)
    finally:
        q.put(None)


class BridgeClient:
    def __init__(self, tc: Toolchain, timeout_s: float = 120.0, heap: str = "2g") -> None:
        self.tc = tc
        self.timeout_s = timeout_s
        self.heap = heap
        self._proc: Popen[bytes] | None = None
        self._q: queue.Queue[bytes | None] = queue.Queue()
        self._lock = threading.Lock()
        self.restarts = 0

    def _argv(self) -> list[str]:
        return [
            self.tc.java,
            f"-Xmx{self.heap}",
            "-XX:+UseSerialGC",
            "-Djava.awt.headless=true",
            "-cp",
            self.tc.classpath(),
            BRIDGE_CLASS,
            "--serve",
        ]

    def _start(self) -> None:
        self._q = queue.Queue()
        p = proc.popen_pipes(self._argv(), env=proc.minimal_env())
        assert p.stdout is not None
        threading.Thread(target=_reader, args=(p.stdout, self._q), daemon=True).start()
        self._proc = p

    def _kill(self) -> None:
        p = self._proc
        self._proc = None
        if p is not None:
            try:
                p.kill()
                p.wait(timeout=10)
            # best-effort cleanup of a dead JVM
            except Exception:  # noqa: S110  # nosec B110
                pass
            self.restarts += 1

    def request(self, payload: dict[str, object]) -> dict[str, object]:
        with self._lock:
            if self._proc is None or self._proc.poll() is not None:
                self._start()
            assert self._proc is not None and self._proc.stdin is not None
            rid = uuid.uuid4().hex
            line = json.dumps({**payload, "id": rid}) + "\n"
            try:
                self._proc.stdin.write(line.encode("utf-8"))
                self._proc.stdin.flush()
            except OSError as e:
                self._kill()
                raise BridgeFailure(f"bridge stdin closed: {e}") from e
            try:
                raw = self._q.get(timeout=self.timeout_s)
            except queue.Empty as e:
                self._kill()
                raise BridgeFailure(f"bridge timed out after {self.timeout_s:.0f}s") from e
            if raw is None:
                self._kill()
                raise BridgeFailure("bridge process exited unexpectedly")
            if len(raw) > MAX_RESPONSE_BYTES:
                self._kill()
                raise BridgeFailure("bridge response too large")
            try:
                data = json.loads(raw)
            except json.JSONDecodeError as e:
                self._kill()
                raise BridgeFailure(f"bridge protocol error: {e}") from e
            if not isinstance(data, dict) or data.get("id") != rid:
                self._kill()
                raise BridgeFailure("bridge response does not match the request")
            return data

    def verify(self, path: Path, min_sdk: int, max_sdk: int) -> BridgeResult:
        data = self.request({"op": "verify", "path": str(path), "min_sdk": int(min_sdk), "max_sdk": int(max_sdk)})
        result = BridgeResult.model_validate(data)
        if result.fatal and result.fatal.startswith("BridgeRequestError"):
            raise BridgeFailure(result.fatal)
        if result.apksig_jar_sha256 != self.tc.apksigner_jar_sha256:
            raise BridgeFailure("bridge loaded an apksig that is not the pinned one")
        return result

    def version(self) -> dict[str, object]:
        return self.request({"op": "version"})

    def close(self) -> None:
        with self._lock:
            p = self._proc
            if p is not None and p.poll() is None and p.stdin is not None:
                try:
                    p.stdin.write(b'{"op":"quit"}\n')
                    p.stdin.flush()
                    p.wait(timeout=10)
                except Exception:
                    p.kill()
            self._proc = None


class BridgePool:
    def __init__(self, tc: Toolchain, size: int, timeout_s: float = 120.0, heap: str = "2g") -> None:
        self._free: queue.Queue[BridgeClient] = queue.Queue()
        self.clients = [BridgeClient(tc, timeout_s, heap) for _ in range(max(1, size))]
        for c in self.clients:
            self._free.put(c)

    @contextmanager
    def client(self) -> Iterator[BridgeClient]:
        c = self._free.get()
        try:
            yield c
        finally:
            self._free.put(c)

    def verify(self, path: Path, min_sdk: int, max_sdk: int) -> BridgeResult:
        with self.client() as c:
            return c.verify(path, min_sdk, max_sdk)

    def close(self) -> None:
        for c in self.clients:
            c.close()
