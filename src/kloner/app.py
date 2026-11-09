"""Runtime wiring shared by every command: home, config, toolchain, quarantine, DB, bridge, HTTP."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import httpx

from kloner.acquire.http import Http
from kloner.acquire.quarantine import Quarantine
from kloner.anchor.store import AnchorStore
from kloner.config import KlonerConfig, load_config
from kloner.forensics.knownkeys import known_keys
from kloner.intel.db import IntelDB
from kloner.toolchain import Toolchain, ToolchainError, bridge_round_trip, load_toolchain
from kloner.verify.bridge import BridgePool
from kloner.verify.facts import Pipeline


class VerifierUnavailable(Exception):
    """Exit code 4 (INV-7): no degraded mode without the authoritative verifier."""


@dataclass
class Runtime:
    home: Path
    config: KlonerConfig
    workers: int | None = None
    proxy: str | None = None
    user_agent_override: str | None = None
    _db: IntelDB | None = field(default=None, init=False)
    _quarantine: Quarantine | None = field(default=None, init=False)
    _toolchain: Toolchain | None = field(default=None, init=False)
    _pool: BridgePool | None = field(default=None, init=False)
    _pipeline: Pipeline | None = field(default=None, init=False)
    _http: Http | None = field(default=None, init=False)
    transport: httpx.BaseTransport | None = field(default=None, init=False)

    @classmethod
    def open(cls, home: Path, **kw: object) -> Runtime:
        home.mkdir(parents=True, exist_ok=True)
        return cls(home=home, config=load_config(home), **kw)  # type: ignore[arg-type]

    @property
    def db(self) -> IntelDB:
        if self._db is None:
            self._db = IntelDB(self.home / "kloner.db")
        return self._db

    @property
    def quarantine(self) -> Quarantine:
        if self._quarantine is None:
            self._quarantine = Quarantine(self.home)
        return self._quarantine

    @property
    def anchors(self) -> AnchorStore:
        return AnchorStore(self.home, self.db)

    @property
    def known_keys(self) -> dict[str, str]:
        return known_keys()

    def toolchain(self) -> Toolchain:
        if self._toolchain is None:
            try:
                self._toolchain = load_toolchain(self.home)
            except ToolchainError as e:
                raise VerifierUnavailable(str(e)) from e
        return self._toolchain

    def fast_doctor(self) -> None:
        """Run before hunt/verify/fetch: stop with exit 4 if the verifier is not usable."""
        try:
            bridge_round_trip(self.toolchain())
        except ToolchainError as e:
            raise VerifierUnavailable(f"{e}; run: kloner doctor") from e

    def worker_count(self) -> int:
        return self.workers or self.config.general.workers

    def pipeline(self) -> Pipeline:
        if self._pipeline is None:
            tc = self.toolchain()
            self._pool = BridgePool(
                tc,
                self.worker_count(),
                timeout_s=self.config.limits.bridge_timeout_s,
                heap=self.config.limits.bridge_heap,
            )
            self._pipeline = Pipeline(self.home, tc, self.config, self.quarantine, self._pool)
        return self._pipeline

    def user_agent(self) -> str:
        return self.user_agent_override or self.config.user_agent()

    def fresh_http(self) -> Http:
        """A new client (fresh connections) with the run's settings."""
        n = self.config.network
        return Http(
            self.user_agent(),
            rate_per_host=n.rate_per_host,
            connect_timeout=n.connect_timeout_s,
            read_timeout=n.read_timeout_s,
            retries=n.retries,
            proxy=self.proxy,
            transport=self.transport,
        )

    def http(self) -> Http:
        if self._http is None:
            self._http = self.fresh_http()
        return self._http

    def close(self) -> None:
        if self._pool is not None:
            self._pool.close()
        if self._http is not None:
            self._http.close()
        if self._db is not None:
            self._db.close()
