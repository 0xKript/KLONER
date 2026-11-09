"""Configuration (§14): ``~/.kloner/config.toml`` merged over safe defaults.

Credentials are never stored here: the config only names the environment variables that hold them.
"""

from __future__ import annotations

import os
import tomllib
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from kloner import __version__
from kloner.util.canonical import canonical_sha256
from kloner.util.limits import Limits

DEFAULT_SOURCES = ["local", "url", "apkpure", "aptoide", "fdroid", "huawei"]


class _Section(BaseModel):
    model_config = ConfigDict(extra="forbid")


class GeneralConfig(_Section):
    workers: int = Field(default=4, ge=1, le=64)
    user_agent: str = "kloner/{version} (+https://github.com/0xKript/kloner)"


class LimitsConfig(_Section):
    max_file_bytes: int = Field(default=1 << 30, gt=0)
    max_entries: int = Field(default=200_000, gt=0)
    max_total_uncompressed: int = Field(default=8 << 30, gt=0)
    max_ratio: int = Field(default=1000, gt=0)
    bridge_timeout_s: float = Field(default=120.0, gt=0)
    bridge_heap: str = "2g"
    worker_timeout_s: float = Field(default=300.0, gt=0)
    worker_memory_bytes: int = Field(default=4 << 30, gt=0)


class NetworkConfig(_Section):
    rate_per_host: float = Field(default=1.0, gt=0)
    connect_timeout_s: float = Field(default=15.0, gt=0)
    read_timeout_s: float = Field(default=120.0, gt=0)
    retries: int = Field(default=3, ge=0, le=10)
    concurrency: int = Field(default=4, ge=1, le=32)


class SourcesConfig(_Section):
    enabled: list[str] = Field(default_factory=lambda: list(DEFAULT_SOURCES))
    googleplay_email_env: str = "KLONER_PLAY_EMAIL"
    # The name of an environment variable, not a secret.
    googleplay_token_env: str = "KLONER_PLAY_AAS_TOKEN"  # noqa: S105


class ForensicsConfig(_Section):
    repackaged_min_jaccard: float = Field(default=0.60, ge=0, le=1)
    impostor_max_jaccard: float = Field(default=0.20, ge=0, le=1)
    dhash_max_distance: int = Field(default=10, ge=0, le=64)
    label_max_edit_distance: int = Field(default=2, ge=0, le=10)
    timeout_s: float = Field(default=300.0, gt=0)


class KlonerConfig(_Section):
    general: GeneralConfig = Field(default_factory=GeneralConfig)
    limits: LimitsConfig = Field(default_factory=LimitsConfig)
    network: NetworkConfig = Field(default_factory=NetworkConfig)
    sources: SourcesConfig = Field(default_factory=SourcesConfig)
    forensics: ForensicsConfig = Field(default_factory=ForensicsConfig)

    def parse_limits(self) -> Limits:
        return Limits(
            max_file_bytes=self.limits.max_file_bytes,
            max_entries=self.limits.max_entries,
            max_total_uncompressed=self.limits.max_total_uncompressed,
            max_ratio=self.limits.max_ratio,
        )

    def user_agent(self) -> str:
        return self.general.user_agent.replace("{version}", __version__)

    def sha256(self) -> str:
        return canonical_sha256(self.model_dump(mode="json"))


def default_home() -> Path:
    env = os.environ.get("KLONER_HOME")
    return Path(env) if env else Path.home() / ".kloner"


def load_config(home: Path) -> KlonerConfig:
    path = home / "config.toml"
    if not path.is_file():
        return KlonerConfig()
    with path.open("rb") as f:
        data: dict[str, Any] = tomllib.load(f)
    return KlonerConfig.model_validate(data)


DEFAULT_CONFIG_TOML = """\
# KLONER configuration. Values shown are the defaults.
[general]
workers = 4
user_agent = "kloner/{version} (+https://github.com/0xKript/kloner)"

[limits]
max_file_bytes = 1073741824
max_entries = 200000
max_total_uncompressed = 8589934592
max_ratio = 1000
bridge_timeout_s = 120
bridge_heap = "2g"

[network]
rate_per_host = 1.0
connect_timeout_s = 15
read_timeout_s = 120
retries = 3

[sources]
enabled = ["local", "url", "apkpure", "aptoide", "fdroid", "huawei"]
googleplay_email_env = "KLONER_PLAY_EMAIL"
googleplay_token_env = "KLONER_PLAY_AAS_TOKEN"

[forensics]
repackaged_min_jaccard = 0.60
impostor_max_jaccard = 0.20
dhash_max_distance = 10
label_max_edit_distance = 2
"""
