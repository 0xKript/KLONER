"""Structured JSON-lines logging (§16.5) to ~/.kloner/logs/, keyed by run ID.

Logs never contain sample bytes or credentials: only identifiers, hashes, URLs and statuses.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from kloner.util.timeutil import now_iso

LOGGER_NAME = "kloner"
_SECRET_KEYS = ("token", "password", "secret", "authorization", "cookie", "aas")


class JsonLineFormatter(logging.Formatter):
    def __init__(self, run_id: str | None) -> None:
        super().__init__()
        self.run_id = run_id

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": now_iso(),
            "level": record.levelname.lower(),
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if self.run_id:
            payload["run_id"] = self.run_id
        extra = getattr(record, "kloner", None)
        if isinstance(extra, dict):
            payload.update({k: ("<redacted>" if _is_secret(k) else v) for k, v in extra.items()})
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, sort_keys=True, default=str)


def _is_secret(key: str) -> bool:
    k = key.lower()
    return any(s in k for s in _SECRET_KEYS)


def setup_logging(home: Path, run_id: str | None, debug: bool = False) -> Path:
    logs = home / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    path = logs / f"{run_id or 'session'}.jsonl"
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(logging.DEBUG if debug else logging.INFO)
    for h in list(logger.handlers):
        logger.removeHandler(h)
        h.close()
    handler = logging.FileHandler(path, encoding="utf-8")
    handler.setFormatter(JsonLineFormatter(run_id))
    logger.addHandler(handler)
    logger.propagate = False
    return path


def bind_run(run_id: str) -> None:
    """Tag every following line with the run that has just started (the file stays per invocation)."""
    for h in logging.getLogger(LOGGER_NAME).handlers:
        if isinstance(h.formatter, JsonLineFormatter):
            h.formatter.run_id = run_id


def safe_url(url: str | None) -> str | None:
    """Scheme, host and path only: query strings and user info can carry tokens."""
    if not url:
        return url
    p = urlsplit(url)
    if p.scheme.lower() not in ("http", "https"):
        return url
    return urlunsplit((p.scheme, p.netloc.rsplit("@", 1)[-1], p.path, "", ""))


def get_logger(name: str = LOGGER_NAME) -> logging.Logger:
    return logging.getLogger(name if name.startswith(LOGGER_NAME) else f"{LOGGER_NAME}.{name}")


def log_event(logger: logging.Logger, msg: str, **fields: Any) -> None:
    logger.info(msg, extra={"kloner": fields})


def quiet_third_party() -> None:
    """androguard logs through loguru at import time; keep it out of KLONER's output."""
    try:
        from loguru import logger as loguru_logger

        loguru_logger.remove()
        loguru_logger.disable("androguard")
    except ImportError:  # pragma: no cover - loguru ships with androguard
        pass
