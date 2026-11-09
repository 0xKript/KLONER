"""Payload fingerprints (§10.4).

* ``payload_id`` = SHA-256 over the sorted list of (added class name, class bytecode digest).
* ``payload_shape_id`` = SHA-256 over the sorted bytecode digests alone (survives renaming).
"""

from __future__ import annotations

import hashlib


def payload_ids(added: dict[str, str]) -> tuple[str, str] | None:
    if not added:
        return None
    pid = hashlib.sha256("\n".join(f"{n}\t{d}" for n, d in sorted(added.items())).encode()).hexdigest()
    shape = hashlib.sha256("\n".join(sorted(added.values())).encode()).hexdigest()
    return pid, shape


def short_payload(pid: str) -> str:
    return f"P-{pid[:4]}…"
