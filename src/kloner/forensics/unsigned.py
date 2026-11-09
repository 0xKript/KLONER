"""Unsigned-data inventory (§10.7): every non-signature pair of the APK Signing Block."""

from __future__ import annotations

from typing import Any

from kloner.models import NativeInventory


def inventory(native: NativeInventory | None) -> list[dict[str, Any]]:
    if native is None:
        return []
    return [
        {"id": p.id_hex, "name": p.name, "kind": p.kind, "size": p.size, "sha256": p.sha256, "preview": p.preview}
        for p in native.pairs
        if p.kind in ("unsigned", "padding", "source_stamp")
    ]
