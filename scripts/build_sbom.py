"""CycloneDX 1.5 SBOM for a KLONER release (spec §16.8).

Components:

* every Python package pinned in ``requirements.lock``, with the SHA-256 digests the lock requires;
* the pinned toolchain artifacts that ``kloner setup`` checks: ``apksigner.jar`` of Android build-tools
  36.0.0 and the apkeep 1.1.0 release binaries.

The output is deterministic. Set ``SOURCE_DATE_EPOCH`` to fix the timestamp, as reproducible builds do.

Usage: python scripts/build_sbom.py [--lock requirements.lock] [--out dist/kloner-<version>.cdx.json]
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sys
import uuid
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from kloner import __version__  # noqa: E402
from kloner.toolchain import (  # noqa: E402
    APKEEP_ASSETS,
    APKEEP_URL,
    APKEEP_VERSION,
    APKSIGNER_JAR_SHA256,
    PINNED_BUILD_TOOLS,
)

_REQ = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;\\]+)")
_HASH = re.compile(r"--hash=sha256:([0-9a-f]{64})")


def normalize(name: str) -> str:
    """PEP 503 name, as used in package URLs."""
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_lock(text: str) -> list[tuple[str, str, list[str], str | None]]:
    """(name, version, SHA-256 digests, environment marker) for every requirement of a hashed lock file."""
    out: list[tuple[str, str, list[str], str | None]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = _REQ.match(line)
        if m:
            marker = line.split(";", 1)[1].rstrip("\\").strip() if ";" in line else None
            out.append((normalize(m.group(1)), m.group(2), [], marker))
        if out:
            out[-1][2].extend(_HASH.findall(line))
    return out


def _timestamp() -> str:
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    moment = dt.datetime.fromtimestamp(int(epoch), dt.UTC) if epoch else dt.datetime.now(dt.UTC)
    return moment.replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def build(lock: Path) -> dict[str, Any]:
    components: list[dict[str, Any]] = []
    for name, version, digests, marker in parse_lock(lock.read_text(encoding="utf-8")):
        purl = f"pkg:pypi/{name}@{version}"
        comp: dict[str, Any] = {
            "type": "library",
            "bom-ref": purl,
            "name": name,
            "version": version,
            "purl": purl,
            "hashes": [{"alg": "SHA-256", "content": d} for d in sorted(set(digests))],
        }
        if marker:
            comp["properties"] = [{"name": "kloner:environment-marker", "value": marker}]
        components.append(comp)
    for digest in sorted(APKSIGNER_JAR_SHA256[PINNED_BUILD_TOOLS]):
        components.append(
            {
                "type": "application",
                "bom-ref": f"android-build-tools-{PINNED_BUILD_TOOLS}-apksigner.jar",
                "group": "com.android",
                "name": "apksigner.jar",
                "version": PINNED_BUILD_TOOLS,
                "description": f"Android SDK build-tools {PINNED_BUILD_TOOLS} lib/apksigner.jar (Google's apksig)",
                "hashes": [{"alg": "SHA-256", "content": digest}],
                "externalReferences": [
                    {"type": "distribution", "url": "https://dl.google.com/android/repository/repository2-3.xml"}
                ],
            }
        )
    for (os_name, arch), (asset, digest) in sorted(APKEEP_ASSETS.items()):
        components.append(
            {
                "type": "application",
                "bom-ref": f"apkeep-{APKEEP_VERSION}-{asset}",
                "group": "EFForg",
                "name": "apkeep",
                "version": APKEEP_VERSION,
                "hashes": [{"alg": "SHA-256", "content": digest}],
                "externalReferences": [
                    {"type": "distribution", "url": APKEEP_URL.format(version=APKEEP_VERSION, asset=asset)}
                ],
                "properties": [{"name": "kloner:platform", "value": f"{os_name}/{arch}"}],
            }
        )
    body = json.dumps(components, sort_keys=True).encode("utf-8")
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, body.hex())}",
        "version": 1,
        "metadata": {
            "timestamp": _timestamp(),
            "tools": {"components": [{"type": "application", "name": "scripts/build_sbom.py"}]},
            "component": {
                "type": "application",
                "bom-ref": f"pkg:pypi/kloner@{__version__}",
                "name": "kloner",
                "version": __version__,
                "purl": f"pkg:pypi/kloner@{__version__}",
                "licenses": [{"license": {"id": "Apache-2.0"}}],
            },
        },
        "components": components,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--lock", type=Path, default=ROOT / "requirements.lock")
    ap.add_argument("--out", type=Path, default=ROOT / "dist" / f"kloner-{__version__}.cdx.json")
    args = ap.parse_args()
    bom = build(args.lock)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(bom, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"{args.out}: {len(bom['components'])} components")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
