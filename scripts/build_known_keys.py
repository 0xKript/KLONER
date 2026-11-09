#!/usr/bin/env python3
"""Generate data/known_keys.json from authoritative sources only (§10.6).

Every entry is fetched from the owning project's official repository; nothing is hand-typed.
Each entry records: name, cert SHA-256 (over DER), source URL, retrieval date, source-file hash.

Sources:
  * AOSP platform/build: target/product/security/*.x509.pem (testkey, platform, shared, media,
    networkstack, sdk_sandbox, bluetooth, nfc, cts_uicc_2021)

Usage: python scripts/build_known_keys.py [--out data/known_keys.json]
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import httpx
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

ROOT = Path(__file__).resolve().parents[1]
GITILES = "https://android.googlesource.com/platform/build/+/{ref}/target/product/security/"
UA = "kloner-build-known-keys/1 (+https://github.com/0xKript/kloner)"


def fetch_text(client: httpx.Client, url: str) -> bytes:
    r = client.get(url, params={"format": "TEXT"})
    r.raise_for_status()
    return base64.b64decode(r.content)


def aosp(client: httpx.Client, ref: str) -> list[dict[str, str]]:
    base = GITILES.format(ref=ref)
    listing = client.get(base, params={"format": "JSON"})
    listing.raise_for_status()
    tree = json.loads(listing.text[listing.text.index("{") :])
    out = []
    for entry in tree["entries"]:
        name = entry["name"]
        if not name.endswith(".x509.pem"):
            continue
        url = base + name
        pem = fetch_text(client, url)
        cert = x509.load_pem_x509_certificate(pem)
        der = cert.public_bytes(Encoding.DER)
        key_name = "AOSP_" + name[: -len(".x509.pem")].upper()
        out.append(
            {
                "name": key_name,
                "cert_sha256": hashlib.sha256(der).hexdigest(),
                "subject": cert.subject.rfc4514_string(),
                "source_url": url,
                "source_tree": tree.get("id", ""),
                "source_file_sha256": hashlib.sha256(pem).hexdigest(),
                "retrieved_utc": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
        )
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=Path, default=ROOT / "data" / "known_keys.json")
    ap.add_argument("--ref", default="refs/heads/main")
    args = ap.parse_args(argv)
    with httpx.Client(timeout=60, headers={"User-Agent": UA}, follow_redirects=False) as client:
        entries = aosp(client, args.ref)
    if not entries:
        print("no certificates fetched", file=sys.stderr)
        return 1
    entries.sort(key=lambda e: e["name"])
    doc = {"schema": "kloner.known_keys/1", "keys": entries}
    args.out.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    for e in entries:
        print(f"{e['name']:28s} {e['cert_sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
