"""Fetch the official test APKs of AOSP's apksig (Apache-2.0) at a pinned commit, SHA-256 verified.

These are real files produced by Google's own signing code with its public test keys, many of them broken on
purpose, so they exercise KLONER's verdict paths on real bytes (docs/DECISIONS.md D-057). They are third-party
APKs and are never committed: this script caches them outside the repository, in
``~/.cache/kloner/aosp-apksig/<commit>/`` (override with ``KLONER_AOSP_CACHE``), together with the upstream
LICENSE and a NOTICE. ``tests/aosp/manifest.json`` pins the commit and, for every file, its git blob id and its
SHA-256; a file that does not match both is refused.

The resources directory is downloaded as one gitiles archive (one request, so the host's rate limit is never
hit) and only the files named in the manifest are read from it, in memory. Nothing else is written; in
particular the archive's private test keys (``*.pk8``) are skipped.

Usage:
  python scripts/fetch_aosp_apksig.py           # fetch and verify every file of the manifest
  python scripts/fetch_aosp_apksig.py --pin     # maintainers: record blob ids and SHA-256 of new entries
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
import tarfile
import time
from pathlib import Path
from typing import Any

import httpx

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "tests" / "aosp" / "manifest.json"
BASE = "https://android.googlesource.com/platform/tools/apksig"
USER_AGENT = "kloner-tests (+https://github.com/0xKript/KLONER)"
MAX_ARCHIVE_BYTES = 256 << 20


class FetchError(Exception):
    """A file could not be fetched, or it is not the pinned content."""


def load_manifest(path: Path = MANIFEST) -> dict[str, Any]:
    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return data


def cache_dir(manifest: dict[str, Any]) -> Path:
    base = os.environ.get("KLONER_AOSP_CACHE")
    root = Path(base) if base else Path.home() / ".cache" / "kloner" / "aosp-apksig"
    return root / str(manifest["commit"])


def git_blob_id(data: bytes) -> str:
    """Git's object id of a blob: SHA-1 over ``blob <size>\\0<data>`` (an integrity check, not a security hash)."""
    return hashlib.sha1(b"blob %d\0" % len(data) + data, usedforsecurity=False).hexdigest()


def resources(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    return [*manifest["certs"], *manifest["apks"]]


class Client:
    """One request at a time, at most one per second, with backoff on HTTP 429 and 5xx."""

    def __init__(self, transport: httpx.BaseTransport | None = None, interval_s: float = 1.0) -> None:
        self.http = httpx.Client(
            timeout=300, headers={"User-Agent": USER_AGENT}, follow_redirects=False, transport=transport
        )
        self.interval_s = interval_s
        self._last = 0.0

    def get(self, url: str, *, attempts: int = 4) -> bytes:
        for attempt in range(attempts):
            wait = self._last + self.interval_s - time.monotonic()
            if wait > 0:
                time.sleep(wait)
            self._last = time.monotonic()
            try:
                r = self.http.get(url)
            except httpx.HTTPError as e:
                if attempt == attempts - 1:
                    raise FetchError(f"{type(e).__name__} for {url}") from e
                time.sleep(5 * 2**attempt)
                continue
            if r.status_code == 200:
                if len(r.content) > MAX_ARCHIVE_BYTES:
                    raise FetchError(f"response from {url} exceeds {MAX_ARCHIVE_BYTES} bytes")
                return r.content
            if r.status_code in (429, 500, 502, 503, 504) and attempt < attempts - 1:
                retry_after = r.headers.get("retry-after", "")
                time.sleep(min(120.0, float(retry_after)) if retry_after.isdigit() else 15.0 * 2**attempt)
                continue
            raise FetchError(f"HTTP {r.status_code} for {url}")
        raise FetchError(f"no response for {url}")

    def close(self) -> None:
        self.http.close()


def _check(entry: dict[str, Any], data: bytes, *, pin: bool) -> None:
    if pin and not entry.get("git_blob"):
        entry["git_blob"] = git_blob_id(data)
    if git_blob_id(data) != entry["git_blob"]:
        raise FetchError(f"{entry['file']}: git blob id does not match the pinned commit")
    digest = hashlib.sha256(data).hexdigest()
    if pin and not entry.get("sha256"):
        entry["sha256"] = digest
    elif digest != entry.get("sha256"):
        raise FetchError(f"{entry['file']}: SHA-256 {digest} is not the pinned value")


def _cached(out: Path, entry: dict[str, Any]) -> bool:
    p = out / entry["file"]
    return bool(entry.get("sha256")) and p.is_file() and hashlib.sha256(p.read_bytes()).hexdigest() == entry["sha256"]


def _write(out: Path, name: str, data: bytes) -> None:
    dest = out / name
    tmp = dest.with_name(dest.name + ".part")
    tmp.write_bytes(data)
    os.replace(tmp, dest)


def _blob_ids(http: Client, commit: str, path: str) -> dict[str, str]:
    raw = http.get(f"{BASE}/+/{commit}/{path}?format=JSON")
    data = json.loads(raw.decode("utf-8").removeprefix(")]}'"))
    return {e["name"]: e["id"] for e in data.get("entries", []) if e.get("type") == "blob"}


def fetch(manifest: dict[str, Any], *, client: Client | None = None, pin: bool = False) -> Path:
    """Make every manifest file available, verified, in the cache. Returns the cache directory."""
    out = cache_dir(manifest)
    out.mkdir(parents=True, exist_ok=True)
    wanted = {e["file"]: e for e in resources(manifest)}
    if any(name.endswith(".pk8") for name in wanted):
        raise FetchError("private keys are never fetched")
    own = client is None
    http = client or Client()
    commit, path = str(manifest["commit"]), str(manifest["path"])
    try:
        if pin:
            ids = _blob_ids(http, commit, path + "/")
            for name, e in wanted.items():
                e.setdefault("git_blob", ids[name])
            manifest["license"].setdefault("git_blob", _blob_ids(http, commit, "")["LICENSE"])
        lic = manifest["license"]
        if not _cached(out, lic):
            data = base64.b64decode(http.get(f"{BASE}/+/{commit}/{lic['path']}?format=TEXT"), validate=True)
            _check(lic, data, pin=pin)
            _write(out, lic["file"], data)
        missing = {n: e for n, e in wanted.items() if not _cached(out, e)}
        if missing:
            archive = http.get(f"{BASE}/+archive/{commit}/{path}.tar.gz")
            with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
                for member in tar:
                    name = member.name.removeprefix("./")
                    if not member.isfile() or name not in missing:
                        continue  # read only the pinned files; nothing else leaves the archive
                    fh = tar.extractfile(member)
                    if fh is None:
                        continue
                    data = fh.read()
                    _check(missing[name], data, pin=pin)
                    _write(out, name, data)
                    del missing[name]
            if missing:
                raise FetchError(f"not in the archive of {commit}: {', '.join(sorted(missing))}")
        _write(out, "NOTICE", (str(manifest["notice"]) + "\n").encode("utf-8"))
    finally:
        if own:
            http.close()
    return out


def verdict_table(manifest: dict[str, Any]) -> str:
    """The expected verdict of every case, grouped by outcome, as a Markdown table (for docs/DECISIONS.md)."""
    groups: dict[tuple[str, tuple[str, ...]], list[str]] = {}
    for e in manifest["apks"]:
        for case in e["cases"]:
            anchor = "+".join(case["anchor"]) if case["anchor"] else "none"
            anchor = anchor if len(anchor) < 40 else anchor[:24] + "…"
            key = (case["verdict"], tuple(case["labels"]))
            groups.setdefault(key, []).append(f"`{e['file']}` ({anchor})")
    order = ["GENUINE", "TAMPERED", "FORGED", "IMPERSONATOR", "ANOMALY", "ERROR", "MISMATCH", "INVALID", "UNANCHORED"]
    rows = ["| Verdict | Labels | Files (anchor) |", "|---|---|---|"]
    for (verdict, labels), files in sorted(groups.items(), key=lambda kv: (order.index(kv[0][0]), kv[0][1])):
        rows.append(f"| {verdict} | {', '.join(labels) or '—'} | {', '.join(sorted(files))} |")
    return "\n".join(rows)


def main() -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--manifest", type=Path, default=MANIFEST)
    ap.add_argument("--pin", action="store_true", help="record blob ids and SHA-256 of entries that lack them")
    ap.add_argument("--table", action="store_true", help="print the expected verdicts as Markdown (no network)")
    args = ap.parse_args()
    manifest = load_manifest(args.manifest)
    if args.table:
        print(verdict_table(manifest))
        return 0
    out = fetch(manifest, pin=args.pin)
    if args.pin:
        args.manifest.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"{out}: LICENSE and {len(resources(manifest))} files verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
