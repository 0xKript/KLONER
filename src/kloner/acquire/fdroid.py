"""F-Droid repository index (index-v2), verified against the SHA-256 published in entry.json.

Format confirmed live: packages[P].versions[<sha256>] = {file: {name, sha256,
size}, manifest: {versionCode, versionName, signer: {sha256: [...]}, usesSdk: {...}}, ...}.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import TYPE_CHECKING, Any

from kloner.acquire.http import HttpError
from kloner.util.hashing import sha256_file

if TYPE_CHECKING:
    from kloner.app import Runtime

REPO = "https://f-droid.org/repo"
ENTRY = f"{REPO}/entry.json"


class FdroidIndex:
    def __init__(self, rt: Runtime, repo: str = REPO) -> None:
        self.rt = rt
        self.repo = repo.rstrip("/")
        self.cache = rt.home / "cache" / "fdroid"
        self.cache.mkdir(parents=True, exist_ok=True)
        self._data: dict[str, Any] | None = None

    def _load(self) -> dict[str, Any]:
        if self._data is not None:
            return self._data
        http = self.rt.http()
        entry = json.loads(http.get_document(f"{self.repo}/entry.json", 1 << 20).content)
        idx = entry["index"]
        name, digest, size = idx["name"], idx["sha256"].lower(), int(idx["size"])
        limit = self.rt.config.parse_limits().max_fdroid_index_bytes
        if size > limit:
            raise HttpError(f"F-Droid index of {size} bytes exceeds the {limit}-byte limit")
        path = self.cache / f"index-v2-{digest[:16]}.json"
        if not (path.is_file() and sha256_file(path) == digest):
            for old in self.cache.glob("index-v2-*.json"):
                old.unlink(missing_ok=True)
            tmp = path.with_suffix(".part")
            from kloner.acquire.quarantine import Sink

            with tmp.open("wb") as fh:
                sink = Sink(fh, tmp, size)
                http.download(f"{self.repo}{name}", sink)
            if sha256_file(tmp) != digest:
                tmp.unlink(missing_ok=True)
                raise HttpError("F-Droid index does not match the SHA-256 in entry.json")
            os.replace(tmp, path)
        self._data = json.loads(path.read_text(encoding="utf-8"))
        return self._data

    def _version(self, package: str, v: dict[str, Any]) -> dict[str, Any]:
        f, m = v["file"], v["manifest"]
        return {
            "package": package,
            "version_code": int(m["versionCode"]),
            "version_name": m.get("versionName"),
            "file_name": f["name"],
            "sha256": f["sha256"].lower(),
            "size": int(f.get("size", 0)),
            "url": f"{self.repo}{f['name']}",
            "signers": [s.lower() for s in (m.get("signer") or {}).get("sha256", [])],
            "min_sdk": (m.get("usesSdk") or {}).get("minSdkVersion"),
        }

    def versions(self, package: str) -> list[dict[str, Any]]:
        pkg = self._load().get("packages", {}).get(package)
        if not pkg:
            return []
        out = [self._version(package, v) for v in pkg.get("versions", {}).values()]
        out.sort(key=lambda v: v["version_code"], reverse=True)
        return out

    def search(self, query: str, limit: int) -> list[tuple[str, str | None, dict[str, Any]]]:
        q = query.casefold().strip()
        hits: list[tuple[str, str | None, dict[str, Any]]] = []
        for package, pkg in sorted(self._load().get("packages", {}).items()):
            names = (pkg.get("metadata") or {}).get("name") or {}
            labels = list(names.values()) if isinstance(names, dict) else [str(names)]
            if any(q and q in str(n).casefold() for n in labels):
                vs = sorted(
                    pkg.get("versions", {}).values(), key=lambda v: int(v["manifest"]["versionCode"]), reverse=True
                )
                if vs:
                    hits.append((package, str(labels[0]) if labels else None, self._version(package, vs[0])))
            if len(hits) >= limit:
                break
        return hits

    def download(self, version: dict[str, Any]) -> tuple[str, str]:
        q = self.rt.quarantine
        with q.sink(self.rt.config.limits.max_file_bytes) as s:
            dl = self.rt.http().download(version["url"], s)
        sha, _ = q.finalize(s)
        if sha != version["sha256"]:
            raise HttpError(f"F-Droid file {version['file_name']} does not match the index SHA-256")
        return sha, dl.final_url


def cached_index_path(home: Path) -> Path | None:
    files = sorted((home / "cache" / "fdroid").glob("index-v2-*.json"))
    return files[-1] if files else None
