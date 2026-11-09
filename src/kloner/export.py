"""``kloner export samples`` (§8.4): package a run's hostile samples for analyst sharing.

Only on explicit request. The archive uses the standard malware-handling convention (password
"infected") so that samples are not opened or scanned by accident. Python's standard library can
only write unencrypted ZIPs, so KLONER writes AES-256 7-Zip-compatible ZIPs through ``7z`` when it
is installed and refuses otherwise: it never writes an unprotected archive of hostile files.
"""

from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

from kloner.app import Runtime
from kloner.models import HOSTILE, Verdict
from kloner.util import proc


def export_samples(rt: Runtime, run_id: str, password: str, out: Path | None) -> tuple[Path, int]:
    seven = shutil.which("7z") or shutil.which("7za") or shutil.which("7zz")
    if seven is None:
        raise ValueError("7-Zip (7z) is required to write a password-protected archive; install p7zip/7-Zip and re-run")
    rows = rt.db.run_samples(run_id)
    if not rows:
        raise ValueError(f"unknown or empty run {run_id}")
    hostile = [str(r["sample_sha256"]) for r in rows if Verdict(r["verdict"]) in HOSTILE]
    if not hostile:
        raise ValueError(f"run {run_id} has no hostile samples to export")
    dest = out or (rt.home / "runs" / run_id / f"samples-{run_id}.zip")
    dest.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=rt.quarantine.incoming) as tmp:
        files = []
        for sha in hostile:
            src = rt.quarantine.path_for(sha)
            target = Path(tmp) / f"{sha}.bin"
            shutil.copyfile(src, target)
            files.append(target)
        manifest = Path(tmp) / "MANIFEST.json"
        manifest.write_text(
            json.dumps(
                {"run": run_id, "samples": hostile, "warning": "hostile Android samples: never install or execute"},
                indent=2,
            ),
            encoding="utf-8",
        )
        res = proc.run(
            [seven, "a", "-tzip", f"-p{password}", "-mem=AES256", "-y", str(dest), str(manifest), *map(str, files)],
            timeout_s=1800,
        )
        if not res.ok:
            raise ValueError(f"7z failed: {res.err_text()[-400:]}")
    return dest, len(hostile)
