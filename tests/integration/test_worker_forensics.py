"""In-process tests of the worker and forensics code (the parent runs them in a bounded subprocess)."""

from __future__ import annotations

import json
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import Any

import pytest

from kloner.app import Runtime
from kloner.forensics.capabilities import capabilities
from kloner.forensics.diff import diff_views
from kloner.forensics.extract import entropy, extract_view
from kloner.forensics.metadata import cross_check
from kloner.forensics.overlap import jaccard, overlap
from kloner.forensics.payload import payload_ids, short_payload
from kloner.forensics.runner import Reference, select_reference
from kloner.models import Claimed, Evaluation, Verdict
from kloner.selftest import corpus as c
from kloner.util.limits import DEFAULT_LIMITS
from kloner.verify.worker import collect, limits_to_dict

pytestmark = pytest.mark.toolchain


def _collect(rt: Runtime, path: Path) -> dict[str, Any]:
    sha, _ = rt.quarantine.ingest_file(path, 1 << 30)
    return collect(
        {
            "op": "facts",
            "path": str(rt.quarantine.path_for(sha)),
            "sha256": sha,
            "expected_package": None,
            "aapt2": rt.toolchain().aapt2,
            "limits": limits_to_dict(DEFAULT_LIMITS),
            "home": str(rt.home),
        }
    )


def test_worker_collect_paths(fresh_rt: Runtime, corpus: dict[str, Any], tmp_path: Path) -> None:
    files = corpus["files"]
    apk = _collect(fresh_rt, files["C-01"])
    f = apk["facts"]
    assert f["intake"]["format"] == "apk" and f["manifest"]["package"] == c.FIXTURE_PACKAGE
    assert f["brand"]["icon_hashes"] and f["brand"]["default_label"] == "Kloner Fixture"
    assert f["native_inventory"]["pairs"] and f["androguard_inventory"]["v2"]
    bundle = _collect(fresh_rt, files["C-24"])
    assert bundle["facts"]["intake"]["format"] == "bundle" and len(bundle["members"]) == 4
    assert {m["role_hint"] for m in bundle["members"]} == {"apk", "metadata"}
    assert _collect(fresh_rt, files["C-22"])["facts"]["intake"]["reason"] == "NOT_ZIP"
    assert _collect(fresh_rt, files["C-23"])["facts"]["intake"]["reason"] == "AAB_NOT_DISTRIBUTABLE"
    assert _collect(fresh_rt, files["C-06"])["facts"]["archive"]["reason"] == "CORRUPT"
    assert _collect(fresh_rt, files["C-07"])["facts"]["archive"]["reason"] == "CORRUPT"
    plain = tmp_path / "plain.zip"
    with zipfile.ZipFile(plain, "w") as z:
        z.writestr("readme.txt", "hi")
    assert _collect(fresh_rt, plain)["facts"]["intake"]["reason"] == "NOT_ANDROID"


def test_worker_main_protocol(fresh_rt: Runtime) -> None:
    out = subprocess.run(
        [sys.executable, "-I", "-m", "kloner.verify.worker"],
        input=b'{"op": "bogus"}',
        capture_output=True,
        check=False,
        timeout=120,
    )
    assert json.loads(out.stdout)["ok"] is False
    out = subprocess.run(
        [sys.executable, "-I", "-m", "kloner.verify.worker"],
        input=b"not json",
        capture_output=True,
        check=False,
        timeout=120,
    )
    assert json.loads(out.stdout)["ok"] is False


def test_forensic_view_diff_capabilities(fresh_rt: Runtime, corpus: dict[str, Any], tmp_path: Path) -> None:
    sg = c.Signer(fresh_rt.toolchain())
    variant = sg.sign(c.fixture_path("modern_v2"), tmp_path / "v2-foreign.apk", corpus["keys"]["foreign"])
    ref_sha, _ = fresh_rt.quarantine.ingest_file(corpus["files"]["C-01"], 1 << 30)
    var_sha, _ = fresh_rt.quarantine.ingest_file(variant, 1 << 30)
    lim = limits_to_dict(DEFAULT_LIMITS)
    rv = extract_view({"path": str(fresh_rt.quarantine.path_for(ref_sha)), "sha256": ref_sha, "limits": lim})
    sv = extract_view({"path": str(fresh_rt.quarantine.path_for(var_sha)), "sha256": var_sha, "limits": lim})
    assert rv["manifest"]["launcher"] == "dev.kloner.fixture.MainActivity"
    d = diff_views(sv, rv)
    assert d["manifest"]["permissions"]["added"] == ["android.permission.INTERNET"]
    assert d["code"]["classes_added"] == ["Ldev/kloner/fixture/Settings;"]
    assert "https://example.org/kloner-fixture" in d["code"]["new_indicators"]["urls"]
    caps = capabilities(d)
    assert caps["capabilities"] == ["NEW_NETWORK_ENDPOINTS(2)"] or caps["capabilities"][-1].startswith("NEW_NETWORK")
    assert "new network endpoint" in caps["line"]
    added = {k: sv["classes"][k] for k in d["code"]["classes_added"]}
    ids = payload_ids(added)
    assert ids is not None and short_payload(ids[0]).startswith("P-")
    ov = overlap(sv, rv, 0.6, 0.2)
    assert ov["heuristic"] and 0 < ov["j_class"] < 1
    assert jaccard(set(), set()) == 1.0 and payload_ids({}) is None
    assert entropy(b"") == 0.0 and entropy(bytes(range(256))) == 8.0


def test_capability_table_rules() -> None:
    def base() -> dict[str, Any]:
        return {
            "manifest": {"permissions": {"added": [], "removed": []}, "components_added": []},
            "code": {
                "risky_api_deltas": {},
                "packages_added": [],
                "new_indicators": {"urls": [], "domains": [], "ips": []},
            },
            "files": {"embedded_payloads": []},
        }

    d = base()
    d["manifest"]["permissions"]["added"] = [
        "android.permission.RECEIVE_SMS",
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.READ_CONTACTS",
        "android.permission.CAMERA",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.REQUEST_INSTALL_PACKAGES",
        "android.permission.RECEIVE_BOOT_COMPLETED",
    ]
    d["manifest"]["components_added"] = [
        {
            "type": "service",
            "name": "a.S",
            "actions": ["android.accessibilityservice.AccessibilityService"],
            "permission": "android.permission.BIND_ACCESSIBILITY_SERVICE",
        },
        {
            "type": "receiver",
            "name": "a.R",
            "actions": ["android.app.action.DEVICE_ADMIN_ENABLED"],
            "permission": "android.permission.BIND_DEVICE_ADMIN",
        },
        {
            "type": "service",
            "name": "a.N",
            "actions": ["android.service.notification.NotificationListenerService"],
            "permission": "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
        },
    ]
    d["code"]["risky_api_deltas"] = {
        "DexClassLoader": {"before": 0, "after": 2},
        "SmsManager": {"before": 0, "after": 1},
    }
    d["code"]["packages_added"] = ["com.startapp.sdk"]
    d["code"]["new_indicators"] = {"urls": ["https://c2.example/x"], "domains": ["c2.example"], "ips": ["203.0.113.7"]}
    d["files"]["embedded_payloads"] = [{"name": "assets/x.bin", "type": "dex"}]
    caps = capabilities(d)
    assert set(caps["capabilities"]) >= {
        "SMS_INTERCEPTION",
        "OVERLAY",
        "ACCESSIBILITY_ABUSE",
        "DYNAMIC_CODE_LOADING",
        "DROPPER",
        "DEVICE_ADMIN",
        "NOTIFICATION_ACCESS",
        "CONTACTS_ACCESS",
        "LOCATION",
        "AUDIO_OR_CAMERA",
        "PACKAGE_INSTALL",
        "PERSISTENCE",
        "ADWARE_SDK",
        "NEW_NETWORK_ENDPOINTS(3)",
    }
    assert caps["line"].startswith("Injected: SMS interception")
    assert capabilities(base())["line"] == "Injected: nothing detected by the capability table"


def test_metadata_cross_check(fresh_rt: Runtime, corpus: dict[str, Any]) -> None:
    sha, _ = fresh_rt.quarantine.ingest_file(corpus["files"]["C-01"], 1 << 30)
    sr = fresh_rt.pipeline().evaluate(
        sha, c.FIXTURE_PACKAGE, {c.FIXTURE_PACKAGE: corpus["anchors"]["v"]}, fresh_rt.known_keys
    )
    path = fresh_rt.quarantine.path_for(sha)
    from kloner.util.hashing import third_party_digests

    d = third_party_digests(path)
    good = Claimed(
        version_code=1,
        version_name="1.0",
        md5=d["md5"],
        sha256=d["sha256"],
        package=c.FIXTURE_PACKAGE,
        signer_sha256=corpus["keys"]["vendor"].sha256,
    )
    assert cross_check(good, sr.evaluation, sr.facts, path) == []
    bad = Claimed(package="x.y", signer_sha256="00" * 32, sha1="0" * 40)
    out = cross_check(bad, sr.evaluation, sr.facts, path)
    assert any("package" in o for o in out) and any("SHA-256" in o for o in out) and any("SHA1" in o for o in out)


def test_reference_selection_order(corpus: dict[str, Any]) -> None:
    def ev(
        sha: str, verdict: Verdict, vc: int | None, split: str | None = None, pkg: str = c.FIXTURE_PACKAGE
    ) -> Evaluation:
        return Evaluation(
            sample_sha256=sha, size=1, format="apk", package=pkg, version_code=vc, split=split, verdict=verdict
        )

    sample = ev("s" * 64, Verdict.FORGED, 5)
    pool = [
        ev("a" * 64, Verdict.GENUINE, 5, "config.en"),
        ev("b" * 64, Verdict.GENUINE, 5),
        ev("c" * 64, Verdict.GENUINE, 3),
    ]
    assert select_reference(sample, pool, None, lambda s: False) == Reference("b" * 64, "same-version-same-variant", 5)
    assert select_reference(sample, pool[:1], None, lambda s: False).kind == "same-version"  # type: ignore[union-attr]
    assert select_reference(sample, pool[2:], None, lambda s: False).kind == "nearest-version"  # type: ignore[union-attr]
    got = select_reference(sample, pool[2:], None, lambda s: False, acquire=lambda vc: ev("d" * 64, Verdict.GENUINE, 5))
    assert got is not None and got.kind == "acquired-same-version"
    anchor = corpus["anchors"]["v"].model_copy(deep=True)
    from kloner.models import ReleaseRef

    anchor.release_refs = [
        ReleaseRef(version_code=1, file_sha256="e" * 64, provenance="VENDOR_HTTPS", observed_utc="x")
    ]
    assert select_reference(sample, [], anchor, lambda s: True).kind == "anchor-source"  # type: ignore[union-attr]
    assert select_reference(sample, [], None, lambda s: False) is None
    bundle = ev("f" * 64, Verdict.GENUINE, 5).model_copy(update={"format": "bundle"})
    assert select_reference(sample, [bundle], None, lambda s: False) is None  # a container is never a reference


def test_icons_and_labels_from_apk(corpus: dict[str, Any]) -> None:
    from androguard.core.apk import APK

    from kloner.container.zipstrict import open_archive
    from kloner.impersonation.icons import dhash, resolve_icon_assets
    from kloner.impersonation.labels import extract_labels, normalize_label, resource_id
    from kloner.util.logging import quiet_third_party

    quiet_third_party()
    path = corpus["files"]["C-01"]
    apk = APK(str(path))
    default, labels = extract_labels(apk)
    assert default == "Kloner Fixture" and labels == ["Kloner Fixture"]
    paths, hashes, dhashes, err = resolve_icon_assets(apk, open_archive(path, DEFAULT_LIMITS))
    assert paths == ["res/mipmap-mdpi-v4/ic_launcher.png"] and len(hashes) == 1 and len(dhashes) == 1 and err is None
    assert dhash(b"not an image") is None
    assert normalize_label("  \uff2bloner\tFIXTURE ") == "kloner fixture"
    assert resource_id("@7F010000") == 0x7F010000 and resource_id("plain") is None


def test_a_cross_version_diff_does_not_call_release_changes_injected() -> None:
    # DuckDuckGo's official 5.114.3, compared with a newer official release, showed "Injected: dropper · 248 new
    # network endpoints": the differences between two releases, not an injection (D-068).
    d: dict[str, Any] = {
        "manifest": {"permissions": {"added": [], "removed": []}, "components_added": []},
        "code": {"risky_api_deltas": {}, "packages_added": [], "new_indicators": {"urls": ["https://a.example"]}},
        "files": {"embedded_payloads": [{"type": "dex", "name": "assets/x.dex"}]},
    }
    same = capabilities(d)["line"]
    other = capabilities(d, other_version=51880000)["line"]
    assert same.startswith("Injected: ")
    assert other.startswith("Changed against version code 51880000, another version (release changes included): ")
    assert "Injected" not in other and other.endswith("dropper · 1 new network endpoint")


def test_an_impostor_overlap_is_not_called_an_injection_in_reports() -> None:
    # The FORGED "Spotify" 110.5 from the mirror sweep shares almost no code with Spotify; its report said
    # "Injected: overlay · location · …". Hunt and verify reports now word it as `kloner diff` does (D-063, D-068).
    from kloner.forensics.capabilities import for_overlap

    line = "Injected: overlay · location · audio/camera · 39 new network endpoints"
    assert for_overlap(line, "IMPOSTOR").startswith("Only in the sample (different code base, not an injection): ")
    assert for_overlap(line, "REPACKAGED") == line and for_overlap(line, None) == line
