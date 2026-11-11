"""Injected-capability summary (§10.3): a fixed, documented, table-driven mapping from deltas.

Deterministic and explanatory only; it never influences a verdict. The README reproduces
this table.
"""

from __future__ import annotations

from typing import Any

PERMISSION_RULES: dict[str, tuple[str, ...]] = {
    "SMS_INTERCEPTION": (
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_SMS",
        "android.permission.SEND_SMS",
    ),
    "OVERLAY": ("android.permission.SYSTEM_ALERT_WINDOW",),
    "CONTACTS_ACCESS": ("android.permission.READ_CONTACTS",),
    "LOCATION": (
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.ACCESS_BACKGROUND_LOCATION",
    ),
    "AUDIO_OR_CAMERA": ("android.permission.RECORD_AUDIO", "android.permission.CAMERA"),
    "PACKAGE_INSTALL": ("android.permission.REQUEST_INSTALL_PACKAGES", "android.permission.INSTALL_PACKAGES"),
    "PERSISTENCE": ("android.permission.RECEIVE_BOOT_COMPLETED",),
}
COMPONENT_ACTIONS: dict[str, tuple[str, ...]] = {
    "SMS_INTERCEPTION": ("android.provider.Telephony.SMS_RECEIVED", "android.provider.Telephony.SMS_DELIVER"),
    "ACCESSIBILITY_ABUSE": ("android.accessibilityservice.AccessibilityService",),
    "DEVICE_ADMIN": ("android.app.action.DEVICE_ADMIN_ENABLED",),
    "NOTIFICATION_ACCESS": ("android.service.notification.NotificationListenerService",),
    "PERSISTENCE": ("android.intent.action.BOOT_COMPLETED", "android.intent.action.LOCKED_BOOT_COMPLETED"),
}
COMPONENT_PERMISSIONS: dict[str, tuple[str, ...]] = {
    "ACCESSIBILITY_ABUSE": ("android.permission.BIND_ACCESSIBILITY_SERVICE",),
    "DEVICE_ADMIN": ("android.permission.BIND_DEVICE_ADMIN",),
    "NOTIFICATION_ACCESS": ("android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",),
}
API_RULES: dict[str, tuple[str, ...]] = {
    "SMS_INTERCEPTION": ("SmsManager",),
    "ACCESSIBILITY_ABUSE": ("AccessibilityService", "AccessibilityNodeInfo.performAction"),
    "DYNAMIC_CODE_LOADING": ("DexClassLoader", "InMemoryDexClassLoader", "PathClassLoader"),
    "DEVICE_ADMIN": ("DevicePolicyManager",),
    "OVERLAY": ("WindowManager.addView",),
    "PACKAGE_INSTALL": ("PackageInstaller",),
    "AUDIO_OR_CAMERA": ("MediaRecorder", "Camera"),
    "LOCATION": ("LocationManager",),
}
AD_SDK_PREFIXES = (
    "com.google.android.gms.ads",
    "com.facebook.ads",
    "com.applovin",
    "com.unity3d.ads",
    "com.ironsource",
    "com.mopub",
    "com.startapp",
    "com.vungle",
    "com.inmobi",
    "com.chartboost",
    "com.adcolony",
    "com.bytedance.sdk.openadsdk",
    "com.mbridge",
    "com.my.target",
    "com.yandex.mobile.ads",
    "com.appodeal",
)
DISPLAY = {
    "SMS_INTERCEPTION": "SMS interception",
    "OVERLAY": "overlay",
    "ACCESSIBILITY_ABUSE": "accessibility abuse",
    "DYNAMIC_CODE_LOADING": "dynamic code loading",
    "DROPPER": "dropper",
    "DEVICE_ADMIN": "device admin",
    "NOTIFICATION_ACCESS": "notification access",
    "CONTACTS_ACCESS": "contacts access",
    "LOCATION": "location",
    "AUDIO_OR_CAMERA": "audio/camera",
    "PACKAGE_INSTALL": "package install",
    "PERSISTENCE": "persistence",
    "ADWARE_SDK": "ad SDK",
}
ORDER = list(DISPLAY)


def capabilities(diff: dict[str, Any], *, other_version: int | None = None) -> dict[str, Any]:
    """The capability summary of a diff. ``other_version`` is the reference's versionCode when the reference is
    another version (CROSS_VERSION_DIFF): the line then says that ordinary release changes are included, instead of
    calling every difference an injection (D-068)."""
    found: dict[str, list[str]] = {}

    def hit(cap: str, why: str) -> None:
        found.setdefault(cap, []).append(why)

    perms = set(diff["manifest"]["permissions"]["added"])
    for cap, names in PERMISSION_RULES.items():
        for n in names:
            if n in perms:
                hit(cap, f"permission {n}")
    for comp in diff["manifest"]["components_added"]:
        for cap, actions in COMPONENT_ACTIONS.items():
            for a in actions:
                if a in comp.get("actions", []):
                    hit(cap, f"{comp['type']} {comp['name']} handles {a}")
        for cap, cperms in COMPONENT_PERMISSIONS.items():
            if comp.get("permission") in cperms:
                hit(cap, f"{comp['type']} {comp['name']} guarded by {comp['permission']}")
    risky = diff["code"]["risky_api_deltas"]
    for cap, apis in API_RULES.items():
        for api in apis:
            if api in risky:
                hit(cap, f"new references to {api}")
    for f in diff["files"]["embedded_payloads"]:
        hit("DROPPER", f"embedded {f.get('type')} {f['name']}")
    for p in diff["code"]["packages_added"]:
        if p.startswith(AD_SDK_PREFIXES):
            hit("ADWARE_SDK", f"package {p}")
    ind = diff["code"]["new_indicators"]
    endpoints = sorted(set(ind.get("urls", [])) | set(ind.get("domains", [])) | set(ind.get("ips", [])))
    caps = [c for c in ORDER if c in found]
    parts = [DISPLAY[c] for c in caps]
    if endpoints:
        plural = "s" if len(endpoints) != 1 else ""
        parts.append(f"{len(endpoints)} new network endpoint{plural}")
    head = (
        "Injected: "
        if other_version is None
        else f"Changed against version code {other_version}, another version (release changes included): "
    )
    line = head + (" · ".join(parts) if parts else "nothing detected by the capability table")
    extra = [f"NEW_NETWORK_ENDPOINTS({len(endpoints)})"] if endpoints else []
    return {
        "capabilities": caps + extra,
        "evidence": {c: sorted(set(v)) for c, v in found.items()},
        "endpoints": endpoints[:200],
        "line": line,
    }


def for_overlap(line: str, overlap_label: str | None) -> str:
    """The capability line for a diff whose files share little code (IMPOSTOR overlap): what the sample has and the
    reference lacks is its own code, not an injection (D-063, D-068)."""
    if overlap_label == "IMPOSTOR":
        return line.replace("Injected: ", "Only in the sample (different code base, not an injection): ", 1)
    return line
