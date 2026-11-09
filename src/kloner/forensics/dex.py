"""DEX parsing for forensics (§10.9): class names, method-code digests, strings, API references.

Only what is needed is parsed: never androguard's full analysis graph. Class digests hash the
disassembled instructions with resolved operands, so they do not change when unrelated classes
shift the DEX index tables.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

URL_RE = re.compile(r"\b(?:https?|wss?|ftp)://[^\s\"'<>]{3,200}", re.I)
DOMAIN_RE = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,24})$", re.I)
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}\b")
PHONE_RE = re.compile(r"^\+\d{7,15}$")
WALLET_RE = re.compile(
    r"^(?:bc1[ac-hj-np-z02-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|0x[a-fA-F0-9]{40}|T[1-9A-HJ-NP-Za-km-z]{33})$"
)
COMMON_TLD_NOISE = {"java.lang", "android.app"}

HIGH_RISK_APIS: dict[str, tuple[str, str | None]] = {
    "DexClassLoader": ("Ldalvik/system/DexClassLoader;", None),
    "InMemoryDexClassLoader": ("Ldalvik/system/InMemoryDexClassLoader;", None),
    "PathClassLoader": ("Ldalvik/system/PathClassLoader;", None),
    "Runtime.exec": ("Ljava/lang/Runtime;", "exec"),
    "ProcessBuilder": ("Ljava/lang/ProcessBuilder;", None),
    "SmsManager": ("Landroid/telephony/SmsManager;", None),
    "AccessibilityService": ("Landroid/accessibilityservice/AccessibilityService;", None),
    "AccessibilityNodeInfo.performAction": ("Landroid/view/accessibility/AccessibilityNodeInfo;", "performAction"),
    "getInstalledPackages": ("Landroid/content/pm/PackageManager;", "getInstalledPackages"),
    "getInstalledApplications": ("Landroid/content/pm/PackageManager;", "getInstalledApplications"),
    "addJavascriptInterface": ("Landroid/webkit/WebView;", "addJavascriptInterface"),
    "Cipher": ("Ljavax/crypto/Cipher;", None),
    "DevicePolicyManager": ("Landroid/app/admin/DevicePolicyManager;", None),
    "PackageInstaller": ("Landroid/content/pm/PackageInstaller;", None),
    "TelephonyManager.getDeviceId": ("Landroid/telephony/TelephonyManager;", "getDeviceId"),
    "WindowManager.addView": ("Landroid/view/WindowManager;", "addView"),
    "MediaRecorder": ("Landroid/media/MediaRecorder;", None),
    "Camera": ("Landroid/hardware/Camera;", None),
    "LocationManager": ("Landroid/location/LocationManager;", None),
}


def method_digest(method: Any) -> str:
    code = method.get_code()
    h = hashlib.sha256()
    h.update(f"{method.get_name()}{method.get_descriptor()}".encode())
    if code is not None:
        for ins in code.get_bc().get_instructions():
            h.update(ins.get_name().encode())
            h.update(b" ")
            h.update(ins.get_output().encode("utf-8", "replace"))
            h.update(b"\n")
    return h.hexdigest()


def parse_dex(datas: list[bytes]) -> dict[str, Any]:
    from androguard.core.dex import DEX

    classes: dict[str, str] = {}
    strings: set[str] = set()
    refs: set[str] = set()
    for data in datas:
        d = DEX(data)
        for cls in d.get_classes():
            name = cls.get_name()
            h = hashlib.sha256()
            h.update((cls.get_superclassname() or "").encode())
            for m in sorted(cls.get_methods(), key=lambda m: (m.get_name(), m.get_descriptor())):
                h.update(method_digest(m).encode())
            classes[name] = h.hexdigest()
        for s in d.get_strings():
            if isinstance(s, str) and not s.startswith(("~~D8", "~~R8", "~~L8")):
                strings.add(s[:300])
        for mid in d.get_methods_id_item().gets():
            refs.add(f"{mid.get_class_name()}->{mid.get_name()}")
    risky: dict[str, int] = {}
    for label, (klass, method) in HIGH_RISK_APIS.items():
        n = sum(1 for r in refs if r.startswith(klass + "->") and (method is None or r.endswith("->" + method)))
        if n:
            risky[label] = n
    return {"classes": classes, "strings": sorted(strings), "risky_apis": risky}


def indicators(strings: list[str]) -> dict[str, list[str]]:
    urls: set[str] = set()
    domains: set[str] = set()
    ips: set[str] = set()
    emails: set[str] = set()
    phones: set[str] = set()
    wallets: set[str] = set()
    for s in strings:
        for u in URL_RE.findall(s):
            urls.add(u.rstrip(".,;)"))
        for ip in IPV4_RE.findall(s):
            if not ip.startswith(("0.", "127.", "255.")):
                ips.add(ip)
        for e in EMAIL_RE.findall(s):
            emails.add(e)
        st = s.strip()
        if (
            DOMAIN_RE.match(st)
            and st.lower() not in COMMON_TLD_NOISE
            and not st.endswith((".java", ".kt", ".xml", ".png", ".so", ".dex"))
        ):
            domains.add(st.lower())
        if PHONE_RE.match(st):
            phones.add(st)
        if WALLET_RE.match(st):
            wallets.add(st)
    return {
        "urls": sorted(urls)[:2000],
        "domains": sorted(domains)[:2000],
        "ips": sorted(ips)[:2000],
        "emails": sorted(emails)[:500],
        "phones": sorted(phones)[:500],
        "wallets": sorted(wallets)[:500],
    }
