#!/usr/bin/env python3
"""Build KLONER's own trivial fixture apps, reproducibly.

The fixtures are unsigned APKs committed to ``src/kloner/selftest/fixtures/``.
``kloner selftest`` signs them with freshly generated synthetic-vendor keys to
build the corpus. Nothing here touches a real vendor's code or keys.

Toolchain (pinned, see docs/DECISIONS.md):
  * build-tools 36.0.0: aapt2 (link), lib/d8.jar (dex)
  * platforms/android-36/android.jar (link target)
  * a JDK 17+ (javac, java)

Usage:
  python scripts/build_fixture_apks.py [--build-tools DIR] [--platform-jar FILE] [--out DIR]
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile
import zlib
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT = ROOT / "src" / "kloner" / "selftest" / "fixtures"
PINNED_BUILD_TOOLS = "36.0.0"
PINNED_PLATFORM = "android-36"
FIXED_ZIP_TIME = (2008, 1, 1, 0, 0, 0)

MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="{package}"{split_attr}
    android:versionCode="{version_code}"
    android:versionName="{version_name}">
    <uses-sdk android:minSdkVersion="{min_sdk}" android:targetSdkVersion="{target_sdk}" />
{permissions}    <application{app_attrs}>
{activity}    </application>
</manifest>
"""

ACTIVITY = """        <activity android:name="{activity}" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
"""

JAVA_ACTIVITY = """package {java_package};

public class MainActivity extends android.app.Activity {{
    @Override
    protected void onCreate(android.os.Bundle state) {{
        super.onCreate(state);
        setTitle("{title}");
    }}
}}
"""

JAVA_SETTINGS = """package {java_package};

public final class Settings {{
    public static final String HOME_PAGE = "https://example.org/kloner-fixture";

    private Settings() {{}}

    public static String homePage() {{
        return HOME_PAGE;
    }}
}}
"""


@dataclass(frozen=True)
class Fixture:
    name: str
    package: str
    version_code: int
    version_name: str
    min_sdk: int
    target_sdk: int
    label: str | None = None
    icon: str | None = None  # "brand" | "other"
    java_package: str | None = None
    split: str | None = None
    permissions: tuple[str, ...] = ()
    extra_settings_class: bool = False
    extra_strings: dict[str, str] = field(default_factory=dict)


FIXTURES: tuple[Fixture, ...] = (
    Fixture("modern", "dev.kloner.fixture", 1, "1.0", 24, 35, "Kloner Fixture", "brand", "dev.kloner.fixture"),
    Fixture(
        "modern_v2",
        "dev.kloner.fixture",
        2,
        "2.0",
        24,
        35,
        "Kloner Fixture",
        "brand",
        "dev.kloner.fixture",
        permissions=("android.permission.INTERNET",),
        extra_settings_class=True,
    ),
    Fixture("legacy", "dev.kloner.fixture", 1, "1.0-legacy", 21, 29, "Kloner Fixture", "brand", "dev.kloner.fixture"),
    Fixture("split_xxhdpi", "dev.kloner.fixture", 1, "1.0", 24, 35, split="config.xxhdpi"),
    Fixture("split_en", "dev.kloner.fixture", 1, "1.0", 24, 35, split="config.en"),
    Fixture("sibling", "dev.kloner.sibling", 1, "1.0", 24, 35, "Kloner Sibling", "other", "dev.kloner.sibling"),
    Fixture("lite", "dev.kloner.fixture.lite", 1, "1.0", 24, 35, "Kloner Fixture", "brand", "dev.kloner.fixture.lite"),
)


def png_bytes(width: int, height: int, pixel: callable) -> bytes:  # type: ignore[valid-type]
    """Encode an RGBA PNG deterministically (zlib level 0: stored blocks only)."""
    raw = bytearray()
    for y in range(height):
        raw.append(0)  # filter type: none
        for x in range(width):
            raw.extend(pixel(x, y))

    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(bytes(raw), 0)) + chunk(b"IEND", b"")
    )


def brand_icon() -> bytes:
    def px(x: int, y: int) -> bytes:
        cx, cy = x - 23.5, y - 23.5
        inside = cx * cx + cy * cy <= 22 * 22
        if not inside:
            return b"\x00\x00\x00\x00"
        if abs(cx) < 4 or abs(cy) < 4:
            return b"\xff\xff\xff\xff"
        return b"\x1a\x5f\xb4\xff"

    return png_bytes(48, 48, px)


def other_icon() -> bytes:
    def px(x: int, y: int) -> bytes:
        return b"\x2e\x7d\x32\xff" if (x // 8 + y // 8) % 2 == 0 else b"\xf9\xa8\x25\xff"

    return png_bytes(48, 48, px)


def find_sdk() -> Path | None:
    candidates = [os.environ.get("ANDROID_HOME"), os.environ.get("ANDROID_SDK_ROOT")]
    local = os.environ.get("LOCALAPPDATA")
    if local:
        candidates.append(str(Path(local) / "Android" / "Sdk"))
    candidates += [str(Path.home() / "Android" / "Sdk"), str(Path.home() / "Library" / "Android" / "sdk")]
    for c in candidates:
        if c and (Path(c) / "build-tools").is_dir():
            return Path(c)
    return None


def exe(path: Path) -> Path:
    if os.name == "nt" and path.with_suffix(".exe").exists():
        return path.with_suffix(".exe")
    return path


def run(cmd: list[str], cwd: Path | None = None) -> None:
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=False)  # noqa: S603
    if proc.returncode != 0:
        sys.stderr.write(proc.stdout + proc.stderr)
        raise SystemExit(f"command failed ({proc.returncode}): {' '.join(cmd)}")


def build_one(fx: Fixture, bt: Path, platform_jar: Path, out_dir: Path, tmp: Path) -> Path:
    work = tmp / fx.name
    res = work / "res"
    (res / "values").mkdir(parents=True)
    strings = {}
    if fx.label:
        strings["app_name"] = fx.label
    strings.update(fx.extra_strings)
    if strings:
        body = "".join(f'    <string name="{k}">{v}</string>\n' for k, v in sorted(strings.items()))
        (res / "values" / "strings.xml").write_text(
            f'<?xml version="1.0" encoding="utf-8"?>\n<resources>\n{body}</resources>\n', encoding="utf-8"
        )
    else:
        # A config split still needs a compiled resource table; keep a neutral integer.
        (res / "values" / "integers.xml").write_text(
            '<?xml version="1.0" encoding="utf-8"?>\n<resources>\n'
            f'    <integer name="kloner_{fx.name}">1</integer>\n</resources>\n',
            encoding="utf-8",
        )
    if fx.icon:
        (res / "mipmap-mdpi").mkdir(parents=True)
        (res / "mipmap-mdpi" / "ic_launcher.png").write_bytes(brand_icon() if fx.icon == "brand" else other_icon())

    app_attrs = ' android:allowBackup="false"'
    if fx.label:
        app_attrs += ' android:label="@string/app_name"'
    if fx.icon:
        app_attrs += ' android:icon="@mipmap/ic_launcher"'
    if not fx.java_package:
        app_attrs += ' android:hasCode="false"'
    perms = "".join(f'    <uses-permission android:name="{p}" />\n' for p in fx.permissions)
    manifest = MANIFEST.format(
        package=fx.package,
        split_attr=f'\n    split="{fx.split}"' if fx.split else "",
        version_code=fx.version_code,
        version_name=fx.version_name,
        min_sdk=fx.min_sdk,
        target_sdk=fx.target_sdk,
        permissions=perms,
        app_attrs=app_attrs,
        activity=ACTIVITY.format(activity=".MainActivity") if fx.java_package else "",
    )
    (work / "AndroidManifest.xml").write_text(manifest, encoding="utf-8")

    aapt2 = exe(bt / "aapt2")
    run([str(aapt2), "compile", "--no-crunch", "--dir", str(res), "-o", str(work / "res.zip")])
    linked = work / "linked.apk"
    run(
        [
            str(aapt2),
            "link",
            "-I",
            str(platform_jar),
            "--manifest",
            str(work / "AndroidManifest.xml"),
            "--no-auto-version",
            "-o",
            str(linked),
            str(work / "res.zip"),
        ]
    )

    dex: bytes | None = None
    if fx.java_package:
        src = work / "java" / Path(*fx.java_package.split("."))
        src.mkdir(parents=True)
        (src / "MainActivity.java").write_text(
            JAVA_ACTIVITY.format(java_package=fx.java_package, title=fx.label or fx.name), encoding="utf-8"
        )
        if fx.extra_settings_class:
            (src / "Settings.java").write_text(JAVA_SETTINGS.format(java_package=fx.java_package), encoding="utf-8")
        classes = work / "classes"
        classes.mkdir()
        sources = sorted(str(p) for p in (work / "java").rglob("*.java"))
        run(["javac", "--release", "11", "-nowarn", "-cp", str(platform_jar), "-d", str(classes), *sources])
        dexout = work / "dex"
        dexout.mkdir()
        class_files = sorted(str(p) for p in classes.rglob("*.class"))
        run(
            [
                "java",
                "-cp",
                str(bt / "lib" / "d8.jar"),
                "com.android.tools.r8.D8",
                "--release",
                "--min-api",
                str(fx.min_sdk),
                "--lib",
                str(platform_jar),
                "--output",
                str(dexout),
                *class_files,
            ]
        )
        dex = (dexout / "classes.dex").read_bytes()

    # Rewrite with fixed timestamps and a stable entry order:
    # AndroidManifest.xml (DEFLATED), classes.dex (DEFLATED), resources.arsc (STORED), then the rest.
    out = out_dir / f"{fx.name}.apk"
    with zipfile.ZipFile(linked) as zin:
        infos = {i.filename: i for i in zin.infolist()}
        names = sorted(infos)
        order = [n for n in ("AndroidManifest.xml",) if n in infos]
        rest = [n for n in names if n not in ("AndroidManifest.xml", "resources.arsc")]
        tmp_out = work / "final.apk"
        with zipfile.ZipFile(tmp_out, "w") as zout:
            for n in order:
                zout.writestr(zipfile.ZipInfo(n, FIXED_ZIP_TIME), zin.read(n), compress_type=zipfile.ZIP_DEFLATED)
            if dex is not None:
                zout.writestr(zipfile.ZipInfo("classes.dex", FIXED_ZIP_TIME), dex, compress_type=zipfile.ZIP_DEFLATED)
            if "resources.arsc" in infos:
                zout.writestr(
                    zipfile.ZipInfo("resources.arsc", FIXED_ZIP_TIME),
                    zin.read("resources.arsc"),
                    compress_type=zipfile.ZIP_STORED,
                )
            for n in rest:
                ctype = infos[n].compress_type
                zout.writestr(zipfile.ZipInfo(n, FIXED_ZIP_TIME), zin.read(n), compress_type=ctype)
    shutil.copyfile(tmp_out, out)
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--build-tools", type=Path, help=f"build-tools {PINNED_BUILD_TOOLS} directory")
    ap.add_argument("--platform-jar", type=Path, help=f"{PINNED_PLATFORM} android.jar")
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = ap.parse_args(argv)

    sdk = find_sdk()
    bt = args.build_tools or (sdk / "build-tools" / PINNED_BUILD_TOOLS if sdk else None)
    pj = args.platform_jar or (sdk / "platforms" / PINNED_PLATFORM / "android.jar" if sdk else None)
    if not bt or not bt.is_dir():
        raise SystemExit(f"build-tools {PINNED_BUILD_TOOLS} not found; pass --build-tools")
    if not pj or not pj.is_file():
        raise SystemExit(f"{PINNED_PLATFORM} android.jar not found; pass --platform-jar")

    args.out.mkdir(parents=True, exist_ok=True)
    manifest_lines = []
    with tempfile.TemporaryDirectory(prefix="kloner-fixtures-") as t:
        for fx in FIXTURES:
            path = build_one(fx, bt, pj, args.out, Path(t))
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            manifest_lines.append(f"{digest}  {path.name}")
            print(f"built {path.name}  sha256={digest}")
    (args.out / "SHA256SUMS").write_text("\n".join(manifest_lines) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
