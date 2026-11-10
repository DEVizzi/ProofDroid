"""Built-in static analysis fallback (no MobSF needed).

Parses AndroidManifest.xml with the Android SDK's `aapt2 dump xmltree` and returns a
MobSF-shaped dict, so the rest of the pipeline is unchanged. Manifest issues only;
use MobSF for full code analysis whenever it is available.
"""

from __future__ import annotations

import re
import subprocess
import zipfile
from pathlib import Path

from .adb import find_sdk_root

TYPES = {"activity": "Activity", "activity-alias": "Activity-Alias", "service": "Service",
         "receiver": "Broadcast Receiver", "provider": "Content Provider"}


class StaticScanError(RuntimeError):
    pass


def find_aapt2() -> str | None:
    sdk = find_sdk_root()
    found = sorted((sdk / "build-tools").glob("*/aapt2")) if sdk else []
    return str(found[-1]) if found else None


class _Node:
    def __init__(self, tag: str):
        self.tag, self.attrs, self.children = tag, {}, []


def _value(raw: str) -> str:
    raw = raw.strip()
    return raw[1:].split('"', 1)[0] if raw.startswith('"') else raw.split(" ", 1)[0]


def parse_xmltree(text: str) -> _Node:
    root = _Node("#root")
    stack: list[tuple[int, _Node]] = [(-1, root)]
    for line in text.splitlines():
        indent, body = len(line) - len(line.lstrip()), line.strip()
        if body.startswith("E: "):
            while stack[-1][0] >= indent:
                stack.pop()
            node = _Node(body[3:].split(" ", 1)[0])
            stack[-1][1].children.append(node)
            stack.append((indent, node))
        elif body.startswith("A: ") and "=" in body:
            key, raw = body[3:].split("=", 1)
            stack[-1][1].attrs[re.sub(r"\(0x[0-9a-fA-F]+\)$", "", key).rsplit(":", 1)[-1]] = _value(raw)
    return root


def _find(node: _Node, tag: str):
    for c in node.children:
        if c.tag == tag:
            yield c
        yield from _find(c, tag)


def _true(v: str | None) -> bool:
    return (v or "").lower() in ("true", "0xffffffff", "-1")


def _int(v: str | None, default: int) -> int:
    try:
        return int(v, 0) if v else default
    except ValueError:
        return default


def analyze_manifest(text: str) -> dict:
    root = parse_xmltree(text)
    manifest, app = next(_find(root, "manifest"), None), next(_find(root, "application"), None)
    if manifest is None or app is None:
        raise StaticScanError("Could not parse AndroidManifest.xml")
    sdk = next(_find(manifest, "uses-sdk"), _Node("uses-sdk"))
    min_sdk, target = _int(sdk.attrs.get("minSdkVersion"), 1), _int(sdk.attrs.get("targetSdkVersion"), 1)
    out: list[dict] = []

    def add(rule, title, severity, desc):
        out.append({"rule": rule, "title": title, "severity": severity, "description": desc})

    if _true(app.attrs.get("debuggable")):
        add("app_is_debuggable", "Debug Enabled For App [android:debuggable=true]", "high",
            "Anyone with adb access can attach a debugger and read private app data via run-as.")
    if app.attrs.get("allowBackup") is None or _true(app.attrs.get("allowBackup")):
        add("app_allowbackup", "Application Data can be Backed up [android:allowBackup=true]", "warning",
            "App data can be extracted with adb backup by anyone with USB access.")
    if _true(app.attrs.get("usesCleartextTraffic")) or (
            target < 28 and "usesCleartextTraffic" not in app.attrs and "networkSecurityConfig" not in app.attrs):
        add("clear_text_traffic", "Clear text traffic is Enabled For App [android:usesCleartextTraffic=true]",
            "high", f"Plain HTTP is allowed (targetSdk {target}, no network security config).")
    if min_sdk < 24:
        add("vulnerable_os_version", f"App can be installed on a vulnerable Android version (minSdk {min_sdk})",
            "warning", "Old Android versions no longer receive security patches.")

    for tag, label in TYPES.items():
        for comp in _find(app, tag):
            name = comp.attrs.get("name", "")
            filters = list(_find(comp, "intent-filter"))
            if any(c.attrs.get("name") == "android.intent.category.LAUNCHER" for f in filters
                   for c in _find(f, "category")):
                continue  # The launcher activity is meant to be public.
            exp = comp.attrs.get("exported")
            exported = _true(exp) if exp is not None else (
                bool(filters) or (tag == "provider" and target < 17))
            if not exported or not name:
                continue
            perm = comp.attrs.get("permission") or comp.attrs.get("readPermission")
            if perm:
                add("exported_protected_permission", f"<strong>{label}</strong> ({name}) is Protected by a "
                    f"permission, but the protection level of the permission should be checked.", "info",
                    f"Exported but guarded by {perm}.")
            else:
                add("explicitly_exported", f"<strong>{label}</strong> ({name}) is not Protected.<br>"
                    "[android:exported=true]", "warning",
                    f"This {label.lower()} can be reached by any other app on the device.")

    return {
        "app_name": manifest.attrs.get("package", ""), "package_name": manifest.attrs.get("package", ""),
        "version_name": manifest.attrs.get("versionName", ""), "static_engine": "ProofDroid built-in (aapt2)",
        "manifest_analysis": {"manifest_findings": out},
    }


def find_content_uris(apk: Path, limit: int = 50) -> list[str]:
    """Collect content:// URI literals from the APK's DEX files (used to query providers)."""
    uris: set[str] = set()
    with zipfile.ZipFile(apk) as zf:
        for name in zf.namelist():
            if re.fullmatch(r"classes\d*\.dex", name):
                for m in re.finditer(rb"content://[A-Za-z0-9._-]+(?:/[A-Za-z0-9._/-]*)?", zf.read(name)):
                    uris.add(m.group().decode())
    return sorted(uris)[:limit]


def scan(apk: Path) -> dict:
    aapt2 = find_aapt2()
    if not aapt2:
        raise StaticScanError("aapt2 not found (install Android SDK build-tools).")
    proc = subprocess.run([aapt2, "dump", "xmltree", "--file", "AndroidManifest.xml", str(apk)],  # noqa: S603
                          capture_output=True, text=True, timeout=120, check=False)
    if proc.returncode != 0:
        raise StaticScanError(f"aapt2 failed: {(proc.stderr or '').strip()[:200]}")
    report = analyze_manifest(proc.stdout)
    report["content_uris"] = find_content_uris(apk)
    return report
