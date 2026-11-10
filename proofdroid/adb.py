"""Thin, safe wrapper around the `adb` binary.

Security note: `adb shell a b c` joins its arguments into ONE command line that
the device's shell re-parses. Package and component names come from the APK
under test (untrusted input), so we (1) validate them against strict allow-list
regexes and (2) shell-quote every remote argument. We never use shell=True
locally.
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
from pathlib import Path

SERIAL_RE = re.compile(r"^[A-Za-z0-9._:-]{1,64}$")
PACKAGE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$")
CLASS_RE = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*(\.[A-Za-z_$][A-Za-z0-9_$]*)*$")
MAX_NAME_LEN = 255


class AdbError(RuntimeError):
    """Raised when adb is missing, times out, or fails in an unrecoverable way."""


def validate_package(name: str) -> str:
    if not isinstance(name, str) or len(name) > MAX_NAME_LEN or not PACKAGE_RE.fullmatch(name):
        raise ValueError(f"Invalid Android package name: {name!r}")
    return name


def resolve_component(package: str, name: str) -> str:
    """Return the fully qualified class name for a manifest component name.

    Manifest names may be relative (".MainActivity" or "MainActivity").
    """
    validate_package(package)
    name = (name or "").strip()
    if name.startswith("."):
        name = package + name
    elif "." not in name:
        name = f"{package}.{name}"
    if len(name) > MAX_NAME_LEN or not CLASS_RE.fullmatch(name):
        raise ValueError(f"Invalid component class name: {name!r}")
    return name


def component_spec(package: str, cls: str) -> str:
    """Build the `package/class` string used by `am`."""
    return f"{validate_package(package)}/{resolve_component(package, cls)}"


def find_sdk_root() -> Path | None:
    """Locate the Android SDK via env vars or common default locations."""
    candidates = [os.environ.get("ANDROID_SDK_ROOT"), os.environ.get("ANDROID_HOME")]
    home = Path.home()
    candidates += [str(home / "Library/Android/sdk"), str(home / "Android/Sdk")]
    for c in candidates:
        if c and Path(c).is_dir():
            return Path(c)
    return None


def find_adb(sdk_root: Path | None = None) -> str | None:
    sdk_root = sdk_root or find_sdk_root()
    if sdk_root:
        p = sdk_root / "platform-tools" / "adb"
        if p.is_file() and os.access(p, os.X_OK):
            return str(p)
    return shutil.which("adb")


class Adb:
    """Runs adb commands against one device (optionally pinned by serial)."""

    def __init__(self, adb_path: str, serial: str | None = None):
        if serial is not None and not SERIAL_RE.fullmatch(serial):
            raise ValueError(f"Invalid device serial: {serial!r}")
        self.adb_path = adb_path
        self.serial = serial

    def _base(self) -> list[str]:
        cmd = [self.adb_path]
        if self.serial:
            cmd += ["-s", self.serial]
        return cmd

    def run(self, args: list[str], timeout: float = 60, binary: bool = False) -> subprocess.CompletedProcess:
        """Run `adb <args>` and return the completed process (never raises on non-zero exit)."""
        kwargs: dict = {"capture_output": True, "timeout": timeout, "check": False}
        if not binary:
            kwargs.update(text=True, encoding="utf-8", errors="replace")
        try:
            return subprocess.run(self._base() + list(args), **kwargs)  # noqa: S603 - fixed binary, list args
        except FileNotFoundError as exc:
            raise AdbError(f"adb not found at {self.adb_path}") from exc
        except subprocess.TimeoutExpired as exc:
            raise AdbError(f"adb command timed out after {timeout}s: {' '.join(args[:3])}") from exc

    @staticmethod
    def _remote(args: list[str]) -> str:
        return " ".join(shlex.quote(str(a)) for a in args)

    def shell(self, args: list[str], timeout: float = 60) -> subprocess.CompletedProcess:
        """Run a command in the device shell with every argument quoted."""
        return self.run(["shell", self._remote(args)], timeout=timeout)

    def exec_out(self, args: list[str], timeout: float = 60) -> bytes:
        """Run a device command and return raw stdout bytes (e.g. screencap PNG)."""
        return self.run(["exec-out", self._remote(args)], timeout=timeout, binary=True).stdout or b""

    def popen_shell(self, args: list[str]) -> subprocess.Popen:
        """Start a long-running device command (e.g. screenrecord) in the background."""
        return subprocess.Popen(  # noqa: S603 - fixed binary, list args
            self._base() + ["shell", self._remote(args)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
        )

    def getprop(self, name: str) -> str:
        return (self.shell(["getprop", name], timeout=15).stdout or "").strip()

    def devices(self) -> list[str]:
        """Return serials of devices in the `device` state."""
        out = self.run(["devices"], timeout=15).stdout or ""
        serials = []
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 2 and parts[1] == "device":
                serials.append(parts[0])
        return serials
