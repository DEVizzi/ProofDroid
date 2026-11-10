"""Boot, control and shut down a headless Android emulator."""

from __future__ import annotations

import logging
import os
import re
import subprocess
import time
from pathlib import Path
from typing import IO

from .adb import Adb, AdbError, find_adb, find_sdk_root, validate_package

log = logging.getLogger(__name__)

AVD_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}$")


class EmulatorError(RuntimeError):
    pass


def find_emulator(sdk_root: Path | None) -> str | None:
    if sdk_root:
        p = sdk_root / "emulator" / "emulator"
        if p.is_file() and os.access(p, os.X_OK):
            return str(p)
    return None


class EmulatorController:
    """Owns the emulator process (if we started it) and app lifecycle on the device."""

    def __init__(self, sdk_root: Path | None = None, adb_path: str | None = None):
        self.sdk_root = sdk_root or find_sdk_root()
        self.adb_path = adb_path or find_adb(self.sdk_root)
        self.emulator_path = find_emulator(self.sdk_root)
        self.process: subprocess.Popen | None = None
        self._log_file: IO | None = None

    # -- device acquisition -------------------------------------------------

    def _require_adb(self) -> str:
        if not self.adb_path:
            raise EmulatorError("adb not found. Install Android platform-tools or set ANDROID_SDK_ROOT.")
        return self.adb_path

    def list_avds(self) -> list[str]:
        if not self.emulator_path:
            return []
        out = subprocess.run(  # noqa: S603
            [self.emulator_path, "-list-avds"], capture_output=True, text=True, timeout=30, check=False
        ).stdout
        return [line.strip() for line in out.splitlines() if AVD_RE.fullmatch(line.strip())]

    def attach(self, serial: str) -> Adb:
        """Use an already running device/emulator instead of booting one."""
        adb = Adb(self._require_adb(), serial)
        if serial not in adb.devices():
            raise EmulatorError(f"Device {serial} is not connected (see `adb devices`).")
        return adb

    def boot(self, avd: str, port: int = 5554, log_path: Path | None = None) -> Adb:
        """Start the emulator headless and return an Adb bound to it (does not wait for boot)."""
        if not AVD_RE.fullmatch(avd or ""):
            raise EmulatorError(f"Invalid AVD name: {avd!r}")
        if not (5554 <= port <= 5682 and port % 2 == 0):
            raise EmulatorError("Emulator port must be an even number between 5554 and 5682.")
        if not self.emulator_path:
            raise EmulatorError("Android emulator binary not found. Install it with sdkmanager or set ANDROID_SDK_ROOT.")
        available = self.list_avds()
        if avd not in available:
            raise EmulatorError(f"AVD {avd!r} not found. Available: {', '.join(available) or 'none'}")

        serial = f"emulator-{port}"
        adb = Adb(self._require_adb(), serial)
        if serial in adb.devices():
            raise EmulatorError(f"{serial} is already running. Use --serial {serial} or another --port.")

        cmd = [
            self.emulator_path, "-avd", avd, "-port", str(port),
            "-no-window", "-no-audio", "-no-boot-anim", "-no-snapshot-save",
        ]
        log.info("Booting emulator %s headless on port %d", avd, port)
        self._log_file = open(log_path, "w", encoding="utf-8") if log_path else None  # noqa: SIM115
        self.process = subprocess.Popen(  # noqa: S603 - validated args, no shell
            cmd,
            stdout=self._log_file or subprocess.DEVNULL,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
        )
        return adb

    def wait_for_boot(self, adb: Adb, timeout: float = 300, poll: float = 3) -> None:
        """Block until Android reports boot completed and the package manager answers."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.process is not None and self.process.poll() is not None:
                raise EmulatorError(f"Emulator exited early (code {self.process.returncode}); see emulator.log.")
            try:
                if adb.getprop("sys.boot_completed") == "1":
                    pm = adb.shell(["pm", "path", "android"], timeout=15).stdout or ""
                    if "package:" in pm:
                        log.info("Device %s booted", adb.serial)
                        return
            except AdbError:
                pass  # Device not up yet.
            time.sleep(poll)
        raise EmulatorError(f"Device did not finish booting within {timeout:.0f}s.")

    def try_root(self, adb: Adb) -> bool:
        """Restart adbd as root (works on google_apis images, not Play Store ones)."""
        try:
            adb.run(["root"], timeout=30)
            adb.run(["wait-for-device"], timeout=60)
            return (adb.shell(["id", "-u"], timeout=15).stdout or "").strip() == "0"
        except AdbError:
            return False

    # -- app lifecycle --------------------------------------------------------

    def install(self, adb: Adb, apk_path: Path, timeout: float = 300) -> None:
        log.info("Installing %s", apk_path.name)
        result = adb.run(["install", "-r", "-g", str(apk_path)], timeout=timeout)
        output = (result.stdout or "") + (result.stderr or "")
        if "INSTALL_FAILED_DEPRECATED_SDK_VERSION" in output:
            # Android 14+ blocks old-targetSdk apps (common for practice targets like DIVA).
            log.info("Old targetSdk blocked; retrying with --bypass-low-target-sdk-block")
            result = adb.run(["install", "-r", "-g", "--bypass-low-target-sdk-block", str(apk_path)],
                             timeout=timeout)
            output = (result.stdout or "") + (result.stderr or "")
        if "Success" not in output:
            last = output.strip().splitlines()[-1] if output.strip() else "no output"
            raise EmulatorError(f"APK install failed: {last[:300]}")

    def launch(self, adb: Adb, package: str) -> None:
        """Launch the app's launcher activity via monkey (works without knowing the activity name)."""
        validate_package(package)
        adb.shell(["monkey", "-p", package, "-c", "android.intent.category.LAUNCHER", "1"], timeout=30)

    def uninstall(self, adb: Adb, package: str) -> None:
        adb.run(["uninstall", validate_package(package)], timeout=60)

    def device_info(self, adb: Adb) -> dict[str, str]:
        return {
            "serial": adb.serial or "",
            "model": adb.getprop("ro.product.model"),
            "android": adb.getprop("ro.build.version.release"),
            "sdk": adb.getprop("ro.build.version.sdk"),
        }

    def shutdown(self, adb: Adb | None) -> None:
        """Stop the emulator if (and only if) we started it."""
        if self.process is None:
            return
        log.info("Shutting down emulator")
        if adb is not None:
            try:
                adb.run(["emu", "kill"], timeout=30)
            except AdbError:
                pass
        try:
            self.process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
        self.process = None
        if self._log_file:
            self._log_file.close()
            self._log_file = None
