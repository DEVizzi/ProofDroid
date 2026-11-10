"""Evidence capture via ADB: screenshots, logcat snapshots, screen recordings, notes.

All files are written inside `<run_dir>/evidence/<subdir>/` and every returned
path is relative to the run folder so the report links keep working when the
folder is zipped and sent to a client.
"""

from __future__ import annotations

import logging
import re
import subprocess
import time
from pathlib import Path

from .adb import Adb, AdbError

log = logging.getLogger(__name__)

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
REMOTE_RECORDING = "/sdcard/proofdroid_record.mp4"


def safe_name(value: str, default: str = "item") -> str:
    """Turn arbitrary text into a safe single path component."""
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value)).strip("._")[:80]
    return name or default


class EvidenceCollector:
    def __init__(self, adb: Adb, run_dir: Path):
        self.adb = adb
        self.run_dir = run_dir.resolve()
        self.root = self.run_dir / "evidence"

    def subdir(self, name: str) -> Path:
        path = (self.root / safe_name(name)).resolve()
        # Defence in depth: never write outside the evidence folder.
        if not path.is_relative_to(self.root.resolve()):
            raise ValueError(f"Refusing to write evidence outside {self.root}")
        path.mkdir(parents=True, exist_ok=True)
        return path

    def rel(self, path: Path) -> str:
        return path.resolve().relative_to(self.run_dir).as_posix()

    def write_text(self, subdir: Path, filename: str, content: str) -> str:
        path = subdir / safe_name(filename)
        path.write_text(content, encoding="utf-8")
        return self.rel(path)

    def screenshot(self, subdir: Path, filename: str = "screenshot.png") -> str | None:
        """Capture the screen with `adb exec-out screencap -p`. Returns None on failure."""
        try:
            data = self.adb.exec_out(["screencap", "-p"], timeout=30)
        except AdbError as exc:
            log.warning("Screenshot failed: %s", exc)
            return None
        if not data.startswith(PNG_MAGIC):
            log.warning("Screenshot did not return PNG data")
            return None
        path = subdir / safe_name(filename)
        path.write_bytes(data)
        return self.rel(path)

    def clear_logcat(self) -> None:
        try:
            self.adb.run(["logcat", "-c"], timeout=15)
        except AdbError as exc:
            log.warning("Could not clear logcat: %s", exc)

    def logcat_snapshot(self, subdir: Path, filename: str = "logcat.txt",
                        max_lines: int = 5000) -> tuple[str | None, str]:
        """Dump the current logcat buffer. Returns (relative path or None, text)."""
        try:
            result = self.adb.run(["logcat", "-d", "-v", "threadtime", "-t", str(max_lines)], timeout=30)
        except AdbError as exc:
            log.warning("logcat capture failed: %s", exc)
            return None, ""
        text = result.stdout or ""
        return self.write_text(subdir, filename, text), text

    # -- screen recording ---------------------------------------------------

    def start_recording(self, time_limit: int = 180) -> subprocess.Popen:
        """Start `screenrecord` on the device (Android caps it at 180 seconds)."""
        time_limit = max(1, min(int(time_limit), 180))
        return self.adb.popen_shell(["screenrecord", "--time-limit", str(time_limit), REMOTE_RECORDING])

    def stop_recording(self, proc: subprocess.Popen, subdir: Path,
                       filename: str = "screenrecord.mp4") -> str | None:
        try:
            self.adb.shell(["pkill", "-INT", "screenrecord"], timeout=15)
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                proc.terminate()
            time.sleep(1)  # Let the device finish writing the MP4 trailer.
            path = subdir / safe_name(filename)
            self.adb.run(["pull", REMOTE_RECORDING, str(path)], timeout=120)
            self.adb.shell(["rm", "-f", REMOTE_RECORDING], timeout=15)
        except AdbError as exc:
            log.warning("Screen recording failed: %s", exc)
            return None
        if not path.is_file() or path.stat().st_size == 0:
            return None
        return self.rel(path)
