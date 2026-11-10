"""Shared test helpers: a scripted fake adb so tests never touch a real device."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Callable

from proofdroid.adb import Adb

FIXTURES = Path(__file__).parent / "fixtures"
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 16


class FakeAdb(Adb):
    """Responds to adb commands via a user-supplied function: joined_args -> stdout."""

    def __init__(self, responder: Callable[[str], str | bytes]):
        super().__init__("adb", "emulator-5554")
        self.responder = responder
        self.calls: list[list[str]] = []

    def run(self, args, timeout=60, binary=False):
        self.calls.append(list(args))
        out = self.responder(" ".join(args))
        if binary and isinstance(out, str):
            out = out.encode()
        if not binary and isinstance(out, bytes):
            out = out.decode("utf-8", "replace")
        return subprocess.CompletedProcess(args, 0, stdout=out, stderr="" if not binary else b"")
