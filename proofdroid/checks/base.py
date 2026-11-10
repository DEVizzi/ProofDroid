"""Base classes shared by all verification checks."""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from ..adb import Adb
from ..evidence import EvidenceCollector
from ..models import CheckResult, Finding

# Substrings that mean Android refused an external caller.
DENIAL_MARKERS = ("SecurityException", "Permission Denial", "not exported", "requires permission")


@dataclass
class CheckContext:
    adb: Adb
    evidence: EvidenceCollector
    package: str
    settle_seconds: float = 2.0
    root: bool = False  # adbd runs as root (needed to read the app sandbox).
    session_logcat: str = ""  # logcat captured right after the app launched.
    frida_path: str | None = None
    content_uris: list = field(default_factory=list)  # content:// literals found in the APK.
    sleep: Callable[[float], None] = field(default=time.sleep)


@dataclass
class Capture:
    evidence: list[str]
    logcat: str


class Check(ABC):
    """One small, self-contained verification. Subclasses set `id`, `name`, `categories`."""

    id: str = ""
    name: str = ""
    categories: frozenset = frozenset()
    order: int = 50  # Lower runs first; secrets/frida checks run late.

    def applies(self, finding: Finding) -> bool:
        return finding.category in self.categories and bool(finding.component)

    @abstractmethod
    def run(self, finding: Finding, ctx: CheckContext) -> CheckResult:
        ...

    # -- helpers -------------------------------------------------------------

    @staticmethod
    def capture(ctx: CheckContext, subdir: Path, command: list[str], output: str,
                extra: dict[str, str] | None = None) -> Capture:
        """Save the command transcript, a screenshot and a logcat snapshot."""
        evidence = [ctx.evidence.write_text(
            subdir, "command.txt", f"$ adb shell {' '.join(command)}\n\n{output}"
        )]
        for name, content in (extra or {}).items():
            evidence.append(ctx.evidence.write_text(subdir, name, content))
        shot = ctx.evidence.screenshot(subdir)
        if shot:
            evidence.append(shot)
        log_path, log_text = ctx.evidence.logcat_snapshot(subdir)
        if log_path:
            evidence.append(log_path)
        return Capture(evidence, log_text)

    @staticmethod
    def denied(text: str) -> bool:
        return any(marker in text for marker in DENIAL_MARKERS)

    @staticmethod
    def names_match(text: str, package: str, cls: str) -> bool:
        """True if `text` mentions the component as pkg/cls or the short pkg/.Cls form."""
        if f"{package}/{cls}" in text:
            return True
        prefix = package + "."
        return cls.startswith(prefix) and f"{package}/.{cls[len(prefix):]}" in text
