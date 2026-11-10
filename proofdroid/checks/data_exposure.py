"""Runtime checks for data the app stores or sends insecurely.

- InsecureStorageCheck: sensitive keywords / world-readable files in the app sandbox
  (needs root) and on shared external storage (no root needed).
- CleartextTrafficCheck: live port-80 connections owned by the app's uid.
- LeakedSecretsCheck: hardcoded secrets from the APK showing up in logcat or storage.
"""

from __future__ import annotations

import re

from ..models import MANIFEST, NETWORK, SECRETS, STORAGE, CheckResult, Finding, Status
from .base import Check, CheckContext

SENSITIVE = r"password|passwd|token|secret|api[_-]?key|session|credit.?card|ssn"


def _stdout(ctx: CheckContext, args: list[str], timeout: float = 30) -> str:
    return (ctx.adb.shell(args, timeout=timeout).stdout or "").strip()


def _mask(value: str) -> str:
    return value[:4] + "…[masked]"


class InsecureStorageCheck(Check):
    id = "insecure-storage"
    name = "Look for sensitive data in app storage"
    categories = frozenset({STORAGE})
    order = 40

    def applies(self, finding: Finding) -> bool:
        return finding.category == STORAGE

    def run(self, finding: Finding, ctx: CheckContext) -> CheckResult:
        subdir = ctx.evidence.subdir(finding.id)
        base, ext = f"/data/data/{ctx.package}", f"/sdcard/Android/data/{ctx.package}"
        ev: list[str] = []
        problems: list[str] = []

        ext_hits = _stdout(ctx, ["grep", "-rIilE", SENSITIVE, ext])
        ev.append(ctx.evidence.write_text(subdir, "external_storage.txt",
                                          f"$ ls -lR {ext}\n{_stdout(ctx, ['ls', '-lR', ext])}\n\n"
                                          f"Files with sensitive keywords:\n{ext_hits or '(none)'}"))
        if ext_hits:
            problems.append(f"{len(ext_hits.splitlines())} file(s) on shared external storage contain sensitive keywords")

        if ctx.root:
            prefs = _stdout(ctx, ["grep", "-rinE", SENSITIVE, f"{base}/shared_prefs"])
            dbs = _stdout(ctx, ["grep", "-railE", SENSITIVE, f"{base}/databases", f"{base}/files"])
            world = _stdout(ctx, ["find", base, "-type", "f", "-perm", "-004"])
            ev.append(ctx.evidence.write_text(subdir, "sandbox.txt", "\n\n".join([
                f"$ ls -lR {base}\n{_stdout(ctx, ['ls', '-lR', base])}",
                f"shared_prefs matches:\n{prefs or '(none)'}",
                f"databases/files with sensitive keywords:\n{dbs or '(none)'}",
                f"world-readable files:\n{world or '(none)'}",
            ])))
            if prefs:
                problems.append(f"{len(prefs.splitlines())} sensitive line(s) in shared_prefs (plaintext)")
            if dbs:
                problems.append(f"{len(dbs.splitlines())} database/file(s) contain sensitive keywords")
            if world:
                problems.append(f"{len(world.splitlines())} world-readable file(s) in the sandbox")

        if problems:
            return CheckResult(Status.CONFIRMED, "; ".join(problems) + ". See sandbox.txt / external_storage.txt.", ev)
        if not ctx.root:
            return CheckResult(Status.NOT_TESTABLE, "Root is needed to read the app sandbox (use a google_apis "
                               "emulator image); external storage was clean.", ev)
        return CheckResult(Status.UNCONFIRMED, "No sensitive keywords or world-readable files found after launch. "
                           "Data written after login is not covered yet.", ev)


class CleartextTrafficCheck(Check):
    id = "cleartext-traffic"
    name = "Observe plain-HTTP connections from the app"
    categories = frozenset({NETWORK, MANIFEST})
    order = 30
    polls = 8

    def applies(self, finding: Finding) -> bool:
        t = finding.title.lower()
        return finding.category in self.categories and ("clear text" in t or "cleartext" in t)

    def run(self, finding: Finding, ctx: CheckContext) -> CheckResult:
        subdir = ctx.evidence.subdir(finding.id)
        m = re.search(rf"package:{re.escape(ctx.package)} uid:(\d+)",
                      _stdout(ctx, ["pm", "list", "packages", "-U", ctx.package]))
        if not m:
            return CheckResult(Status.NOT_TESTABLE, "Could not determine the app's uid.")
        uid = m.group(1)

        ctx.adb.shell(["am", "force-stop", ctx.package], timeout=15)
        ctx.evidence.clear_logcat()
        cmd = ["monkey", "-p", ctx.package, "-c", "android.intent.category.LAUNCHER", "1"]
        ctx.adb.shell(cmd, timeout=30)
        hits: set[str] = set()
        raw = []
        for _ in range(self.polls):
            ctx.sleep(1.5)
            table = _stdout(ctx, ["cat", "/proc/net/tcp", "/proc/net/tcp6"])
            raw.append(table)
            for line in table.splitlines():
                parts = line.split()
                if len(parts) > 7 and parts[7] == uid and parts[2].upper().endswith(":0050"):
                    hits.add(_decode_addr(parts[2]))
        cap = self.capture(ctx, subdir, cmd, f"app uid {uid}; port-80 peers: {sorted(hits) or 'none'}",
                           {"proc_net_tcp.txt": "\n----\n".join(raw)})
        if hits:
            return CheckResult(Status.CONFIRMED, f"The app opened plain-HTTP (port 80) connections to "
                               f"{', '.join(sorted(hits))} right after launch.", cap.evidence)
        if "Cleartext HTTP traffic" in cap.logcat and "not permitted" in cap.logcat:
            return CheckResult(Status.UNCONFIRMED, "The platform blocked a cleartext request (see logcat).",
                               cap.evidence)
        return CheckResult(Status.UNCONFIRMED, "No port-80 connections observed during launch. Cleartext on "
                           "other ports or behind login is not covered yet.", cap.evidence)


def _decode_addr(field: str) -> str:
    """Decode a /proc/net/tcp 'HEXIP:HEXPORT' address (IPv4 or IPv4-mapped IPv6)."""
    ip_hex, port_hex = field.split(":")
    try:
        v4 = ip_hex[-8:]
        ip = ".".join(str(int(v4[i:i + 2], 16)) for i in (6, 4, 2, 0))
        return f"{ip}:{int(port_hex, 16)}"
    except ValueError:
        return field


class LeakedSecretsCheck(Check):
    id = "secrets-exposure"
    name = "Find hardcoded secrets in logcat and app storage"
    categories = frozenset({SECRETS})
    order = 80

    def applies(self, finding: Finding) -> bool:
        return finding.category == SECRETS and bool(finding.private.get("values"))

    def run(self, finding: Finding, ctx: CheckContext) -> CheckResult:
        subdir = ctx.evidence.subdir(finding.id)
        values: list[str] = finding.private["values"][:50]
        log_path, now = ctx.evidence.logcat_snapshot(subdir)
        ev = [log_path] if log_path else []
        logs = ctx.session_logcat + "\n" + now
        in_logs = [v for v in values if v in logs]
        in_storage = []
        if ctx.root:
            for v in values[:20]:
                # -e so a value starting with "-" is never parsed as an option.
                if _stdout(ctx, ["grep", "-rlF", "-e", v, f"/data/data/{ctx.package}"]):
                    in_storage.append(v)
        ev.append(ctx.evidence.write_text(subdir, "matches.txt",
                                          f"in logcat: {[_mask(v) for v in in_logs]}\n"
                                          f"in app storage: {[_mask(v) for v in in_storage]}\n"
                                          f"(root available: {ctx.root})"))
        if in_logs or in_storage:
            where = " and ".join(w for w, ok in (("logcat", in_logs), ("app storage", in_storage)) if ok)
            return CheckResult(Status.CONFIRMED, f"{len(set(in_logs + in_storage))} hardcoded secret(s) were "
                               f"exposed at runtime in {where}.", ev)
        return CheckResult(Status.UNCONFIRMED, "Secrets exist in the APK (anyone can extract them statically) "
                           "but were not seen in logcat or storage at runtime.", ev)
