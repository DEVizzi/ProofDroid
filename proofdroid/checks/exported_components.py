"""Verify exported activities, services and broadcast receivers.

All checks run as the unprivileged `shell` user (uid 2000), which stands in for
"some other app on the device". If Android lets the shell reach the component,
any installed app can too.
"""

from __future__ import annotations

from ..adb import resolve_component
from ..models import EXPORTED_ACTIVITY, EXPORTED_RECEIVER, EXPORTED_SERVICE, CheckResult, Finding, Status
from .base import Check, CheckContext


def _out(result) -> str:
    return ((result.stdout or "") + (result.stderr or "")).strip()


def _first_error(text: str) -> str:
    for line in text.splitlines():
        if "Error" in line or "Exception" in line:
            return line.strip()[:200]
    return ""


class ExportedActivityCheck(Check):
    id = "exported-activity"
    name = "Launch exported activity from an external caller"
    categories = frozenset({EXPORTED_ACTIVITY})

    def run(self, finding: Finding, ctx: CheckContext) -> CheckResult:
        cls = resolve_component(ctx.package, finding.component or "")
        spec = f"{ctx.package}/{cls}"
        subdir = ctx.evidence.subdir(finding.id)

        ctx.adb.shell(["am", "force-stop", ctx.package], timeout=15)  # Start from a cold state.
        ctx.evidence.clear_logcat()
        cmd = ["am", "start", "-W", "-n", spec]
        output = _out(ctx.adb.shell(cmd, timeout=30))
        ctx.sleep(ctx.settle_seconds)

        dumpsys = ctx.adb.shell(["dumpsys", "activity", "activities"], timeout=30).stdout or ""
        resumed = "\n".join(l.strip() for l in dumpsys.splitlines() if "ResumedActivity" in l)
        cap = self.capture(ctx, subdir, cmd, output, {"resumed_activity.txt": resumed or "(none)"})

        if self.denied(output):
            return CheckResult(Status.UNCONFIRMED,
                               "Android refused the launch from an unprivileged caller "
                               "(SecurityException / permission denial).", cap.evidence)
        if "Error" in output:
            return CheckResult(Status.UNCONFIRMED, f"am start failed: {_first_error(output)}", cap.evidence)
        if self.names_match(resumed, ctx.package, cls):
            return CheckResult(Status.CONFIRMED,
                               f"{cls} was launched directly by an external, unprivileged caller and "
                               "reached the foreground, bypassing the app's normal entry flow.", cap.evidence)
        return CheckResult(Status.UNCONFIRMED,
                           "Launch was accepted but the activity did not stay in the foreground "
                           "(it may have finished or crashed). Review the logcat evidence.", cap.evidence)


class ExportedServiceCheck(Check):
    id = "exported-service"
    name = "Start exported service from an external caller"
    categories = frozenset({EXPORTED_SERVICE})

    def run(self, finding: Finding, ctx: CheckContext) -> CheckResult:
        cls = resolve_component(ctx.package, finding.component or "")
        spec = f"{ctx.package}/{cls}"
        subdir = ctx.evidence.subdir(finding.id)

        ctx.evidence.clear_logcat()
        cmd = ["am", "startservice", "-n", spec]
        output = _out(ctx.adb.shell(cmd, timeout=30))
        transcript = output
        if "Not allowed to start service" in output:
            # Android 8+ background start limits: retry as a foreground service.
            cmd = ["am", "start-foreground-service", "-n", spec]
            output = _out(ctx.adb.shell(cmd, timeout=30))
            transcript += f"\n\n$ adb shell {' '.join(cmd)}\n\n{output}"
        ctx.sleep(ctx.settle_seconds)

        services = ctx.adb.shell(["dumpsys", "activity", "services", ctx.package], timeout=30).stdout or ""
        cap = self.capture(ctx, subdir, ["am", "startservice", "-n", spec], transcript,
                           {"dumpsys_services.txt": services or "(empty)"})

        # Judge only the final attempt's output.
        if self.denied(output) or (self.denied(cap.logcat) and cls in cap.logcat):
            return CheckResult(Status.UNCONFIRMED,
                               "Android refused to start the service for an unprivileged caller.", cap.evidence)
        if "Error" in output:
            return CheckResult(Status.UNCONFIRMED, f"am startservice failed: {_first_error(output)}", cap.evidence)
        if self.names_match(services, ctx.package, cls):
            return CheckResult(Status.CONFIRMED,
                               f"{cls} was started by an external, unprivileged caller and is running "
                               "(see dumpsys_services.txt).", cap.evidence)
        return CheckResult(Status.UNCONFIRMED,
                           "Start request was accepted but the service was not observed running "
                           "(it may have stopped immediately).", cap.evidence)


class ExportedReceiverCheck(Check):
    id = "exported-receiver"
    name = "Send explicit broadcast from an external caller"
    categories = frozenset({EXPORTED_RECEIVER})

    def run(self, finding: Finding, ctx: CheckContext) -> CheckResult:
        cls = resolve_component(ctx.package, finding.component or "")
        spec = f"{ctx.package}/{cls}"
        subdir = ctx.evidence.subdir(finding.id)

        ctx.evidence.clear_logcat()
        cmd = ["am", "broadcast", "-n", spec]
        output = _out(ctx.adb.shell(cmd, timeout=30))
        ctx.sleep(ctx.settle_seconds)
        cap = self.capture(ctx, subdir, cmd, output)

        denial_lines = [l for l in cap.logcat.splitlines()
                        if "Permission Denial" in l and (cls in l or ctx.package in l)]
        if self.denied(output) or denial_lines:
            return CheckResult(Status.UNCONFIRMED,
                               "Android blocked delivery to the receiver (permission denial in logcat).",
                               cap.evidence)
        if "Broadcast completed" in output:
            return CheckResult(Status.CONFIRMED,
                               f"An explicit broadcast from an external, unprivileged caller was delivered "
                               f"to {cls} with no permission denial.", cap.evidence)
        return CheckResult(Status.UNCONFIRMED, "Broadcast did not complete; see command output.", cap.evidence)
