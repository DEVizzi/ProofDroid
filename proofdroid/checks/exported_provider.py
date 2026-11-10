"""Verify exported content providers by querying them as an unprivileged caller."""

from __future__ import annotations

import re

from ..adb import resolve_component
from ..models import EXPORTED_PROVIDER, CheckResult, Finding, Status
from .base import Check, CheckContext

AUTH_RE = re.compile(r"\[([A-Za-z0-9._;-]+)\]:\s*\n\s*Provider\{\S+ ([^}\s]+)\}")


class ExportedProviderCheck(Check):
    id = "exported-provider"
    name = "Query exported content provider from an external caller"
    categories = frozenset({EXPORTED_PROVIDER})
    order = 20
    max_uris = 6

    def run(self, finding: Finding, ctx: CheckContext) -> CheckResult:
        cls = resolve_component(ctx.package, finding.component or "")
        subdir = ctx.evidence.subdir(finding.id)
        dumpsys = ctx.adb.shell(["dumpsys", "package", ctx.package], timeout=30).stdout or ""
        found = [a for a, spec in AUTH_RE.findall(dumpsys)
                 if self.names_match(spec, ctx.package, cls) or spec.endswith(cls)]
        authorities = [x for a in found for x in a.split(";") if re.fullmatch(r"[A-Za-z0-9._-]+", x)]
        if not authorities:
            return CheckResult(Status.NOT_TESTABLE, "Could not find the provider's authority on the device.")

        uris = [u for u in ctx.content_uris if any(u.startswith(f"content://{a}") for a in authorities)]
        uris = list(dict.fromkeys(uris + [f"content://{a}/" for a in authorities]))[: self.max_uris]
        transcript, rows, denied = [], [], False
        for uri in uris:
            out = ctx.adb.shell(["content", "query", "--uri", uri], timeout=30)
            text = ((out.stdout or "") + (out.stderr or "")).strip()
            transcript.append(f"$ adb shell content query --uri {uri}\n{text}\n")
            denied |= self.denied(text)
            rows += [line for line in text.splitlines() if line.startswith("Row:")]
        cap = self.capture(ctx, subdir, ["content", "query", "--uri", uris[0]], "\n".join(transcript))
        if rows:
            return CheckResult(Status.CONFIRMED, f"An unprivileged caller read {len(rows)} row(s) of private app "
                               f"data from {cls} (see command.txt).", cap.evidence)
        if denied:
            return CheckResult(Status.UNCONFIRMED, "Android denied the query (permission required).", cap.evidence)
        return CheckResult(Status.UNCONFIRMED, f"Queries were accepted but returned no rows for the {len(uris)} "
                           "URI(s) tried.", cap.evidence)
