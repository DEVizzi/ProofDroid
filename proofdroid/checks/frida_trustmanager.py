"""Frida check: does the app install a TrustManager that accepts any certificate?

Uses the `frida` CLI if it's on PATH (no Python dependency). It needs frida-server
running on a rooted device. The hook wraps SSLContext.init. For every TrustManager
the app passes in, it calls checkServerTrusted() with an EMPTY chain. A correct
implementation throws; a trust-all one returns, which proves the weakness.
"""

from __future__ import annotations

import json
import subprocess

from ..models import CODE, CheckResult, Finding, Status
from .base import Check, CheckContext

HOOK_JS = r"""
Java.perform(function () {
  var X509 = Java.use('javax.net.ssl.X509TrustManager');
  var Ctx = Java.use('javax.net.ssl.SSLContext');
  Ctx.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;',
                    'java.security.SecureRandom').implementation = function (km, tms, sr) {
    if (tms) {
      for (var i = 0; i < tms.length; i++) {
        var cls = tms[i].getClass().getName();
        try {
          var chain = Java.array('java.security.cert.X509Certificate', []);
          Java.cast(tms[i], X509).checkServerTrusted(chain, 'RSA');
          console.log('PD:' + JSON.stringify({type: 'trust_all', cls: cls}));
        } catch (e) {
          console.log('PD:' + JSON.stringify({type: 'trust_ok', cls: cls}));
        }
      }
    }
    return this.init(km, tms, sr);
  };
  console.log('PD:' + JSON.stringify({type: 'ready'}));
});
"""

KEYWORDS = ("trusting all", "trustmanager", "x509", "insecure implementation of ssl", "self signed", "ssl")
FRIDA_FAILURES = ("Failed to spawn", "unable to connect", "Failed to attach", "not found", "need Gadget",
                  "unable to find", "Failed to enumerate")


class TrustManagerFridaCheck(Check):
    id = "frida-trustmanager"
    name = "Prove a trust-all TrustManager with Frida"
    categories = frozenset({CODE})
    order = 90
    timeout = 20

    def __init__(self) -> None:
        self._cache: dict[str, CheckResult] = {}  # One Frida session per package is enough.

    def applies(self, finding: Finding) -> bool:
        return finding.category == CODE and any(k in finding.title.lower() for k in KEYWORDS)

    def run(self, finding: Finding, ctx: CheckContext) -> CheckResult:
        if not ctx.frida_path:
            return CheckResult(Status.NOT_TESTABLE, "frida CLI not installed (pip install frida-tools, plus "
                               "frida-server on a rooted emulator).")
        if ctx.package in self._cache:
            return self._cache[ctx.package]
        subdir = ctx.evidence.subdir(finding.id)
        hook = subdir / "hook.js"
        hook.write_text(HOOK_JS, encoding="utf-8")
        ctx.adb.shell(["am", "force-stop", ctx.package], timeout=15)
        device = ["-D", ctx.adb.serial] if ctx.adb.serial else ["-U"]
        cmd = [ctx.frida_path, *device, "-f", ctx.package, "-l", str(hook),
               "-q", "-t", str(self.timeout)]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout + 30,  # noqa: S603
                                  check=False, errors="replace")
            output = (proc.stdout or "") + (proc.stderr or "")
        except subprocess.TimeoutExpired as exc:
            output = (exc.stdout or b"").decode("utf-8", "replace") if isinstance(exc.stdout, bytes) \
                else (exc.stdout or "")
        events = []
        for line in output.splitlines():
            if line.startswith("PD:"):
                try:
                    events.append(json.loads(line[3:]))
                except json.JSONDecodeError:
                    pass
        cap = self.capture(ctx, subdir, ["frida", "-f", ctx.package, "-l", "hook.js"], output)
        cap.evidence.insert(0, ctx.evidence.rel(hook))
        trust_all = sorted({e.get("cls", "") for e in events if e.get("type") == "trust_all"})

        if not any(e.get("type") == "ready" for e in events):
            hint = next((m for m in FRIDA_FAILURES if m in output), "hook did not load")
            result = CheckResult(Status.NOT_TESTABLE, f"Frida could not instrument the app ({hint}). Is "
                                 "frida-server running as root on the device?", cap.evidence)
        elif trust_all:
            result = CheckResult(Status.CONFIRMED, f"TrustManager {', '.join(trust_all)} accepted an empty "
                                 "certificate chain: the app trusts any certificate, so HTTPS can be intercepted.",
                                 cap.evidence)
        elif events and any(e.get("type") == "trust_ok" for e in events):
            result = CheckResult(Status.UNCONFIRMED, "Every TrustManager the app installed rejected an invalid "
                                 "chain.", cap.evidence)
        else:
            result = CheckResult(Status.UNCONFIRMED, f"The app made no SSLContext.init call in {self.timeout}s. "
                                 "The code may only run behind a login or another screen.", cap.evidence)
        self._cache[ctx.package] = result
        return result
