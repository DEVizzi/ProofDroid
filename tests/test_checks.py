import tempfile
import unittest
from pathlib import Path

from proofdroid.checks import CheckContext, default_checks, find_check
from proofdroid.checks.exported_components import (
    ExportedActivityCheck, ExportedReceiverCheck, ExportedServiceCheck,
)
from proofdroid.evidence import EvidenceCollector, safe_name
from proofdroid.models import EXPORTED_ACTIVITY, EXPORTED_RECEIVER, EXPORTED_SERVICE, Finding, Severity, Status

from .helpers import PNG, FakeAdb

PKG = "jakhar.aseem.diva"


def finding(category, component):
    return Finding(id=f"{category}-x", title="t", severity=Severity.MEDIUM, category=category, component=component)


class ChecksTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.run_dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def ctx(self, responder):
        adb = FakeAdb(responder)
        return CheckContext(adb=adb, evidence=EvidenceCollector(adb, self.run_dir), package=PKG,
                            settle_seconds=0, sleep=lambda s: None)

    @staticmethod
    def responder(table):
        def respond(cmd):
            if "screencap" in cmd:
                return PNG
            for key, value in table.items():
                if key in cmd:
                    return value
            return ""
        return respond

    def assert_evidence_exists(self, result):
        self.assertTrue(result.evidence)
        for rel in result.evidence:
            self.assertTrue((self.run_dir / rel).is_file(), rel)
        self.assertTrue(any(p.endswith("screenshot.png") for p in result.evidence))
        self.assertTrue(any(p.endswith("logcat.txt") for p in result.evidence))

    def test_activity_confirmed(self):
        ctx = self.ctx(self.responder({
            "am start": "Starting: Intent { cmp=jakhar.aseem.diva/.APICredsActivity }\nStatus: ok",
            "dumpsys activity activities": "  mResumedActivity: ActivityRecord{1 u0 jakhar.aseem.diva/.APICredsActivity t5}",
        }))
        result = ExportedActivityCheck().run(finding(EXPORTED_ACTIVITY, ".APICredsActivity"), ctx)
        self.assertEqual(result.status, Status.CONFIRMED)
        self.assert_evidence_exists(result)
        # The component was passed as a single quoted-safe argument.
        self.assertIn(["shell", "am start -W -n jakhar.aseem.diva/jakhar.aseem.diva.APICredsActivity"],
                      ctx.adb.calls)

    def test_activity_denied(self):
        ctx = self.ctx(self.responder({
            "am start": "Exception occurred: java.lang.SecurityException: Permission Denial: starting Intent",
        }))
        result = ExportedActivityCheck().run(finding(EXPORTED_ACTIVITY, "jakhar.aseem.diva.Secret"), ctx)
        self.assertEqual(result.status, Status.UNCONFIRMED)

    def test_activity_not_foreground(self):
        ctx = self.ctx(self.responder({"am start": "Status: ok", "dumpsys": "mResumedActivity: other/.X"}))
        result = ExportedActivityCheck().run(finding(EXPORTED_ACTIVITY, ".A"), ctx)
        self.assertEqual(result.status, Status.UNCONFIRMED)

    def test_service_confirmed_after_background_retry(self):
        ctx = self.ctx(self.responder({
            "am startservice": "Error: app is in background: Not allowed to start service Intent",
            "start-foreground-service": "Starting service: Intent { cmp=jakhar.aseem.diva/.SyncService }",
            "dumpsys activity services": "* ServiceRecord{abc u0 jakhar.aseem.diva/.SyncService}",
        }))
        result = ExportedServiceCheck().run(finding(EXPORTED_SERVICE, ".SyncService"), ctx)
        self.assertEqual(result.status, Status.CONFIRMED, result.reason)

    def test_service_not_found(self):
        ctx = self.ctx(self.responder({"am startservice": "Error: Not found; no service started."}))
        result = ExportedServiceCheck().run(finding(EXPORTED_SERVICE, ".Nope"), ctx)
        self.assertEqual(result.status, Status.UNCONFIRMED)

    def test_receiver_confirmed_and_denied(self):
        ok = self.ctx(self.responder({"am broadcast": "Broadcasting: Intent\nBroadcast completed: result=0"}))
        self.assertEqual(ExportedReceiverCheck().run(finding(EXPORTED_RECEIVER, ".R"), ok).status, Status.CONFIRMED)
        denied = self.ctx(self.responder({
            "am broadcast": "Broadcast completed: result=0",
            "logcat -d": "W BroadcastQueue: Permission Denial: receiving Intent to jakhar.aseem.diva/.R",
        }))
        self.assertEqual(ExportedReceiverCheck().run(finding(EXPORTED_RECEIVER, ".R"), denied).status,
                         Status.UNCONFIRMED)

    def test_malicious_component_rejected(self):
        ctx = self.ctx(self.responder({}))
        with self.assertRaises(ValueError):
            ExportedActivityCheck().run(finding(EXPORTED_ACTIVITY, "x;reboot"), ctx)
        self.assertFalse(any("reboot" in " ".join(c) for c in ctx.adb.calls))

    def test_registry(self):
        checks = default_checks()
        self.assertIsInstance(find_check(finding(EXPORTED_ACTIVITY, ".A"), checks), ExportedActivityCheck)
        self.assertIsNone(find_check(finding("code", None), checks))
        self.assertIsNone(find_check(finding(EXPORTED_ACTIVITY, None), checks))


class EvidenceTest(unittest.TestCase):
    def test_safe_name_and_confinement(self):
        self.assertEqual(safe_name("../../etc/passwd"), "etc_passwd")
        self.assertEqual(safe_name("..."), "item")
        with tempfile.TemporaryDirectory() as tmp:
            ev = EvidenceCollector(FakeAdb(lambda c: ""), Path(tmp))
            sub = ev.subdir("../escape")
            self.assertTrue(sub.resolve().is_relative_to(Path(tmp).resolve() / "evidence"))

    def test_non_png_screenshot_discarded(self):
        with tempfile.TemporaryDirectory() as tmp:
            ev = EvidenceCollector(FakeAdb(lambda c: b"error: device offline"), Path(tmp))
            self.assertIsNone(ev.screenshot(ev.subdir("x")))


if __name__ == "__main__":
    unittest.main()
