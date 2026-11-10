import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from proofdroid.checks import CheckContext, default_checks, find_check
from proofdroid.checks.data_exposure import CleartextTrafficCheck, InsecureStorageCheck, LeakedSecretsCheck
from proofdroid.checks.frida_trustmanager import TrustManagerFridaCheck
from proofdroid.evidence import EvidenceCollector
from proofdroid.findings import extract_findings
from proofdroid.models import CODE, NETWORK, SECRETS, STORAGE, Finding, Severity, Status
from proofdroid.triage import llm_triage, rank_findings

from .helpers import FIXTURES, PNG, FakeAdb

PKG = "jakhar.aseem.diva"
SECRET = "AIzaSyD-SECRETVALUE1234567890"


def f(category, title="t", **kw):
    return Finding(id=f"{category}-x", title=title, severity=Severity.MEDIUM, category=category, **kw)


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.run_dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def ctx(self, table, **kw):
        def respond(cmd):
            if "screencap" in cmd:
                return PNG
            return next((v for k, v in table.items() if k in cmd), "")
        adb = FakeAdb(respond)
        return CheckContext(adb=adb, evidence=EvidenceCollector(adb, self.run_dir), package=PKG,
                            settle_seconds=0, sleep=lambda s: None, **kw)


class DataExposureTest(Base):
    def test_storage(self):
        storage = f(STORAGE)
        prefs = {"grep -rinE": "/data/data/x/shared_prefs/a.xml:3:<string name=\"password\">hunter2</string>"}
        self.assertEqual(InsecureStorageCheck().run(storage, self.ctx(prefs, root=True)).status, Status.CONFIRMED)
        self.assertEqual(InsecureStorageCheck().run(storage, self.ctx({}, root=True)).status, Status.UNCONFIRMED)
        self.assertEqual(InsecureStorageCheck().run(storage, self.ctx({})).status, Status.NOT_TESTABLE)

    def test_cleartext(self):
        finding = f(NETWORK, "Base config is insecurely configured to permit clear text traffic.")
        self.assertTrue(CleartextTrafficCheck().applies(finding))
        tcp = ("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid\n"
               "   0: 0F02000A:A1B2 2200A8C0:0050 01 00000000:00000000 00:00000000 00000000 10123 0 1")
        ctx = self.ctx({"pm list packages": f"package:{PKG} uid:10123", "/proc/net/tcp": tcp})
        r = CleartextTrafficCheck().run(finding, ctx)
        self.assertEqual(r.status, Status.CONFIRMED, r.reason)
        self.assertIn("192.168.0.34:80", r.reason)
        other_uid = self.ctx({"pm list packages": f"package:{PKG} uid:10999", "/proc/net/tcp": tcp})
        self.assertEqual(CleartextTrafficCheck().run(finding, other_uid).status, Status.UNCONFIRMED)

    def test_secrets(self):
        (secret,) = [x for x in extract_findings(json.loads((FIXTURES / "mobsf_report_sample.json").read_text()))
                     if x.category == SECRETS]
        self.assertEqual(secret.private["values"], [SECRET])
        self.assertNotIn("private", secret.to_dict())
        leak = self.ctx({}, session_logcat=f"D Api: using key {SECRET}")
        r = LeakedSecretsCheck().run(secret, leak)
        self.assertEqual(r.status, Status.CONFIRMED)
        for rel in r.evidence:
            if rel.endswith("matches.txt"):
                self.assertNotIn(SECRET, (self.run_dir / rel).read_text())
        self.assertEqual(LeakedSecretsCheck().run(secret, self.ctx({})).status, Status.UNCONFIRMED)
        ctx = self.ctx({}, root=True)
        LeakedSecretsCheck().run(secret, ctx)
        self.assertIn(["shell", f"grep -rlF -e {SECRET} /data/data/{PKG}"], ctx.adb.calls)


class FridaTest(Base):
    finding = f(CODE, "Insecure Implementation of SSL. Trusting all the certificates")

    def run_with(self, output):
        ctx = self.ctx({}, frida_path="/usr/bin/frida")
        proc = mock.Mock(stdout=output, stderr="")
        with mock.patch("subprocess.run", return_value=proc) as run:
            result = TrustManagerFridaCheck().run(self.finding, ctx)
        self.assertNotIn("shell=True", str(run.call_args))
        return result

    def test_statuses(self):
        self.assertTrue(TrustManagerFridaCheck().applies(self.finding))
        self.assertEqual(TrustManagerFridaCheck().run(self.finding, self.ctx({})).status, Status.NOT_TESTABLE)
        ready = 'PD:{"type":"ready"}\n'
        self.assertEqual(self.run_with(ready + 'PD:{"type":"trust_all","cls":"a.TrustAll"}').status,
                         Status.CONFIRMED)
        self.assertEqual(self.run_with(ready + 'PD:{"type":"trust_ok","cls":"x"}').status, Status.UNCONFIRMED)
        self.assertEqual(self.run_with(ready).status, Status.UNCONFIRMED)
        self.assertEqual(self.run_with("Failed to spawn: unable to connect").status, Status.NOT_TESTABLE)


class FakeResp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        pass


class LlmTriageTest(unittest.TestCase):
    def test_llm(self):
        findings = rank_findings([f(CODE, "A"), f(SECRETS, "B", private={"values": [SECRET]})])
        sent = {}

        def opener(req, timeout):
            sent["body"] = req.data.decode()
            content = "```json\n" + json.dumps([{"rank": 1, "explanation": "Plain words."}]) + "\n```"
            return FakeResp(json.dumps({"choices": [{"message": {"content": content}}]}).encode())

        self.assertFalse(llm_triage(findings, opener))  # Not configured.
        env = {"PROOFDROID_LLM_URL": "https://api.example/v1/chat/completions",
               "PROOFDROID_LLM_KEY": "k", "PROOFDROID_LLM_MODEL": "m"}
        with mock.patch.dict(os.environ, env):
            self.assertTrue(llm_triage(findings, opener))
        self.assertEqual(findings[0].explanation, "Plain words.")
        self.assertNotIn(SECRET, sent["body"])
        with mock.patch.dict(os.environ, {**env, "PROOFDROID_LLM_URL": "http://remote.example/x"}):
            self.assertFalse(llm_triage(findings, opener))

    def test_registry_routes(self):
        checks = default_checks()
        self.assertIsInstance(find_check(f(STORAGE), checks), InsecureStorageCheck)
        self.assertIsNone(find_check(f(NETWORK, "Domain config is fine"), checks))


if __name__ == "__main__":
    unittest.main()
