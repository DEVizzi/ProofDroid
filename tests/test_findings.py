import json
import unittest

from proofdroid.adb import Adb, component_spec, resolve_component, validate_package
from proofdroid.findings import clean_text, extract_findings
from proofdroid.models import (
    CERTIFICATE, CODE, EXPORTED_ACTIVITY, EXPORTED_PROVIDER, EXPORTED_RECEIVER, EXPORTED_SERVICE,
    MANIFEST, NETWORK, SECRETS, Severity,
)
from proofdroid.triage import rank_findings
from proofdroid.models import Status

from .helpers import FIXTURES


def load_sample():
    return json.loads((FIXTURES / "mobsf_report_sample.json").read_text())


class FindingsTest(unittest.TestCase):
    def setUp(self):
        self.findings = extract_findings(load_sample())
        self.by_cat = {}
        for f in self.findings:
            self.by_cat.setdefault(f.category, []).append(f)

    def test_exported_components_detected(self):
        acts = {f.component for f in self.by_cat[EXPORTED_ACTIVITY]}
        # Manifest finding + fallback list, deduplicated; StrandHogg is NOT an exposure.
        self.assertEqual(acts, {"jakhar.aseem.diva.APICredsActivity", "jakhar.aseem.diva.APICreds2Activity"})
        self.assertEqual(self.by_cat[EXPORTED_SERVICE][0].component, ".SyncService")
        self.assertEqual(self.by_cat[EXPORTED_RECEIVER][0].severity, Severity.HIGH)
        self.assertIn(EXPORTED_PROVIDER, self.by_cat)

    def test_other_sections(self):
        for cat in (MANIFEST, CODE, NETWORK, CERTIFICATE, SECRETS):
            self.assertIn(cat, self.by_cat, cat)
        titles = [f.title for f in self.by_cat[MANIFEST]]
        self.assertTrue(any("StrandHogg" in t for t in titles))
        self.assertFalse(any("Everything fine" in t for t in titles), "secure items must be dropped")

    def test_html_stripped_and_secrets_masked(self):
        for f in self.findings:
            self.assertNotIn("<strong>", f.title)
        secret = self.by_cat[SECRETS][0]
        self.assertNotIn("SECRETVALUE", secret.description)

    def test_ids_unique(self):
        ids = [f.id for f in self.findings]
        self.assertEqual(len(ids), len(set(ids)))

    def test_tolerates_garbage(self):
        self.assertEqual(extract_findings({}), [])
        self.assertEqual(extract_findings({"manifest_analysis": "x", "code_analysis": [1], "secrets": [3]}), [])

    def test_old_list_style_manifest(self):
        report = {"package_name": "a.b", "manifest_analysis": [
            {"title": "<strong>Activity</strong> (a.b.X) is not Protected.", "stat": "high", "desc": "d"}]}
        (f,) = extract_findings(report)
        self.assertEqual((f.category, f.component, f.severity), (EXPORTED_ACTIVITY, "a.b.X", Severity.HIGH))

    def test_clean_text(self):
        self.assertEqual(clean_text("<b>a</b>&amp;  b", None), "a & b")
        self.assertEqual(len(clean_text("x" * 50, 10)), 10)


class ValidationTest(unittest.TestCase):
    def test_package(self):
        self.assertEqual(validate_package("com.example.app"), "com.example.app")
        for bad in ("com", "com.example;rm -rf /", "com.ex ample", "$(id).x", "", "a.b\n"):
            with self.assertRaises(ValueError, msg=bad):
                validate_package(bad)

    def test_component(self):
        self.assertEqual(resolve_component("a.b", ".Main"), "a.b.Main")
        self.assertEqual(resolve_component("a.b", "Main"), "a.b.Main")
        self.assertEqual(resolve_component("a.b", "x.y.Outer$Inner"), "x.y.Outer$Inner")
        self.assertEqual(component_spec("a.b", ".Main"), "a.b/a.b.Main")
        for bad in ("a.b.X;id", "a.b.X`id`", "../x", "a b"):
            with self.assertRaises(ValueError, msg=bad):
                resolve_component("a.b", bad)

    def test_serial(self):
        with self.assertRaises(ValueError):
            Adb("adb", "emulator-5554; reboot")

    def test_shell_quoting(self):
        self.assertEqual(Adb._remote(["am", "start", "a b", "x;y"]), "am start 'a b' 'x;y'")


class TriageTest(unittest.TestCase):
    def test_order(self):
        findings = extract_findings(load_sample())
        findings[-1].status = Status.CONFIRMED
        findings[0].status = Status.UNCONFIRMED
        ranked = rank_findings(findings)
        self.assertEqual(ranked[0].status, Status.CONFIRMED)
        self.assertEqual(ranked[1].status, Status.UNCONFIRMED)
        self.assertEqual([f.rank for f in ranked], list(range(1, len(ranked) + 1)))
        rest = ranked[2:]
        self.assertEqual([int(f.severity) for f in rest], sorted((int(f.severity) for f in rest), reverse=True))


if __name__ == "__main__":
    unittest.main()
