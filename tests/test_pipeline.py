import io
import json
import tempfile
import unittest
import urllib.error
from pathlib import Path

from proofdroid.mobsf_client import MobSFClient, MobSFError
from proofdroid.pipeline import PipelineError, RunOptions, run, validate_apk

from .helpers import FIXTURES


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


class FakeOpener:
    def __init__(self, responses):
        self.responses = responses
        self.requests = []

    def __call__(self, req, timeout=None):
        self.requests.append(req)
        path = req.full_url.split("8000", 1)[1]
        for key, value in self.responses.items():
            if path.startswith(key):
                if isinstance(value, Exception):
                    raise value
                return FakeResponse(json.dumps(value).encode())
        raise AssertionError(f"unexpected request {path}")


def make_apk(directory: Path, name="diva.apk") -> Path:
    path = directory / name
    path.write_bytes(b"PK\x03\x04" + b"\x00" * 64)
    return path


class MobSFClientTest(unittest.TestCase):
    def test_scan_flow(self):
        h = "0123456789abcdef0123456789abcdef"
        opener = FakeOpener({
            "/api/v1/upload": {"hash": h, "file_name": "diva.apk", "scan_type": "apk"},
            "/api/v1/scan": {"status": "ok"},
            "/api/v1/report_json": {"package_name": "a.b"},
        })
        client = MobSFClient("http://127.0.0.1:8000", "secret-key", opener=opener)
        with tempfile.TemporaryDirectory() as tmp:
            apk = make_apk(Path(tmp), "my app;$(id).apk")
            file_hash, report = client.scan_apk(apk)
        self.assertEqual((file_hash, report), (h, {"package_name": "a.b"}))
        upload = opener.requests[0]
        self.assertEqual(upload.get_header("Authorization"), "secret-key")
        self.assertIn(b'filename="my_app_id.apk"', upload.data)
        self.assertEqual(opener.requests[1].data, f"hash={h}".encode())
        for req in opener.requests:
            self.assertNotIn("secret-key", req.full_url)
        self.assertNotIn("secret-key", repr(client))

    def test_errors(self):
        err = urllib.error.HTTPError("u", 401, "nope", {}, io.BytesIO(b'{"error":"bad key"}'))
        client = MobSFClient("http://127.0.0.1:8000", "k", opener=FakeOpener({"/api/v1/scans": err}))
        with self.assertRaises(MobSFError):
            client.ping()
        bad_hash = FakeOpener({"/api/v1/upload": {"hash": "../../x"}})
        with tempfile.TemporaryDirectory() as tmp, self.assertRaises(MobSFError):
            MobSFClient("http://127.0.0.1:8000", "k", opener=bad_hash).upload(make_apk(Path(tmp)))
        with self.assertRaises(ValueError):
            MobSFClient("ftp://x", "k")
        with self.assertRaises(ValueError):
            MobSFClient("http://127.0.0.1:8000", "")


class PipelineTest(unittest.TestCase):
    def test_validate_apk(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "x.apk").write_bytes(b"not a zip")
            (tmp / "x.txt").write_bytes(b"PK\x03\x04")
            for p in (tmp / "x.apk", tmp / "x.txt", tmp / "missing.apk"):
                with self.assertRaises(PipelineError):
                    validate_apk(p)

    def test_static_only_run_produces_reports(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            apk = make_apk(tmp)
            run_dir = run(RunOptions(apk=apk, reports_dir=tmp / "reports",
                                     mobsf_json=FIXTURES / "mobsf_report_sample.json", dynamic=False))
            for name in ("report.md", "report.html", "findings.json", "mobsf_report.json"):
                self.assertTrue((run_dir / name).is_file(), name)

            data = json.loads((run_dir / "findings.json").read_text())
            statuses = {f["status"] for f in data["findings"]}
            self.assertEqual(statuses, {"Not testable"})
            checked = [f for f in data["findings"] if f["check_id"]]
            self.assertTrue(checked)
            self.assertTrue(all("--no-dynamic" in f["status_reason"] for f in checked))

            html_text = (run_dir / "report.html").read_text()
            self.assertNotIn("<script>", html_text)
            self.assertIn("&lt;script&gt;", html_text)
            self.assertIn("Content-Security-Policy", html_text)
            md_text = (run_dir / "report.md").read_text()
            self.assertNotIn("<script>", md_text)
            self.assertNotIn("SECRETVALUE", md_text + html_text)


if __name__ == "__main__":
    unittest.main()
