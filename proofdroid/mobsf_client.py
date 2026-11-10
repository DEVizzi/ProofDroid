"""Minimal MobSF REST API client (standard library only).

ProofDroid never bundles MobSF code; it only talks to a separately running
MobSF instance (usually Docker on 127.0.0.1:8000) over HTTP.

API used:
  POST /api/v1/upload       multipart file  -> {"hash", "file_name", "scan_type"}
  POST /api/v1/scan         hash=<md5>      -> scan summary
  POST /api/v1/report_json  hash=<md5>      -> full JSON report
  GET  /api/v1/scans                        -> recent scans (used as a health check)
"""

from __future__ import annotations

import json
import logging
import re
import secrets
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable

log = logging.getLogger(__name__)

LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
MAX_ERROR_BODY = 300
HASH_RE = re.compile(r"^[0-9a-fA-F]{32}$")


class MobSFError(RuntimeError):
    """Raised for any MobSF communication or protocol error."""


def _safe_upload_name(path: Path) -> str:
    """Return a header-safe filename that still ends in .apk (MobSF checks the extension)."""
    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", path.stem).strip("._")[:80] or "app"
    return f"{stem}.apk"


class MobSFClient:
    def __init__(
        self,
        base_url: str,
        api_key: str,
        timeout: float = 900,
        opener: Callable[..., Any] | None = None,
    ):
        parsed = urllib.parse.urlparse(base_url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError(f"Invalid MobSF URL: {base_url!r}")
        if not api_key:
            raise ValueError("A MobSF API key is required (set the MOBSF_API_KEY environment variable).")
        if parsed.scheme == "http" and parsed.hostname not in LOOPBACK_HOSTS:
            log.warning("MobSF URL uses plain HTTP to a non-local host; the API key and APK travel unencrypted.")
        self.base_url = base_url.rstrip("/")
        self._api_key = api_key
        self.timeout = timeout
        self._opener = opener or urllib.request.urlopen

    def __repr__(self) -> str:  # Never leak the API key in logs/tracebacks.
        return f"MobSFClient(base_url={self.base_url!r})"

    # -- low level ---------------------------------------------------------

    def _request(self, method: str, path: str, data: bytes | None = None,
                 content_type: str | None = None) -> bytes:
        req = urllib.request.Request(self.base_url + path, data=data, method=method)
        req.add_header("Authorization", self._api_key)
        req.add_header("X-Mobsf-Api-Key", self._api_key)
        if content_type:
            req.add_header("Content-Type", content_type)
        try:
            with self._opener(req, timeout=self.timeout) as resp:
                return resp.read()
        except urllib.error.HTTPError as exc:
            body = (exc.read() or b"")[:MAX_ERROR_BODY].decode("utf-8", "replace")
            raise MobSFError(f"MobSF returned HTTP {exc.code} for {path}: {body}") from None
        except urllib.error.URLError as exc:
            raise MobSFError(f"Could not reach MobSF at {self.base_url}: {exc.reason}") from None

    def _json(self, method: str, path: str, data: bytes | None = None,
              content_type: str | None = None) -> dict:
        raw = self._request(method, path, data, content_type)
        try:
            result = json.loads(raw.decode("utf-8", "replace"))
        except json.JSONDecodeError:
            raise MobSFError(f"MobSF returned non-JSON data for {path}") from None
        if not isinstance(result, dict):
            raise MobSFError(f"Unexpected MobSF response type for {path}")
        if "error" in result and len(result) <= 2:
            raise MobSFError(f"MobSF error for {path}: {str(result['error'])[:MAX_ERROR_BODY]}")
        return result

    def _post_form(self, path: str, fields: dict[str, str]) -> dict:
        data = urllib.parse.urlencode(fields).encode()
        return self._json("POST", path, data, "application/x-www-form-urlencoded")

    # -- public API --------------------------------------------------------

    def ping(self) -> bool:
        """Return True if MobSF is reachable and accepts our API key."""
        self._json("GET", "/api/v1/scans?page=1&page_size=1")
        return True

    def upload(self, apk_path: Path) -> dict:
        boundary = "----ProofDroid" + secrets.token_hex(16)
        filename = _safe_upload_name(apk_path)
        body = b"".join([
            f"--{boundary}\r\n".encode(),
            f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'.encode(),
            b"Content-Type: application/vnd.android.package-archive\r\n\r\n",
            apk_path.read_bytes(),
            f"\r\n--{boundary}--\r\n".encode(),
        ])
        result = self._json("POST", "/api/v1/upload", body, f"multipart/form-data; boundary={boundary}")
        file_hash = str(result.get("hash", ""))
        if not HASH_RE.fullmatch(file_hash):
            raise MobSFError("MobSF upload response did not contain a valid file hash.")
        return result

    def scan(self, file_hash: str) -> dict:
        return self._post_form("/api/v1/scan", {"hash": self._check_hash(file_hash)})

    def report_json(self, file_hash: str) -> dict:
        return self._post_form("/api/v1/report_json", {"hash": self._check_hash(file_hash)})

    def scan_apk(self, apk_path: Path) -> tuple[str, dict]:
        """Upload, scan and fetch the JSON report. Returns (hash, report)."""
        log.info("Uploading %s to MobSF", apk_path.name)
        file_hash = self.upload(apk_path)["hash"]
        log.info("Running MobSF static scan (hash %s); this can take a few minutes", file_hash)
        self.scan(file_hash)
        log.info("Downloading MobSF JSON report")
        return file_hash, self.report_json(file_hash)

    @staticmethod
    def _check_hash(file_hash: str) -> str:
        if not HASH_RE.fullmatch(file_hash or ""):
            raise ValueError(f"Invalid MobSF file hash: {file_hash!r}")
        return file_hash
