"""End-to-end pipeline: static scan -> dynamic verification -> ranked report."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from . import report as report_mod
from .adb import Adb, AdbError, validate_package
from .checks import CheckContext, default_checks, find_check
from .emulator import EmulatorController, EmulatorError
from .evidence import EvidenceCollector, safe_name
from .findings import clean_text, extract_findings
from .mobsf_client import MobSFClient, MobSFError
from .models import STORAGE, Finding, Severity, Status
from .triage import llm_triage, rank_findings, summarize

log = logging.getLogger(__name__)

APK_MAGIC = b"PK\x03\x04"
MAX_APK_BYTES = 1024 * 1024 * 1024  # 1 GiB
MAX_JSON_BYTES = 200 * 1024 * 1024


class PipelineError(RuntimeError):
    """A user-facing error that stops the run."""


@dataclass
class RunOptions:
    apk: Path
    reports_dir: Path = Path("reports")
    mobsf_url: str = "http://127.0.0.1:8000"
    mobsf_json: Path | None = None  # Use an existing MobSF JSON report instead of scanning.
    dynamic: bool = True
    avd: str | None = None
    serial: str | None = None
    port: int = 5554
    boot_timeout: int = 300
    keep_emulator: bool = False
    record: bool = False
    uninstall: bool = False
    settle_seconds: float = 2.0
    llm: bool = False
    static_engine: str = "mobsf"  # "mobsf" or "builtin" (aapt2 manifest analysis).


def validate_apk(path: Path) -> Path:
    path = path.expanduser()
    if not path.is_file():
        raise PipelineError(f"APK not found: {path}")
    if path.suffix.lower() != ".apk":
        raise PipelineError("Input must be an .apk file.")
    if path.stat().st_size > MAX_APK_BYTES:
        raise PipelineError("APK is larger than 1 GiB; refusing to process.")
    with path.open("rb") as fh:
        if fh.read(4) != APK_MAGIC:
            raise PipelineError("File does not look like an APK (missing ZIP header).")
    return path.resolve()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def create_run_dir(reports_dir: Path, apk: Path) -> Path:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    run_dir = reports_dir.expanduser().resolve() / f"{stamp}_{safe_name(apk.stem, 'app')}"
    suffix = 1
    while run_dir.exists():
        suffix += 1
        run_dir = run_dir.with_name(f"{stamp}_{safe_name(apk.stem, 'app')}_{suffix}")
    run_dir.mkdir(parents=True)
    return run_dir


def _load_static_report(options: RunOptions, apk: Path) -> tuple[dict, str | None]:
    if options.mobsf_json:
        path = options.mobsf_json.expanduser()
        if not path.is_file() or path.stat().st_size > MAX_JSON_BYTES:
            raise PipelineError(f"MobSF JSON report not found or too large: {path}")
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise PipelineError(f"Invalid JSON in {path}: {exc}") from None
        if not isinstance(data, dict):
            raise PipelineError("MobSF JSON report must be an object.")
        return data, None
    if options.static_engine == "builtin":
        from .static_builtin import StaticScanError, scan
        try:
            return scan(apk), None
        except StaticScanError as exc:
            raise PipelineError(str(exc)) from None
    api_key = os.environ.get("MOBSF_API_KEY", "").strip()
    if not api_key:
        raise PipelineError("Set MOBSF_API_KEY to your MobSF REST API key (or pass --mobsf-json).")
    try:
        client = MobSFClient(options.mobsf_url, api_key)
        file_hash, data = client.scan_apk(apk)
    except (MobSFError, ValueError) as exc:
        raise PipelineError(str(exc)) from None
    return data, file_hash


def _mark(findings: list[Finding], status: Status, reason: str, only_checked: bool = True) -> None:
    for f in findings:
        if not only_checked or f.check_id:
            f.status, f.status_reason = status, reason


def _run_dynamic(options: RunOptions, apk: Path, package: str, run_dir: Path,
                 testable: list[Finding], meta: dict) -> None:
    controller = EmulatorController()
    adb: Adb | None = None
    try:
        if options.serial:
            adb = controller.attach(options.serial)
        else:
            avd = options.avd or next(iter(controller.list_avds()), None)
            if not avd:
                raise EmulatorError("No AVD found. Create one with avdmanager or pass --serial.")
            adb = controller.boot(avd, options.port, log_path=run_dir / "emulator.log")
        controller.wait_for_boot(adb, timeout=options.boot_timeout)
        meta["device"] = controller.device_info(adb)
        root = controller.try_root(adb)
        meta["root"] = root
        log.info("Root available: %s", root)

        controller.install(adb, apk)
        evidence = EvidenceCollector(adb, run_dir)
        recording = evidence.start_recording() if options.record else None

        controller.launch(adb, package)
        time.sleep(3)
        launch_dir = evidence.subdir("00_launch")
        evidence.screenshot(launch_dir, "launch.png")
        _, session_log = evidence.logcat_snapshot(launch_dir)

        ctx = CheckContext(adb=adb, evidence=evidence, package=package, settle_seconds=options.settle_seconds,
                           root=root, session_logcat=session_log, frida_path=shutil.which("frida"),
                           content_uris=list(meta.get("_content_uris", [])))
        checks = {c.id: c for c in default_checks()}
        for finding in sorted(testable, key=lambda f: checks[f.check_id].order):
            check = checks[finding.check_id]
            log.info("Verifying %s with %s", finding.component, check.id)
            try:
                result = check.run(finding, ctx)
            except ValueError as exc:  # e.g. component name failed validation
                finding.status, finding.status_reason = Status.NOT_TESTABLE, f"Skipped: {exc}"
                continue
            except AdbError as exc:
                finding.status, finding.status_reason = Status.NOT_TESTABLE, f"Check could not run: {exc}"
                continue
            finding.status, finding.status_reason, finding.evidence = result.status, result.reason, result.evidence
            log.info("  -> %s", result.status.value)

        if recording is not None:
            path = evidence.stop_recording(recording, evidence.subdir("session"))
            if path:
                meta["recording"] = path
        if options.uninstall:
            controller.uninstall(adb, package)
    except (EmulatorError, AdbError) as exc:
        log.error("Dynamic stage failed: %s", exc)
        meta["dynamic"] = f"failed: {clean_text(exc, 200)}"
        for f in testable:
            if not f.evidence:
                f.status, f.status_reason = Status.NOT_TESTABLE, f"Dynamic stage failed: {clean_text(exc, 200)}"
    finally:
        if not options.keep_emulator:
            controller.shutdown(adb)


def run(options: RunOptions) -> Path:
    """Execute the full pipeline and return the run folder."""
    apk = validate_apk(options.apk)
    run_dir = create_run_dir(options.reports_dir, apk)
    log.info("Run folder: %s", run_dir)

    # 1. Static analysis.
    static_report, file_hash = _load_static_report(options, apk)
    (run_dir / "mobsf_report.json").write_text(json.dumps(static_report, indent=2), encoding="utf-8")
    try:
        package = validate_package(str(static_report.get("package_name") or ""))
    except ValueError as exc:
        raise PipelineError(f"MobSF report has no valid package_name: {exc}") from None

    meta = {
        "generated": datetime.now().astimezone().isoformat(timespec="seconds"),
        "app_name": clean_text(static_report.get("app_name"), 100),
        "package": package,
        "version": clean_text(static_report.get("version_name"), 50),
        "apk_name": apk.name,
        "apk_sha256": sha256_file(apk),
        "mobsf_hash": file_hash or clean_text(static_report.get("md5"), 32),
        "dynamic": "enabled" if options.dynamic else "skipped (--no-dynamic)",
        "static_engine": clean_text(static_report.get("static_engine") or "MobSF", 60),
        "_content_uris": [u for u in static_report.get("content_uris") or [] if isinstance(u, str)][:50],
    }

    # 2. Map findings to checks.
    findings = extract_findings(static_report)
    findings.append(Finding(
        id="storage-sandbox", title="Sensitive data stored insecurely on the device", severity=Severity.MEDIUM,
        category=STORAGE, source="proofdroid",
        description="Runtime inspection of the app sandbox and shared external storage after launch.",
    ))
    checks = default_checks()
    for f in findings:
        check = find_check(f, checks)
        if check:
            f.check_id = check.id
    testable = [f for f in findings if f.check_id]
    log.info("%d findings, %d with an automated check", len(findings), len(testable))

    # 3. Dynamic verification.
    if not testable:
        meta["dynamic"] = "not needed (no testable findings)"
    elif options.dynamic:
        _run_dynamic(options, apk, package, run_dir, testable, meta)
    else:
        _mark(findings, Status.NOT_TESTABLE, "Dynamic verification was skipped (--no-dynamic).")

    # 4. Rank and report.
    meta.pop("_content_uris", None)
    findings = rank_findings(findings)
    if options.llm:
        llm_triage(findings)
    report_mod.write_findings_json(run_dir, meta, findings)
    md_path = report_mod.write_markdown(run_dir, meta, findings)
    report_mod.write_html(run_dir, meta, findings)
    log.info("Summary: %s", ", ".join(f"{k}: {v}" for k, v in summarize(findings).items()))
    log.info("Report: %s", md_path)
    return run_dir
