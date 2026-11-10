"""Command-line entry point.

    proofdroid scan path/to/app.apk [options]
    proofdroid doctor
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

from . import __version__
from .adb import find_adb, find_sdk_root
from .emulator import EmulatorController
from .mobsf_client import MobSFClient, MobSFError
from .pipeline import PipelineError, RunOptions, run

log = logging.getLogger("proofdroid")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="proofdroid",
        description="Scan an APK with MobSF and prove which findings are exploitable on an emulator.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan and verify an APK")
    scan.add_argument("apk", type=Path, help="path to the APK")
    scan.add_argument("--mobsf-url", default=os.environ.get("MOBSF_URL", "http://127.0.0.1:8000"),
                      help="MobSF base URL (default: %(default)s). API key is read from MOBSF_API_KEY.")
    scan.add_argument("--mobsf-json", type=Path, help="use an existing MobSF JSON report instead of scanning")
    scan.add_argument("--reports-dir", type=Path, default=Path("reports"), help="output folder (default: reports)")
    scan.add_argument("--no-dynamic", action="store_true", help="static only; mark checkable findings Not testable")
    device = scan.add_mutually_exclusive_group()
    device.add_argument("--avd", help="AVD to boot headless (default: first AVD found)")
    device.add_argument("--serial", help="use an already running device, e.g. emulator-5554")
    scan.add_argument("--port", type=int, default=5554, help="emulator console port (default: 5554)")
    scan.add_argument("--boot-timeout", type=int, default=300, help="seconds to wait for boot (default: 300)")
    scan.add_argument("--settle", type=float, default=2.0, help="seconds to wait after each trigger (default: 2)")
    scan.add_argument("--keep-emulator", action="store_true", help="leave the emulator running afterwards")
    scan.add_argument("--record", action="store_true", help="screen-record the verification session (max 180s)")
    scan.add_argument("--llm", action="store_true",
                      help="add plain-language explanations via an OpenAI-compatible API (see README)")
    scan.add_argument("--uninstall", action="store_true", help="uninstall the app after testing")

    sub.add_parser("doctor", help="check that MobSF, adb and the emulator are set up")
    return parser


def _doctor() -> int:
    ok = True

    def line(good: bool, label: str, detail: str = "") -> None:
        nonlocal ok
        ok = ok and good
        print(f"[{'ok' if good else '!!'}] {label}{': ' + detail if detail else ''}")

    line(sys.version_info >= (3, 11), "Python 3.11+", sys.version.split()[0])
    sdk = find_sdk_root()
    line(sdk is not None, "Android SDK", str(sdk) if sdk else "set ANDROID_SDK_ROOT")
    adb = find_adb(sdk)
    line(adb is not None, "adb", adb or "install platform-tools")
    controller = EmulatorController(sdk, adb)
    line(controller.emulator_path is not None, "emulator", controller.emulator_path or "install with sdkmanager")
    avds = controller.list_avds()
    line(bool(avds), "AVDs", ", ".join(avds) or "create one with avdmanager")
    key = os.environ.get("MOBSF_API_KEY", "")
    line(bool(key), "MOBSF_API_KEY set")
    if key:
        url = os.environ.get("MOBSF_URL", "http://127.0.0.1:8000")
        try:
            MobSFClient(url, key, timeout=10).ping()
            line(True, "MobSF reachable", url)
        except (MobSFError, ValueError) as exc:
            line(False, "MobSF reachable", str(exc))
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)-7s %(message)s", datefmt="%H:%M:%S")
    if args.command == "doctor":
        return _doctor()

    options = RunOptions(
        apk=args.apk, reports_dir=args.reports_dir, mobsf_url=args.mobsf_url, mobsf_json=args.mobsf_json,
        dynamic=not args.no_dynamic, avd=args.avd, serial=args.serial, port=args.port,
        boot_timeout=args.boot_timeout, keep_emulator=args.keep_emulator, record=args.record,
        uninstall=args.uninstall, settle_seconds=args.settle, llm=args.llm,
    )
    try:
        run_dir = run(options)
    except PipelineError as exc:
        log.error("%s", exc)
        return 2
    except KeyboardInterrupt:
        log.error("Interrupted")
        return 130
    print(f"\nReport written to {run_dir / 'report.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
