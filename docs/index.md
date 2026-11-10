---
title: ProofDroid
---

# ProofDroid

**MobSF tells you what's in an Android app. ProofDroid tells you what to worry about, and proves it.**

ProofDroid scans an APK with MobSF, then runs it on a headless emulator. There it tries to
exploit each finding and saves evidence (screenshots, logcat, Frida output). The result is a
short, ranked report where every finding is **Confirmed**, **Unconfirmed** or **Not testable**.

- [Install guide and usage](https://github.com/DEVizzi/ProofDroid#quick-start)
- [Sample report (HTML)](sample-report/report.html) · [Markdown](sample-report/report.md)

> Real run against DIVA on an Android 16 emulator (built-in static engine, no root):
> 3 Confirmed with evidence, including private notes read from an exported content provider.

## What it verifies today

| Check | How it proves it |
| --- | --- |
| Exported activities | Launched by an unprivileged caller; reaches the foreground |
| Exported services | Started externally; shows as running in `dumpsys` |
| Exported receivers | Explicit broadcast delivered with no permission denial |
| Cleartext traffic | Live port-80 sockets owned by the app's uid (`/proc/net/tcp`) |
| Insecure storage | Sensitive keywords / world-readable files in sandbox and external storage |
| Hardcoded secrets | Secret values from the APK appear in logcat or app storage |
| Trust-all TrustManager | Frida calls the app's TrustManager with an empty chain; it doesn't throw |

Open source (MIT). Only test apps you own or are authorised to test.
