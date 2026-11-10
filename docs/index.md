---
title: ProofDroid
---

# ProofDroid

**MobSF tells you what's in an Android app. ProofDroid tells you what to worry about, and proves it.**

Every finding ends up **Confirmed** (with screenshots, logs and command output as evidence),
**Unconfirmed**, or **Not testable**.

## Choose how to use it

| | What you get | Proof? | Setup |
| --- | --- | --- | --- |
| **[1. Scan in your browser](scan/)** | Instant manifest findings. Your APK never leaves your browser. | No (static only) | None |
| **[2. Full scan on GitHub Actions](https://github.com/DEVizzi/ProofDroid#full-scan-on-github-actions)** | Full report with evidence, run on an emulator in GitHub's cloud | Yes | Fork the repo, paste an APK link |
| **[3. Run locally (CLI)](https://github.com/DEVizzi/ProofDroid#quick-start)** | Everything, on your own emulator, with MobSF or the built-in engine | Yes | Python + Android SDK |

## See a real report

[DIVA sample report (HTML)](sample-report/report.html) · [Markdown](sample-report/report.md)

A real run against DIVA on an Android 16 emulator: **3 Confirmed**, including all 6 private notes
read from an exported content provider by an app with no permissions.

## What it verifies

| Check | How it proves it |
| --- | --- |
| Exported activities | Launched by an unprivileged caller; reaches the foreground |
| Exported services | Started externally; shows as running in `dumpsys` |
| Exported receivers | Explicit broadcast delivered with no permission denial |
| Exported content providers | Queried by an unprivileged caller; rows of private data returned |
| Cleartext traffic | Live port-80 sockets owned by the app's uid |
| Insecure storage | Sensitive keywords / world-readable files in the sandbox and external storage |
| Hardcoded secrets | Secret values from the APK appear in logcat or app storage |
| Trust-all TrustManager | Frida calls the app's TrustManager with an empty chain; it doesn't throw |

Open source (MIT). Only test apps you own or are authorised to test.
