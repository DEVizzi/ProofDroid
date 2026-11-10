# ProofDroid

**MobSF tells you what's in an app. ProofDroid tells you what to worry about, and proves it.**

ProofDroid is an open-source command-line tool. It takes an Android APK, scans it with
[MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF), then runs the app on a
headless emulator to check which findings can really be exploited. For each one it saves
evidence (screenshots, logcat, command output). You get a short, ranked report you can hand to a client.

Every finding in the report gets exactly one status:

| Status | Meaning |
| --- | --- |
| **Confirmed** | ProofDroid reproduced it on a device and saved the evidence files. |
| **Unconfirmed** | A check ran but couldn't prove it, e.g. Android blocked the call. |
| **Not testable** | No automated check exists yet, or the dynamic stage couldn't run. |

## How it works

```
APK ──► MobSF REST API (static scan, JSON)
         │
         ▼
   findings ──► checks (am start / startservice / broadcast as an unprivileged caller)
         │            │
         │            └─► evidence/: screenshot.png, logcat.txt, command.txt, dumpsys
         ▼
   triage (rank) ──► report.md + report.html + findings.json
```

Checks:

| Check | Confirmed when | Needs |
| --- | --- | --- |
| Exported activity | `am start` brings it to the foreground, skipping the normal entry flow | – |
| Exported service | `am startservice` works and `dumpsys` shows it running | – |
| Exported receiver | Explicit broadcast completes with no permission denial in logcat | – |
| Cleartext traffic | The app's uid owns port-80 sockets in `/proc/net/tcp` after launch | – |
| Insecure storage | Sensitive keywords in shared_prefs/databases/files, world-readable files, or external storage | root for the sandbox |
| Hardcoded secrets | Secret values MobSF found in the APK show up in logcat or app storage | root for storage |
| Trust-all TrustManager | Frida hook: the app's TrustManager accepts an empty certificate chain | `frida` CLI + frida-server |

Checks run as the `shell` user (uid 2000). It stands in for any other app on the device.

## Three ways to use it

1. **In your browser:** [devizzi.github.io/ProofDroid/scan](https://devizzi.github.io/ProofDroid/scan/) gives instant
   manifest findings. The APK never leaves your browser.
2. **On GitHub Actions:** full scan with evidence, nothing to install (see below).
3. **Locally:** the CLI, described in the rest of this README.

### Full scan on GitHub Actions

1. Fork this repo.
2. In your fork, open **Actions → ProofDroid scan → Run workflow** and paste a direct `https://` link to the APK.
3. When it finishes (about 10–15 min), download the **proofdroid-report** file from the run page.

It runs on a rooted `google_apis` emulator, so the sandbox checks work there too.

## Requirements

- Python **3.11+**. ProofDroid uses only the standard library, so there's nothing to `pip install`.
- [Docker](https://docs.docker.com/get-docker/), to run MobSF.
- Android SDK command-line tools: `platform-tools` (adb), `emulator`, and a system image.

## Quick start

```bash
# 1. Start MobSF (localhost only) with an API key you choose
export MOBSF_API_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
docker compose up -d          # uses docker-compose.yml in this repo

# 2. Create an emulator (once). Use a google_apis image, not google_apis_playstore:
#    Play Store images can't `adb root`, and later checks will need root.
sdkmanager "system-images;android-34;google_apis;arm64-v8a"     # x86_64 on Intel
avdmanager create avd -n proofdroid -k "system-images;android-34;google_apis;arm64-v8a"

# 3. Install ProofDroid and check your setup
pip install -e .
proofdroid doctor

# 4. Scan a deliberately vulnerable app
proofdroid scan ~/targets/diva-beta.apk --avd proofdroid
```

Useful options:

| Option | Purpose |
| --- | --- |
| `--serial emulator-5554` | Use a device that's already running instead of booting one |
| `--no-dynamic` | Static only. Checkable findings are marked *Not testable* |
| `--mobsf-json report.json` | Skip MobSF and reuse a JSON report you already have |
| `--record` | Screen-record the verification session (180 s max) |
| `--keep-emulator` / `--uninstall` | Control cleanup |
| `--llm` | Add plain-language explanations (see below) |
| `--mobsf-url` | MobSF address (default `http://127.0.0.1:8000`, or set `$MOBSF_URL`) |

The API key is read **only** from `MOBSF_API_KEY`, so it never ends up in your shell history.

### Optional extras

- **Root:** ProofDroid runs `adb root` automatically. This works on `google_apis` images. Without root,
  the sandbox checks are marked *Not testable*.
- **Frida:** install the `frida` CLI on your machine (`pip install frida-tools`, which is optional and
  not a ProofDroid dependency). Push a matching `frida-server` to the emulator and run it as root:
  ```bash
  adb root && adb push frida-server /data/local/tmp/ && adb shell "chmod 755 /data/local/tmp/frida-server && /data/local/tmp/frida-server &"
  ```
- **LLM triage (`--llm`):** works with any OpenAI-compatible chat completions endpoint. It sends only
  each finding's title, severity, status and result line. Evidence, descriptions and secrets are never sent.
  ```bash
  export PROOFDROID_LLM_URL=https://api.openai.com/v1/chat/completions
  export PROOFDROID_LLM_KEY=...   PROOFDROID_LLM_MODEL=gpt-4o-mini
  ```

## Output

Each run gets its own folder:

```
reports/20261110-181500_diva-beta/
├── report.md            # ranked, client-ready report
├── report.html          # same report, self-contained, no JavaScript
├── findings.json        # machine-readable results
├── mobsf_report.json    # raw MobSF output
├── emulator.log
└── evidence/
    ├── 00_launch/launch.png
    └── exported-activity-apicredsactivity/
        ├── command.txt
        ├── resumed_activity.txt
        ├── screenshot.png
        └── logcat.txt
```

> Reports can contain sensitive client data. `reports/` is git-ignored on purpose.
> Possible hardcoded secrets are masked in the report (the raw MobSF JSON still has them).

## Project layout

```
proofdroid/
  cli.py            command-line entry point (scan, doctor)
  pipeline.py       orchestrates static → dynamic → report
  mobsf_client.py   upload, scan, fetch JSON (REST only, stdlib urllib)
  emulator.py       boot headless, wait for boot, install, launch, shut down
  adb.py            safe adb wrapper (input validation + remote shell quoting)
  evidence.py       screenshots, screen recordings, logcat
  findings.py       MobSF JSON → Finding objects
  checks/           one small module per verification check
  triage.py         ranking (LLM triage planned)
  report.py         Markdown / HTML / JSON reports
tests/              unittest suite with a fake adb, no device needed
```

### Adding a check

1. Create `proofdroid/checks/my_check.py` with a `Check` subclass. Give it `id`, `name` and
   `categories`, and implement `run(finding, ctx) -> CheckResult`.
2. Use `self.capture(...)` to save the command transcript, a screenshot and logcat.
3. Register it in `default_checks()` in `proofdroid/checks/__init__.py`.
4. Add tests with `tests/helpers.FakeAdb`.

## Development

```bash
python3 -m unittest discover -s tests -t . -v
```

## Security design

- The APK is untrusted input. Package and component names from it are checked against strict
  allow-list regexes. Every argument passed to `adb shell` is shell-quoted, because the device
  re-parses it. Nothing runs with `shell=True`.
- Evidence filenames are sanitised, and every write is confined to the run folder.
- Reports escape all text that comes from the app or MobSF. The HTML report has a strict CSP
  with no scripts.
- MobSF is bound to `127.0.0.1`. The API key is never logged or put in URLs. ProofDroid warns
  if you point it at a plain-HTTP remote host.

## Roadmap

- Done: exported components, cleartext, storage, secrets, Frida TrustManager, LLM triage,
  [sample report](docs/sample-report/report.md), [landing page](docs/index.md).
- Next: demo GIF from a DIVA run, Frida pinning bypass + MITM proof, launch posts.
- **v2:** SDK risk module, uiautomator2 login flows, iOS, CI/CD integration.

## Legal

Only test apps you own, or deliberately vulnerable apps that are legal to test:
[DIVA](https://github.com/payatu/diva-android), [InsecureBankv2](https://github.com/dineshshetty/Android-InsecureBankv2),
[OVAA](https://github.com/oversecured/ovaa). ProofDroid is not affiliated with MobSF. MobSF (GPLv3)
runs as a separate service and none of its code is included here.

## License

MIT. See [LICENSE](LICENSE).
