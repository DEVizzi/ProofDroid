# ProofDroid launch kit

Replace `DEVizzi` with your GitHub username. Post only after a real DIVA run gives you a
sample report with Confirmed findings and a demo GIF.

## 1. Publish (from your personal machine and personal GitHub account)

```bash
cd ProofDroid
git init -b main
git config user.name "Your Name"; git config user.email "you@personal.example"
git add . && git commit -m "ProofDroid v0.1.0"
gh repo create ProofDroid --public --source . --push      # or create it on github.com and `git push`
git tag v0.1.0 && git push --tags
```

Then on GitHub:
- Settings → Pages → Source: *Deploy from a branch*, branch `main`, folder `/docs`.
- Settings → General: add the description and topics `android-security mobsf frida pentest`.
- Releases → draft `v0.1.0` from the tag and paste the changelog below.
- Replace `DEVizzi` in `docs/index.md`.

## 2. Release notes (v0.1.0)

First public release. ProofDroid scans an APK with MobSF, then verifies findings on a headless emulator:
exported activities, services and receivers, cleartext traffic, insecure storage, leaked hardcoded secrets,
and trust-all TrustManagers (Frida). Every finding is Confirmed (with evidence), Unconfirmed, or Not testable.
Outputs Markdown, HTML and JSON reports. Standard library only, MIT licensed.

## 3. Show HN

**Title:** Show HN: ProofDroid – prove which MobSF findings in an Android app are actually exploitable

MobSF is great at listing what's in an APK, but a typical report has 50+ findings and most are noise.
ProofDroid takes that output and tries each finding on a headless emulator: it launches exported
activities as an unprivileged caller, watches the app's sockets for plain HTTP, greps the sandbox for
tokens, and uses Frida to check whether the app's TrustManager accepts any certificate. Every finding ends
up Confirmed (with screenshots/logcat as evidence), Unconfirmed, or Not testable.

It's a Python CLI with zero dependencies. MobSF runs separately in Docker over its REST API.
Tested on deliberately vulnerable apps (DIVA, InsecureBankv2, OVAA).

Repo: https://github.com/DEVizzi/ProofDroid · Sample report: https://DEVizzi.github.io/ProofDroid/

I'd love feedback on which checks to add next.

## 4. Reddit r/netsec / r/androiddev

**Title:** ProofDroid: open-source tool that turns MobSF static findings into proven, evidence-backed results

Same body as HN, plus a short "how a check works" section, e.g. the exported-activity flow:
`am force-stop` → `am start -W -n pkg/cls` as uid 2000 → check `mResumedActivity` → screenshot + logcat.

## 5. LinkedIn / X

> Static scanners tell you what's in a mobile app. Clients want to know what's actually exploitable.
> I built ProofDroid, an open-source CLI that takes MobSF findings and proves them on an emulator,
> with screenshots, logs and Frida output as evidence. It produces a short, ranked report.
> 🔗 github.com/DEVizzi/ProofDroid  #AndroidSecurity #AppSec #OpenSource

(X version: cut to the first two sentences + link + GIF.)

## 6. Blog post outline: "Running ProofDroid against open-source apps"

1. The problem: 60 MobSF findings, which ones matter?
2. Setup in 5 minutes (Docker MobSF + emulator).
3. DIVA walkthrough: what got Confirmed, with screenshots.
4. Why "Unconfirmed" and "Not testable" are honest, useful answers.
5. How to write your own check (~50 lines).
6. Roadmap and call for contributors.

## Pre-launch checklist

- [ ] Employment agreement / conflict-of-interest policy checked
- [ ] Built and published from a personal device and account
- [ ] Name free on GitHub, Google, Play Store
- [ ] Real DIVA report in `docs/sample-report/` + demo GIF in README
- [ ] CI green on GitHub Actions
