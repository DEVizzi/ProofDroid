# ProofDroid Report: Diva \<script\>alert(1)\</script\>

Generated 2026-11-10T18:29:50+05:30 by ProofDroid 0.1.0.

## Summary

| Status | Count |
| --- | --- |
| Confirmed | 0 |
| Unconfirmed | 0 |
| Not testable | 13 |

## Target

- **Package:** jakhar.aseem.diva
- **Version:** 1.0
- **APK:** diva-sample.apk
- **SHA-256:** `74d89e416490b24a6aea74fa1bd616c31c0c406958d8121a6b4ce4c75c3822e1`
- **Dynamic analysis:** skipped (--no-dynamic)

## Ranked findings

| # | Status | Severity | Finding | Component |
| --- | --- | --- | --- | --- |
| 1 | Not testable | High | [Broadcast Receiver (jakhar.aseem.diva.BootReceiver) is not Protected.](#finding-1) | jakhar.aseem.diva.BootReceiver |
| 2 | Not testable | High | [Activity (jakhar.aseem.diva.MainActivity) is vulnerable to StrandHogg 2.0](#finding-2) |  |
| 3 | Not testable | High | [Debug Enabled For App \[android:debuggable=true\]](#finding-3) |  |
| 4 | Not testable | High | [Base config is insecurely configured to permit clear text traffic.](#finding-4) |  |
| 5 | Not testable | Medium | [Application vulnerable to Janus Vulnerability](#finding-5) |  |
| 6 | Not testable | Medium | [App uses SQLite Database and execute raw SQL query.](#finding-6) |  |
| 7 | Not testable | Medium | [Activity (jakhar.aseem.diva.APICreds2Activity) is exported](#finding-7) | jakhar.aseem.diva.APICreds2Activity |
| 8 | Not testable | Medium | [Activity (jakhar.aseem.diva.APICredsActivity) is not Protected. \[android:exported=true\]](#finding-8) | jakhar.aseem.diva.APICredsActivity |
| 9 | Not testable | Medium | [Content Provider (jakhar.aseem.diva.NotesProvider) is not Protected.](#finding-9) | jakhar.aseem.diva.NotesProvider |
| 10 | Not testable | Medium | [Service (.SyncService) is not Protected.](#finding-10) | .SyncService |
| 11 | Not testable | Medium | [Possible hardcoded secrets (1)](#finding-11) |  |
| 12 | Not testable | Medium | [Sensitive data stored insecurely on the device](#finding-12) |  |
| 13 | Not testable | Info | [The App logs information. Sensitive information should never be logged.](#finding-13) |  |

## Details

<a id="finding-1"></a>
### 1. [Not testable] Broadcast Receiver (jakhar.aseem.diva.BootReceiver) is not Protected.

- **Severity:** High
- **Category:** exported\_receiver
- **Component:** `jakhar.aseem.diva.BootReceiver`
- **Check:** exported-receiver
- **Result:** Dynamic verification was skipped (--no-dynamic).

A receiver is exported.

---

<a id="finding-2"></a>
### 2. [Not testable] Activity (jakhar.aseem.diva.MainActivity) is vulnerable to StrandHogg 2.0

- **Severity:** High
- **Category:** manifest
- **Result:** No automated verification check exists for this finding yet.

StrandHogg.

---

<a id="finding-3"></a>
### 3. [Not testable] Debug Enabled For App \[android:debuggable=true\]

- **Severity:** High
- **Category:** manifest
- **Result:** No automated verification check exists for this finding yet.

Debugging was enabled on the app.

---

<a id="finding-4"></a>
### 4. [Not testable] Base config is insecurely configured to permit clear text traffic.

- **Severity:** High
- **Category:** network
- **Check:** cleartext-traffic
- **Result:** Dynamic verification was skipped (--no-dynamic).

Scope: \*

---

<a id="finding-5"></a>
### 5. [Not testable] Application vulnerable to Janus Vulnerability

- **Severity:** Medium
- **Category:** certificate
- **Result:** No automated verification check exists for this finding yet.

Application is signed with v1 signature scheme.

---

<a id="finding-6"></a>
### 6. [Not testable] App uses SQLite Database and execute raw SQL query.

- **Severity:** Medium
- **Category:** code
- **References:** CWE-89
- **Result:** No automated verification check exists for this finding yet.

Matched in 1 source file(s) by MobSF static analysis.

---

<a id="finding-7"></a>
### 7. [Not testable] Activity (jakhar.aseem.diva.APICreds2Activity) is exported

- **Severity:** Medium
- **Category:** exported\_activity
- **Component:** `jakhar.aseem.diva.APICreds2Activity`
- **Check:** exported-activity
- **Result:** Dynamic verification was skipped (--no-dynamic).

Listed by MobSF as an exported activity reachable by other apps.

---

<a id="finding-8"></a>
### 8. [Not testable] Activity (jakhar.aseem.diva.APICredsActivity) is not Protected. \[android:exported=true\]

- **Severity:** Medium
- **Category:** exported\_activity
- **Component:** `jakhar.aseem.diva.APICredsActivity`
- **Check:** exported-activity
- **Result:** Dynamic verification was skipped (--no-dynamic).

An Activity is found to be shared with other apps on the device.

---

<a id="finding-9"></a>
### 9. [Not testable] Content Provider (jakhar.aseem.diva.NotesProvider) is not Protected.

- **Severity:** Medium
- **Category:** exported\_provider
- **Component:** `jakhar.aseem.diva.NotesProvider`
- **Result:** No automated verification check exists for this finding yet.

A provider is exported.

---

<a id="finding-10"></a>
### 10. [Not testable] Service (.SyncService) is not Protected.

- **Severity:** Medium
- **Category:** exported\_service
- **Component:** `.SyncService`
- **Check:** exported-service
- **Result:** Dynamic verification was skipped (--no-dynamic).

A Service is exported.

---

<a id="finding-11"></a>
### 11. [Not testable] Possible hardcoded secrets (1)

- **Severity:** Medium
- **Category:** secrets
- **Check:** secrets-exposure
- **Result:** Dynamic verification was skipped (--no-dynamic).

MobSF flagged 1 possible secrets. Masked samples: "api\_k…\[masked\]

---

<a id="finding-12"></a>
### 12. [Not testable] Sensitive data stored insecurely on the device

- **Severity:** Medium
- **Category:** storage
- **Check:** insecure-storage
- **Result:** Dynamic verification was skipped (--no-dynamic).

Runtime inspection of the app sandbox and shared external storage after launch.

---

<a id="finding-13"></a>
### 13. [Not testable] The App logs information. Sensitive information should never be logged.

- **Severity:** Info
- **Category:** code
- **References:** CWE-532: Insertion of Sensitive Information into Log File, MSTG-STORAGE-3
- **Result:** No automated verification check exists for this finding yet.

Matched in 2 source file(s) by MobSF static analysis.

---


_"Confirmed" means ProofDroid reproduced the issue on an emulator and captured evidence. "Unconfirmed" means a check ran but could not prove it. "Not testable" means no automated check exists yet or the dynamic stage could not run; these still deserve manual review. Only test apps you own or are explicitly authorised to test._
