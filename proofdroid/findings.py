"""Turn a MobSF JSON report into a flat list of ProofDroid `Finding`s.

MobSF's JSON shape has shifted between versions, so every accessor here is
defensive: unknown shapes are skipped rather than crashing the run.
"""

from __future__ import annotations

import html
import re
from typing import Any, Iterable

from .adb import resolve_component
from .models import (
    CERTIFICATE, CODE, EXPORTED_ACTIVITY, EXPORTED_PROVIDER, EXPORTED_RECEIVER,
    EXPORTED_SERVICE, MANIFEST, NETWORK, SECRETS, Finding, Severity,
)

_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")
# e.g. "<strong>Broadcast Receiver</strong> (com.app.MyReceiver) is not Protected."
_COMPONENT_TITLE_RE = re.compile(
    r"(?:<strong>\s*)?\b(Activity-Alias|Activity|Service|Broadcast Receiver|Content Provider)\b"
    r"\s*(?:</strong>)?\s*\(([A-Za-z0-9_.$]+)\)",
    re.IGNORECASE,
)
_TYPE_TO_CATEGORY = {
    "activity": EXPORTED_ACTIVITY,
    "activity-alias": EXPORTED_ACTIVITY,
    "service": EXPORTED_SERVICE,
    "broadcast receiver": EXPORTED_RECEIVER,
    "content provider": EXPORTED_PROVIDER,
}


def clean_text(value: Any, limit: int | None = None) -> str:
    """Strip HTML tags/entities that MobSF embeds in titles and collapse whitespace."""
    text = html.unescape(_TAG_RE.sub(" ", str(value or "")))
    text = _WS_RE.sub(" ", text).strip()
    if limit and len(text) > limit:
        text = text[: limit - 1] + "…"
    return text


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")[:60] or "finding"


class _IdMaker:
    def __init__(self) -> None:
        self._seen: dict[str, int] = {}

    def make(self, *parts: str) -> str:
        base = _slug("-".join(p for p in parts if p))
        n = self._seen.get(base, 0) + 1
        self._seen[base] = n
        return base if n == 1 else f"{base}-{n}"


def _is_exposure(lowered_title: str) -> bool:
    return "not protected" in lowered_title or "protected by a permission" in lowered_title \
        or "exported" in lowered_title


def _normalise(package: str, name: str) -> str:
    try:
        return resolve_component(package, name)
    except ValueError:
        return name


def _manifest_items(report: dict) -> Iterable[dict]:
    ma = report.get("manifest_analysis")
    items = ma.get("manifest_findings", []) if isinstance(ma, dict) else ma
    if isinstance(items, list):
        yield from (i for i in items if isinstance(i, dict))


def _name_list(value: Any) -> list[str]:
    """MobSF sometimes stores lists as their Python repr string; handle both."""
    if isinstance(value, list):
        return [str(v) for v in value if isinstance(v, str) and v]
    if isinstance(value, str):
        return re.findall(r"[A-Za-z_$][A-Za-z0-9_.$]+", value)
    return []


def _mask_secret(value: str) -> str:
    value = clean_text(value)
    return (value[:6] + "…[masked]") if len(value) > 6 else "[masked]"


def _secret_values(items: list[str]) -> list[str]:
    """Pull the value part out of MobSF strings like '"api_key" : "AIza..."'."""
    values = []
    for item in items:
        value = item.split(":", 1)[-1].strip().strip('"\' ')
        if len(value) >= 8:
            values.append(value)
    return values


def extract_findings(report: dict) -> list[Finding]:
    package = str(report.get("package_name") or "")
    ids = _IdMaker()
    findings: list[Finding] = []
    seen_components: set[tuple[str, str]] = set()

    # 1. Manifest findings (includes exported components).
    for item in _manifest_items(report):
        severity = Severity.from_mobsf(item.get("severity") or item.get("stat"))
        if severity is None:
            continue
        raw_title = str(item.get("title") or "")
        title = clean_text(raw_title, 300)
        desc = clean_text(item.get("description") or item.get("desc"), 2000)
        rule = str(item.get("rule") or "")
        match = _COMPONENT_TITLE_RE.search(raw_title)
        if match and _is_exposure(title.lower()):
            category = _TYPE_TO_CATEGORY[match.group(1).lower()]
            component = match.group(2)
            key = (category, _normalise(package, component))
            if key in seen_components:
                continue
            seen_components.add(key)
            findings.append(Finding(
                id=ids.make(category, component.split(".")[-1]), title=title, severity=severity,
                category=category, description=desc, component=component, rule=rule,
            ))
        else:
            findings.append(Finding(
                id=ids.make("manifest", rule or title[:40]), title=title, severity=severity,
                category=MANIFEST, description=desc, rule=rule,
            ))

    # 2. Fallback: explicit exported-activities list some MobSF versions provide.
    for component in _name_list(report.get("exported_activities")):
        key = (EXPORTED_ACTIVITY, _normalise(package, component))
        if key in seen_components:
            continue
        seen_components.add(key)
        findings.append(Finding(
            id=ids.make(EXPORTED_ACTIVITY, component.split(".")[-1]),
            title=f"Activity ({component}) is exported", severity=Severity.MEDIUM,
            category=EXPORTED_ACTIVITY, component=component,
            description="Listed by MobSF as an exported activity reachable by other apps.",
        ))

    # 3. Code analysis.
    ca = report.get("code_analysis") or {}
    entries = ca.get("findings") if isinstance(ca, dict) and isinstance(ca.get("findings"), dict) else ca
    if isinstance(entries, dict):
        for rule, entry in entries.items():
            if not isinstance(entry, dict) or not isinstance(entry.get("metadata"), dict):
                continue
            meta = entry["metadata"]
            severity = Severity.from_mobsf(meta.get("severity"))
            if severity is None:
                continue
            files = entry.get("files")
            nfiles = len(files) if isinstance(files, (dict, list)) else 0
            refs = [clean_text(meta[k], 120) for k in ("cwe", "owasp-mobile", "masvs") if meta.get(k)]
            findings.append(Finding(
                id=ids.make("code", str(rule)), title=clean_text(meta.get("description") or rule, 300),
                severity=severity, category=CODE, rule=str(rule), references=refs,
                description=f"Matched in {nfiles} source file(s) by MobSF static analysis.",
            ))

    # 4. Network security config.
    ns = report.get("network_security") or {}
    items = ns.get("network_findings") if isinstance(ns, dict) else ns
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict):
            continue
        severity = Severity.from_mobsf(item.get("severity"))
        if severity is None:
            continue
        scope = item.get("scope") or []
        scope_txt = ", ".join(clean_text(s, 100) for s in scope[:10]) if isinstance(scope, list) else ""
        findings.append(Finding(
            id=ids.make("network", clean_text(item.get("description"), 40)),
            title=clean_text(item.get("description"), 300), severity=severity, category=NETWORK,
            description=f"Scope: {scope_txt}" if scope_txt else "",
        ))

    # 5. Signing certificate.
    cert = report.get("certificate_analysis") or {}
    items = cert.get("certificate_findings") if isinstance(cert, dict) else cert
    for item in items if isinstance(items, list) else []:
        if isinstance(item, (list, tuple)) and len(item) >= 3:
            sev_raw, desc, title = item[0], item[1], item[2]
        elif isinstance(item, dict):
            sev_raw, desc, title = item.get("severity"), item.get("description"), item.get("title")
        else:
            continue
        severity = Severity.from_mobsf(sev_raw)
        if severity is None:
            continue
        findings.append(Finding(
            id=ids.make("certificate", clean_text(title, 40)), title=clean_text(title, 300),
            severity=severity, category=CERTIFICATE, description=clean_text(desc, 2000),
        ))

    # 6. Possible hardcoded secrets (values are masked in the report).
    secrets_list = [s for s in report.get("secrets") or [] if isinstance(s, str)]
    if secrets_list:
        samples = "; ".join(_mask_secret(s) for s in secrets_list[:5])
        findings.append(Finding(
            id=ids.make("secrets", "hardcoded"), title=f"Possible hardcoded secrets ({len(secrets_list)})",
            severity=Severity.MEDIUM, category=SECRETS,
            description=f"MobSF flagged {len(secrets_list)} possible secrets. Masked samples: {samples}",
            private={"values": _secret_values(secrets_list)},
        ))

    return findings
