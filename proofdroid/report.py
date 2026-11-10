"""Build the client-ready Markdown and HTML reports.

All text that originates from the APK or MobSF is untrusted: it is escaped for
Markdown, and HTML-escaped (with a script-free CSP) for the HTML report.
"""

from __future__ import annotations

import base64
import hashlib
import html
import json
import re
import urllib.parse
from pathlib import Path

from . import __version__
from .models import Finding, Status
from .triage import summarize

_MD_SPECIAL = re.compile(r"([\\`*_\[\]<>|#])")
DISCLAIMER = (
    "\"Confirmed\" means ProofDroid reproduced the issue on an emulator and captured evidence. "
    "\"Unconfirmed\" means a check ran but could not prove it. \"Not testable\" means no automated "
    "check exists yet or the dynamic stage could not run; these still deserve manual review. "
    "Only test apps you own or are explicitly authorised to test."
)


def md(text: object) -> str:
    """Escape untrusted text for inline Markdown (also neutralises raw HTML)."""
    return _MD_SPECIAL.sub(r"\\\1", str(text or "")).replace("\n", " ")


def _link(path: str) -> str:
    return urllib.parse.quote(path, safe="/._-")


def write_markdown(run_dir: Path, meta: dict, findings: list[Finding]) -> Path:
    counts = summarize(findings)
    lines = [
        f"# ProofDroid Report: {md(meta.get('app_name') or meta.get('package'))}",
        "",
        f"Generated {md(meta.get('generated'))} by ProofDroid {__version__}.",
        "",
        "## Summary",
        "",
        "| Status | Count |",
        "| --- | --- |",
        *[f"| {s} | {n} |" for s, n in counts.items()],
        "",
        "## Target",
        "",
        f"- **Package:** {md(meta.get('package'))}",
        f"- **Version:** {md(meta.get('version'))}",
        f"- **APK:** {md(meta.get('apk_name'))}",
        f"- **SHA-256:** `{md(meta.get('apk_sha256'))}`",
        f"- **Dynamic analysis:** {md(meta.get('dynamic'))}",
    ]
    if meta.get("device"):
        dev = meta["device"]
        lines.append(f"- **Device:** {md(dev.get('model'))}, Android {md(dev.get('android'))} "
                     f"(API {md(dev.get('sdk'))})")
    lines += ["", "## Ranked findings", "", "| # | Status | Severity | Finding | Component |",
              "| --- | --- | --- | --- | --- |"]
    for f in findings:
        lines.append(f"| {f.rank} | {f.status.value} | {f.severity.label} | "
                     f"[{md(f.title)}](#finding-{f.rank}) | {md(f.component or '')} |")
    lines += ["", "## Details", ""]
    for f in findings:
        lines += [
            f'<a id="finding-{f.rank}"></a>',
            f"### {f.rank}. [{f.status.value}] {md(f.title)}",
            "",
            f"- **Severity:** {f.severity.label}",
            f"- **Category:** {md(f.category)}",
        ]
        if f.component:
            lines.append(f"- **Component:** `{md(f.component)}`")
        if f.check_id:
            lines.append(f"- **Check:** {md(f.check_id)}")
        if f.references:
            lines.append(f"- **References:** {md(', '.join(f.references))}")
        lines.append(f"- **Result:** {md(f.status_reason)}")
        if f.explanation:
            lines.append(f"- **In plain language:** {md(f.explanation)}")
        if f.description:
            lines += ["", md(f.description)]
        if f.evidence:
            lines += ["", "**Evidence:**", ""]
            for path in f.evidence:
                lines.append(f"- [{md(Path(path).name)}]({_link(path)})")
            for path in f.evidence:
                if path.endswith(".png"):
                    lines += ["", f"![screenshot for finding {f.rank}]({_link(path)})"]
        lines += ["", "---", ""]
    lines += ["", f"_{md(DISCLAIMER)}_", ""]
    out = run_dir / "report.md"
    out.write_text("\n".join(lines), encoding="utf-8")
    return out


_CSS = """
body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;max-width:980px;margin:2rem auto;padding:0 1rem;color:#1d2330}
h1{margin-bottom:.2rem}table{border-collapse:collapse;width:100%;margin:1rem 0}
th,td{border:1px solid #d5d9e0;padding:.4rem .6rem;text-align:left;vertical-align:top}th{background:#f3f5f8}
.badge{display:inline-block;padding:.1rem .5rem;border-radius:.6rem;font-size:.85em;font-weight:600}
.s-confirmed{background:#fde2e1;color:#a4161a}.s-unconfirmed{background:#fff1d6;color:#8a5a00}
.s-not-testable{background:#e9ecf1;color:#4a5363}.sev-high{color:#a4161a}.sev-medium{color:#b35c00}
.sev-low{color:#2b6cb0}.sev-info{color:#4a5363}.finding{border-top:1px solid #d5d9e0;padding-top:1rem;margin-top:1rem}
img{max-width:320px;border:1px solid #d5d9e0;margin:.5rem 0}code{background:#f3f5f8;padding:0 .25rem}
.muted{color:#6b7385;font-size:.9em}
""".strip()


def _cls(status: Status) -> str:
    return "s-" + status.value.lower().replace(" ", "-")


def write_html(run_dir: Path, meta: dict, findings: list[Finding]) -> Path:
    e = html.escape  # quote=True by default: safe inside quoted attributes too.
    css_hash = base64.b64encode(hashlib.sha256(_CSS.encode()).digest()).decode()
    # No scripts at all; styles allowed only by hash.
    csp = (f"default-src 'none'; img-src 'self' file:; style-src 'sha256-{css_hash}'; "
           "base-uri 'none'; form-action 'none'")
    counts = summarize(findings)
    parts = [
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">",
        f'<meta http-equiv="Content-Security-Policy" content="{e(csp)}">',
        '<meta name="referrer" content="no-referrer">',
        f"<title>ProofDroid Report: {e(str(meta.get('package') or ''))}</title>",
        f"<style>{_CSS}</style></head><body>",
        f"<h1>ProofDroid Report: {e(str(meta.get('app_name') or meta.get('package') or ''))}</h1>",
        f'<p class="muted">Generated {e(str(meta.get("generated") or ""))} by ProofDroid {e(__version__)}</p>',
        "<h2>Summary</h2><table><tr><th>Status</th><th>Count</th></tr>",
        *[f"<tr><td>{e(s)}</td><td>{n}</td></tr>" for s, n in counts.items()],
        "</table><h2>Target</h2><table>",
    ]
    for label, key in (("Package", "package"), ("Version", "version"), ("APK", "apk_name"),
                       ("SHA-256", "apk_sha256"), ("Dynamic analysis", "dynamic")):
        parts.append(f"<tr><th>{label}</th><td>{e(str(meta.get(key) or ''))}</td></tr>")
    parts.append("</table><h2>Ranked findings</h2><table><tr><th>#</th><th>Status</th>"
                 "<th>Severity</th><th>Finding</th><th>Component</th></tr>")
    for f in findings:
        parts.append(
            f'<tr><td>{f.rank}</td><td><span class="badge {_cls(f.status)}">{e(f.status.value)}</span></td>'
            f'<td class="sev-{f.severity.label.lower()}">{e(f.severity.label)}</td>'
            f'<td><a href="#finding-{f.rank}">{e(f.title)}</a></td><td><code>{e(f.component or "")}</code></td></tr>'
        )
    parts.append("</table><h2>Details</h2>")
    for f in findings:
        parts.append(f'<div class="finding" id="finding-{f.rank}">')
        parts.append(f'<h3>{f.rank}. <span class="badge {_cls(f.status)}">{e(f.status.value)}</span> {e(f.title)}</h3>')
        parts.append(f'<p><b>Severity:</b> <span class="sev-{f.severity.label.lower()}">{e(f.severity.label)}</span>'
                     f" &middot; <b>Category:</b> {e(f.category)}")
        if f.component:
            parts.append(f" &middot; <b>Component:</b> <code>{e(f.component)}</code>")
        parts.append("</p>")
        parts.append(f"<p><b>Result:</b> {e(f.status_reason)}</p>")
        if f.explanation:
            parts.append(f"<p><b>In plain language:</b> {e(f.explanation)}</p>")
        if f.references:
            parts.append(f"<p><b>References:</b> {e(', '.join(f.references))}</p>")
        if f.description:
            parts.append(f"<p>{e(f.description)}</p>")
        if f.evidence:
            parts.append("<p><b>Evidence:</b></p><ul>")
            parts += [f'<li><a href="{e(_link(p))}">{e(Path(p).name)}</a></li>' for p in f.evidence]
            parts.append("</ul>")
            parts += [f'<img src="{e(_link(p))}" alt="screenshot for finding {f.rank}">'
                      for p in f.evidence if p.endswith(".png")]
        parts.append("</div>")
    parts.append(f'<p class="muted">{e(DISCLAIMER)}</p></body></html>')
    out = run_dir / "report.html"
    out.write_text("\n".join(parts), encoding="utf-8")
    return out


def write_findings_json(run_dir: Path, meta: dict, findings: list[Finding]) -> Path:
    out = run_dir / "findings.json"
    out.write_text(json.dumps({"meta": meta, "findings": [f.to_dict() for f in findings]}, indent=2),
                   encoding="utf-8")
    return out
