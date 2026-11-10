"""Rank findings so the report leads with what matters most.

Ordering: Confirmed > Unconfirmed > Not testable, then severity (High first),
then category and title for a stable order.
"""

from __future__ import annotations

import json
import logging
import os
import urllib.parse
import urllib.request
from collections import Counter
from typing import Any, Callable

from .models import Finding, Status

log = logging.getLogger(__name__)

STATUS_ORDER = {Status.CONFIRMED: 0, Status.UNCONFIRMED: 1, Status.NOT_TESTABLE: 2}


def rank_findings(findings: list[Finding]) -> list[Finding]:
    ranked = sorted(findings, key=lambda f: (STATUS_ORDER[f.status], -int(f.severity), f.category, f.title))
    for i, finding in enumerate(ranked, start=1):
        finding.rank = i
    return ranked


def summarize(findings: list[Finding]) -> dict[str, int]:
    counts = Counter(f.status.value for f in findings)
    return {s.value: counts.get(s.value, 0) for s in Status}


LLM_PROMPT = (
    "You are a mobile security consultant. For each Android app finding below, write one or two plain-language "
    "sentences for a non-technical client: what it means and why it matters. Be accurate about the status: "
    "only 'Confirmed' findings were proven. Reply ONLY with a JSON array of objects {\"rank\": int, "
    "\"explanation\": str}."
)


def llm_triage(findings: list[Finding], opener: Callable[..., Any] | None = None) -> bool:
    """Add plain-language explanations using an OpenAI-compatible chat completions API.

    Configured by env vars PROOFDROID_LLM_URL (full .../chat/completions URL), PROOFDROID_LLM_KEY and
    PROOFDROID_LLM_MODEL. Only titles, severity, status and result text are sent: never evidence,
    descriptions or secret values. Failures are logged and ignored so the report is still produced.
    """
    url = os.environ.get("PROOFDROID_LLM_URL", "")
    key = os.environ.get("PROOFDROID_LLM_KEY", "")
    model = os.environ.get("PROOFDROID_LLM_MODEL", "")
    parsed = urllib.parse.urlparse(url)
    if not (url and key and model):
        log.warning("LLM triage skipped: set PROOFDROID_LLM_URL, PROOFDROID_LLM_KEY and PROOFDROID_LLM_MODEL.")
        return False
    if parsed.scheme != "https" and parsed.hostname not in ("127.0.0.1", "localhost", "::1"):
        log.warning("LLM triage skipped: PROOFDROID_LLM_URL must use https (or be a local server).")
        return False
    items = [{"rank": f.rank, "title": f.title, "severity": f.severity.label, "status": f.status.value,
              "result": f.status_reason} for f in findings[:60]]
    body = json.dumps({"model": model, "temperature": 0.2, "messages": [
        {"role": "system", "content": LLM_PROMPT},
        {"role": "user", "content": json.dumps(items)},
    ]}).encode()
    req = urllib.request.Request(url, data=body, method="POST", headers={
        "Authorization": f"Bearer {key}", "Content-Type": "application/json"})
    try:
        with (opener or urllib.request.urlopen)(req, timeout=120) as resp:
            content = json.loads(resp.read().decode("utf-8", "replace"))["choices"][0]["message"]["content"]
        content = content.strip().removeprefix("```json").removeprefix("```").removesuffix("```")
        answers = json.loads(content)
    except Exception as exc:  # noqa: BLE001 - triage is best-effort by design.
        log.warning("LLM triage failed (%s); continuing without explanations.", type(exc).__name__)
        return False
    by_rank = {f.rank: f for f in findings}
    for a in answers if isinstance(answers, list) else []:
        if isinstance(a, dict) and isinstance(a.get("explanation"), str) and a.get("rank") in by_rank:
            by_rank[a["rank"]].explanation = a["explanation"][:600]
    return True
