"""AI analyst — turns a finished case into a plain-English explanation.

Uses the Claude API. Activates only when ANTHROPIC_API_KEY is configured
(.env or environment); everything else in the scanner works without it.
"""

from __future__ import annotations

import os

import anthropic

# Claude Opus 4.8 by default; override with REPORTIT_AI_MODEL if you want a
# cheaper model on a busy public instance.
_MODEL = os.environ.get("REPORTIT_AI_MODEL", "claude-opus-4-8")

_SYSTEM = """You are the AI analyst inside ReportIT.ai, an open-source phishing
and smishing investigation tool for everyday people. You receive the results
of an automated scan and explain them to someone with no security background.

Rules:
- Plain English, no jargon without a one-phrase explanation.
- Be direct about the verdict and WHY, referencing the strongest 2-3 findings.
- Never include clickable URLs; keep all indicators defanged exactly as given.
- Finish with a short "What you should do" list of 2-4 concrete steps
  (e.g. delete it, report to reportphishing@apwg.org / 7726 for texts,
  change a password ONLY via the official site typed by hand).
- If the verdict is LIKELY CLEAN, say so plainly and mention the checks it
  passed — do not invent danger. If forwarding broke authentication, explain
  that in one sentence.
- 120-200 words. No markdown headers; short paragraphs and one dash list."""


def is_configured() -> bool:
    return bool(os.environ.get("ANTHROPIC_API_KEY"))


def _case_brief(case: dict) -> str:
    """Compact, model-friendly text version of a case dict."""
    lines = [
        f"Channel: {'text message (SMS)' if case.get('kind') == 'sms' else 'email'}",
        f"Verdict: {case['verdict']} ({case['confidence']} confidence, "
        f"risk score {case['score']}/100)",
        f"From: {case['headers'].get('from', '')}",
        f"Subject/preview: {case['headers'].get('subject', '')}",
    ]
    if case.get("kind") != "sms":
        auth = case["auth"]
        lines.append(f"Authentication: SPF={auth['spf']} DKIM={auth['dkim']} "
                     f"DMARC={auth['dmarc']}")
    lines.append("Findings:")
    for f in case["findings"]:
        lines.append(f"- [{f['severity']}] {f['title']}: {f['detail']}")
    if case["urls"]:
        lines.append("Links (defanged):")
        for u in case["urls"][:8]:
            lines.append(f"- {u['defanged']}")
    lines.append("Attack chain: " + " -> ".join(
        f"{n['label']} ({n['sub']})" for n in case["chain"]))
    return "\n".join(lines)


def explain_case(case: dict) -> str:
    """Return a plain-English analyst explanation. Raises on API errors —
    the web layer maps those to friendly HTTP responses."""
    client = anthropic.Anthropic()
    response = client.messages.create(
        model=_MODEL,
        max_tokens=1024,
        thinking={"type": "adaptive"},
        output_config={"effort": "low"},
        system=_SYSTEM,
        messages=[{
            "role": "user",
            "content": "Explain this scan result to the person who received "
                       "the message:\n\n" + _case_brief(case),
        }],
    )
    if response.stop_reason == "refusal":
        return ("The AI analyst declined to summarize this case. The scan "
                "findings above still stand on their own.")
    return next((b.text for b in response.content if b.type == "text"), "").strip()
