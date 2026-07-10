"""AI analyst — turns a finished case into a plain-English explanation.

Uses the Claude API. Activates only when ANTHROPIC_API_KEY is configured
(.env or environment); everything else in the scanner works without it.
"""

from __future__ import annotations

import json
import os

import anthropic

# Claude Haiku 4.5 by default — fast and cheap enough for a free public
# instance. Override with REPORTIT_AI_MODEL to use a bigger model.
_MODEL = os.environ.get("REPORTIT_AI_MODEL", "claude-haiku-4-5")

_SYSTEM = """You are the AI analyst inside ReportIT.ai, an open-source phishing
and smishing investigation tool for everyday people. You receive the results
of an automated heuristic scan and act as an INDEPENDENT second opinion in an
ensemble: judge the evidence yourself, then explain it to someone with no
security background.

Rules:
- Form your own verdict from the evidence. Agree with the scanner only if the
  evidence supports it; if the scanner over- or under-reacted (e.g. auth
  failures caused by forwarding, or a lure the heuristics missed), say so.
- Plain English, no jargon without a one-phrase explanation.
- Reference the strongest 2-3 pieces of evidence in the summary.
- Never include clickable URLs; keep all indicators defanged exactly as given.
- Actions: 2-4 concrete steps for this specific case (delete it, report to
  reportphishing@apwg.org / forward texts to 7726, change a password ONLY via
  the official site typed by hand). No generic filler.
- If the message is LIKELY CLEAN, say so plainly — do not invent danger.
- Summary: 80-160 words, short paragraphs, no markdown headers."""

# Structured second opinion — the ensemble output the UI renders.
_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string",
                    "enum": ["MALICIOUS", "SUSPICIOUS", "LIKELY CLEAN"],
                    "description": "Your independent verdict on the message."},
        "confidence": {"type": "string", "enum": ["HIGH", "MEDIUM", "LOW"]},
        "agrees_with_scanner": {
            "type": "boolean",
            "description": "Whether your verdict matches the heuristic scanner's."},
        "summary": {"type": "string",
                    "description": "Plain-English explanation for the recipient."},
        "actions": {"type": "array", "items": {"type": "string"},
                    "description": "2-4 concrete next steps for this case."},
    },
    "required": ["verdict", "confidence", "agrees_with_scanner",
                 "summary", "actions"],
    "additionalProperties": False,
}


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


def analyze_case(case: dict) -> dict:
    """Return the AI analyst's structured second opinion:
    {verdict, confidence, agrees_with_scanner, summary, actions}.
    Raises on API errors — the web layer maps those to friendly responses."""
    client = anthropic.Anthropic()
    # No thinking/effort params: Haiku 4.5 doesn't support them, and omitting
    # them keeps the call valid if REPORTIT_AI_MODEL is overridden upward.
    response = client.messages.create(
        model=_MODEL,
        max_tokens=2048,
        output_config={
            "format": {"type": "json_schema", "schema": _SCHEMA},
        },
        system=_SYSTEM,
        messages=[{
            "role": "user",
            "content": "Give your independent second opinion on this scan, "
                       "then explain it to the person who received the "
                       "message:\n\n" + _case_brief(case),
        }],
    )
    if response.stop_reason == "refusal":
        return {
            "verdict": case["verdict"], "confidence": "LOW",
            "agrees_with_scanner": True,
            "summary": ("The AI analyst declined to review this case. The "
                        "scan findings above still stand on their own."),
            "actions": [],
        }
    text = next((b.text for b in response.content if b.type == "text"), "{}")
    return json.loads(text)
