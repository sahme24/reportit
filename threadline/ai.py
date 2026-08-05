"""AI analyst: turns a finished case into a plain-English explanation.

Uses the Claude API. Activates only when ANTHROPIC_API_KEY is configured
(.env or environment); everything else in the scanner works without it.
"""

from __future__ import annotations

import json
import os

import anthropic

# Claude Haiku 4.5 by default, fast and cheap enough for a free public
# instance. Override with REPORTIT_AI_MODEL to use a bigger model.
_MODEL = os.environ.get("REPORTIT_AI_MODEL", "claude-haiku-4-5")

_SYSTEM = """You are the AI analyst inside CatPhish, an open-source phishing
and smishing investigation tool for everyday people. Every scan is a single
pass: automated heuristics gather the evidence, and your verdict is what the
person actually sees. There is no separate "heuristic verdict" shown next to
yours, so weigh the evidence yourself rather than defaulting to whatever the
raw score implies.

Rules:
- Judge the evidence on its merits. A high score driven by auth failures that
  are explained by forwarding, or a low score that misses a lure the
  heuristics didn't catch, both mean the raw score is wrong. Call it as you
  actually see it.
- Plain English, no jargon without a one-phrase explanation.
- Reference the strongest 2-3 pieces of evidence in the summary.
- Never include clickable URLs; keep all indicators defanged exactly as given.
- Actions: 2-4 concrete, case-specific steps (not generic filler). These
  supplement the standard verdict-based advice already shown, so focus on
  what's specific to this message, e.g. how to verify a claimed shipment or
  account independently.
- If the message is LIKELY CLEAN, say so plainly. Do not invent danger.
- Write like a person typing quickly, not a press release. Use commas,
  periods, and colons for pacing. Never use an em dash (—) anywhere in your
  response.
- Summary: 80-160 words, short paragraphs, no markdown headers."""

# The verdict/confidence here become THE case's verdict/confidence (the
# caller overwrites the heuristic ones), not a second opinion shown
# alongside them, so there's only ever one result on screen.
_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string",
                    "enum": ["MALICIOUS", "SUSPICIOUS", "LIKELY CLEAN"],
                    "description": "Your verdict on the message, weighing all evidence."},
        "confidence": {"type": "string", "enum": ["HIGH", "MEDIUM", "LOW"]},
        "summary": {"type": "string",
                    "description": "Plain-English explanation for the recipient."},
        "actions": {"type": "array", "items": {"type": "string"},
                    "description": "2-4 concrete next steps specific to this case."},
    },
    "required": ["verdict", "confidence", "summary", "actions"],
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
    """Return the AI analyst's read of the case: {verdict, confidence,
    summary, actions}. The caller uses verdict/confidence as THE case's
    final verdict, not a second one shown alongside the heuristic score.
    Raises on API errors; the web layer maps those to friendly responses."""
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
            "content": "Analyze this scan and explain it to the person who "
                       "received the message:\n\n" + _case_brief(case),
        }],
    )
    if response.stop_reason == "refusal":
        return {
            "verdict": case["verdict"], "confidence": "LOW",
            "summary": ("The AI analyst declined to review this case. The "
                        "scan findings above still stand on their own."),
            "actions": [],
        }
    text = next((b.text for b in response.content if b.type == "text"), "{}")
    return json.loads(text)
