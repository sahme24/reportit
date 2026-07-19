"""Language-aware content signals: the pre-LLM detection layer.

Scores message text on urgency language, requests for credentials/identity,
authority impersonation phrasing, and formatting anomalies typical of
translated scam templates, in English, French, and Arabic.

This module is the swap point for a future trained classifier: callers
depend only on detect_language() and content_findings(), which return plain
Findings plus the matched substrings. Replace the internals with a model and
nothing upstream changes.

Pattern lists live in threadline/patterns/{en,fr,ar}.json, one file per
language, so new rules and languages are config edits, not code changes.
"""

from __future__ import annotations

import json
import re
from functools import cache
from pathlib import Path

from .models import INFO, WARN, Finding

_PATTERN_DIR = Path(__file__).parent / "patterns"

LANGUAGES = ("en", "fr", "ar")
_LANG_NAMES = {"en": "English", "fr": "French", "ar": "Arabic"}

_ARABIC_RE = re.compile(r"[؀-ۿ]")
_LATIN_RE = re.compile(r"[a-zA-Z]")

# Distinctive French tokens (accents casefolded away by callers, so both
# accented and bare forms appear). Two hits = French.
_FRENCH_TOKENS = (
    " votre ", " vous ", " cliquez ", " compte ", " colis ", " livraison ",
    " paiement ", " facture ", " sécurité ", " securite ", " bancaire ",
    " remboursement ", " impôt ", " impot ", " veuillez ", " dès ",
    " immédiatement ", " immediatement ", " expédition ", " expedition ",
)

_EXCLAIM_RE = re.compile(r"!{2,}")
_CAPS_WORD_RE = re.compile(r"\b[A-Z]{4,}\b")
_SPACE_PUNCT_RE = re.compile(r"\w [!?;:]")


@cache
def _patterns(lang: str) -> dict:
    path = _PATTERN_DIR / f"{lang}.json"
    if not path.is_file():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    data.pop("_comment", None)
    return data


def detect_language(text: str) -> str:
    """Best-effort en/fr/ar detection, tuned for short scam messages."""
    letters = len(_LATIN_RE.findall(text)) + len(_ARABIC_RE.findall(text))
    if letters and len(_ARABIC_RE.findall(text)) / letters > 0.25:
        return "ar"
    padded = f" {text.casefold()} "
    if sum(1 for tok in _FRENCH_TOKENS if tok in padded) >= 2:
        return "fr"
    return "en"


def _matches(text: str, phrases: list[str]) -> list[str]:
    return [p for p in phrases if p in text]


def _anomaly_findings(text: str, lang: str) -> list[Finding]:
    """Formatting tells of mass-produced / machine-translated templates.
    Deliberately low-weight: each is weak alone, real signal is the combo."""
    findings = []
    if _EXCLAIM_RE.search(text):
        findings.append(Finding(
            WARN, "Excessive punctuation",
            "Repeated exclamation marks are a hallmark of scam templates, "
            "not professional correspondence.", weight=4, category="content"))
    caps = _CAPS_WORD_RE.findall(text)
    if len(caps) >= 4:
        findings.append(Finding(
            WARN, "Shouting case",
            f"{len(caps)} fully capitalized words "
            f"({', '.join(caps[:4])}…). Legitimate notices rarely shout.",
            weight=4, category="content"))
    # French legitimately puts a space before !?;: so only flag elsewhere.
    if lang != "fr" and len(_SPACE_PUNCT_RE.findall(text)) >= 2:
        findings.append(Finding(
            INFO, "Odd spacing before punctuation",
            "Spaces before punctuation marks often survive machine "
            "translation of scam templates written in another language.",
            category="content"))
    # Latin text mixed into a mostly-Arabic message (or vice versa) is
    # common in templated scams reused across markets.
    arabic, latin = len(_ARABIC_RE.findall(text)), len(_LATIN_RE.findall(text))
    if arabic and latin and min(arabic, latin) / max(arabic, latin) > 0.15:
        findings.append(Finding(
            INFO, "Mixed-script message",
            "The message mixes Arabic and Latin script, which is common in "
            "scam templates recycled across languages. Not conclusive alone.",
            category="content"))
    return findings


def content_findings(text: str, lang: str | None = None,
                     kind: str = "email") -> tuple[str, list[Finding], list[str]]:
    """Score message content. Returns (language, findings, matched_phrases).

    matched_phrases are the exact substrings that triggered, for UI
    highlighting. This signature is the stable integration point: a trained
    classifier can replace everything below it.
    """
    lang = lang or detect_language(text)
    pats = _patterns(lang)
    folded = text.casefold()
    findings: list[Finding] = []
    matched: list[str] = []
    lang_note = "" if lang == "en" else f" ({_LANG_NAMES[lang]} patterns)"

    urgency = list(pats.get("urgency", []))
    if kind == "sms":
        urgency += [p for p in pats.get("urgency_sms_extra", [])
                    if p not in urgency]
    hits = _matches(folded, urgency)
    if hits:
        matched += hits
        findings.append(Finding(
            WARN, "Urgency and pressure language",
            "Classic pressure phrasing" + lang_note + ": "
            + ", ".join(f'"{h}"' for h in hits[:3])
            + ("…" if len(hits) > 3 else "."),
            weight=min(5 * len(hits), 15), category="content"))

    hits = _matches(folded, pats.get("info_request", []))
    if hits:
        matched += hits
        findings.append(Finding(
            WARN, "Asks for sensitive information",
            "Requests credentials, identity, or payment details" + lang_note
            + ": " + ", ".join(f'"{h}"' for h in hits[:3])
            + ("…" if len(hits) > 3 else ".")
            + " Legitimate organizations don't ask for these by message.",
            weight=min(8 * len(hits), 16), category="content"))

    hits = _matches(folded, pats.get("authority", []))
    if hits:
        matched += hits
        findings.append(Finding(
            WARN, "Claims institutional authority",
            "Invokes an institution to borrow its credibility" + lang_note
            + ": " + ", ".join(f'"{h}"' for h in hits[:3])
            + ("…" if len(hits) > 3 else ".")
            + " Verify through the organization's official channels, never "
            "through this message.",
            weight=min(6 * len(hits), 12), category="content"))

    findings += _anomaly_findings(text, lang)
    return lang, findings, matched
