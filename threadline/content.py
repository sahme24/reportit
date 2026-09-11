"""Language-aware content signals: the pre-LLM detection layer.

Scores message text on urgency language, requests for credentials/identity,
authority impersonation phrasing, and formatting anomalies typical of
translated scam templates, in English, French, Spanish, Portuguese, Italian,
German, Arabic, Russian, Hindi and Chinese. Messages in any other language
are reported as not covered instead of being checked against English.

This module is the swap point for a future trained classifier: callers
depend only on detect_language() and content_findings(), which return plain
Findings plus the matched substrings. Replace the internals with a model and
nothing upstream changes.

Pattern lists live in threadline/patterns/<code>.json, one file per
language, so new rules are config edits. A new language also needs its
code in LANGUAGES and a way to recognise it in detect_language().
"""

from __future__ import annotations

import json
import re
from functools import cache
from pathlib import Path

from .models import INFO, WARN, Finding

_PATTERN_DIR = Path(__file__).parent / "patterns"

LANGUAGES = ("en", "fr", "es", "pt", "it", "de", "ar", "ru", "hi", "zh")
_LANG_NAMES = {
    "en": "English", "fr": "French", "es": "Spanish", "pt": "Portuguese",
    "it": "Italian", "de": "German", "ar": "Arabic", "ru": "Russian",
    "hi": "Hindi", "zh": "Chinese",
}

# Returned by detect_language() when a message is clearly written in a
# language with no pattern pack. It is never a key in _LANG_NAMES and has no
# file in patterns/, so content_findings() handles it before either lookup.
UNKNOWN = "unknown"

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


# Links and email addresses are long runs of Latin letters. Left in, a single
# URL outweighs the words of a short Arabic or Russian SMS and the message is
# no longer recognised as that language.
_URL_OR_EMAIL_RE = re.compile(r"(?:https?://|www\.)\S+|\S+@\S+", re.IGNORECASE)

# Punctuation becomes spaces before marker words are looked for, so "cuenta,"
# and "cuenta." still count as the word "cuenta".
_WORD_SPLIT_RE = re.compile(r"[^\w]+")

# Latin-script languages can't be told apart by their script, so each one is
# scored by how many of its marker words appear. Every marker was picked to be
# absent from the other supported languages: "para", "esta" and "pedido" are
# shared by Spanish and Portuguese, and "pagamento" by Portuguese and Italian,
# so none of them are here. English markers also avoid words that are common in
# languages with no pack ("is", "of" and "we" are Dutch; "to" is Polish), because
# those messages should come back as unknown, not be mistaken for English.
_LATIN_MARKERS = {
    "fr": _FRENCH_TOKENS,
    "es": (" usted ", " cuenta ", " contraseña ", " contrasena ", " haga ",
           " ahora ", " nuestro ", " nuestra ", " tarjeta ", " envío ",
           " envio ", " paquete ", " gracias ", " hemos ", " señor ",
           " inmediatamente ", " verifique ", " ingrese "),
    "pt": (" você ", " voce ", " sua ", " seu ", " conta ", " senha ",
           " não ", " nao ", " foi ", " clique ", " agora ", " cartão ",
           " cartao ", " encomenda ", " obrigado ", " imediatamente ",
           " pontos "),
    "it": (" il tuo ", " tuo ", " tua ", " conto ", " clicca ", " della ",
           " grazie ", " subito ", " stato ", " sono ", " questo ", " questa ",
           " nostro ", " nostra ", " gentile ", " immediatamente "),
    "de": (" sie ", " ihr ", " ihre ", " ihren ", " bitte ", " wurde ",
           " wurden ", " klicken ", " und ", " nicht ", " werden ", " sofort ",
           " zahlung ", " sendung ", " bestätigen ", " haben ", " ist "),
    "en": (" the ", " your ", " you ", " please ", " with ", " have ",
           " will ", " this ", " that ", " are ", " and ", " our ", " not ",
           " been ", " from ", " could ", " would ", " here "),
}

# Ties go to the language listed first. English comes last: its markers are
# everyday function words that turn up in footers and brand names inside mail
# that is otherwise written in another language.
_LATIN_ORDER = ("fr", "es", "pt", "it", "de", "en")

# Fewer Latin letters than this is too little text to name a language. Such a
# message defaults to English rather than being called unknown, which would
# attach a "language not covered" note to every one-line reply.
_SHORT_TEXT_LETTERS = 60


def _script_of(ch: str) -> str:
    """The writing system a single letter belongs to, judged by code point."""
    code = ord(ch)
    if 0x41 <= code <= 0x5A or 0x61 <= code <= 0x7A:
        return "latin"
    if 0xC0 <= code <= 0x24F or 0x1E00 <= code <= 0x1EFF:
        return "latin"
    if 0x0600 <= code <= 0x06FF:
        return "arabic"
    if 0x0400 <= code <= 0x04FF:
        return "cyrillic"
    if 0x0900 <= code <= 0x097F:
        return "devanagari"
    if 0x4E00 <= code <= 0x9FFF:
        return "han"
    if 0x3040 <= code <= 0x30FF:
        return "kana"
    return "other"


def detect_language(text: str) -> str:
    """Best-effort language detection, tuned for short scam messages.

    Returns a code from LANGUAGES, or UNKNOWN when the message is clearly in a
    language CatPhish has no patterns for.
    """
    if type(text) is not str:
        raise ValueError(
            "detect_language expects text as a str, got " + type(text).__name__)

    body = _URL_OR_EMAIL_RE.sub(" ", text)

    counts = {"latin": 0, "arabic": 0, "cyrillic": 0, "devanagari": 0,
              "han": 0, "kana": 0, "other": 0}
    for ch in body:
        if ch.isalpha():
            counts[_script_of(ch)] += 1
    total = 0
    for script in counts:
        total += counts[script]
    if total == 0:
        return "en"

    # Scripts with no pack: Japanese kana, Korean, Greek, Hebrew, Thai and so
    # on. Checked before Chinese, because Japanese is written with Chinese
    # characters as well as kana and would otherwise be read as Chinese.
    if (counts["kana"] + counts["other"]) / total > 0.25:
        return UNKNOWN

    # A quarter of the letters is enough to name a non-Latin script, which is
    # the threshold the original Arabic check used for short messages.
    script_languages = (("arabic", "ar"), ("cyrillic", "ru"),
                        ("devanagari", "hi"), ("han", "zh"))
    best_script_language = None
    best_script_count = 0
    for script, code in script_languages:
        if counts[script] / total > 0.25 and counts[script] > best_script_count:
            best_script_language = code
            best_script_count = counts[script]
    if best_script_language is not None:
        return best_script_language

    padded = " " + _WORD_SPLIT_RE.sub(" ", body.casefold()) + " "
    best = "en"
    best_score = 0
    languages_with_a_hit = 0
    for code in _LATIN_ORDER:
        score = 0
        for marker in _LATIN_MARKERS[code]:
            if marker in padded:
                score += 1
        if score > 0:
            languages_with_a_hit += 1
        if score > best_score:
            best = code
            best_score = score

    if best_score >= 2:
        return best
    if counts["latin"] < _SHORT_TEXT_LETTERS:
        # One marker word is weak evidence, so it only counts in a short
        # message and only when no other language matched anything.
        if best_score == 1 and languages_with_a_hit == 1:
            return best
        return "en"
    return UNKNOWN


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
    if type(text) is not str:
        raise ValueError(
            "content_findings expects text as a str, got " + type(text).__name__)
    if kind != "email" and kind != "sms":
        raise ValueError("kind must be 'email' or 'sms', got " + repr(kind))
    if lang is None or lang == "":
        lang = detect_language(text)
    elif lang != UNKNOWN and lang not in LANGUAGES:
        raise ValueError("unsupported language code " + repr(lang)
                         + "; expected one of " + ", ".join(LANGUAGES)
                         + " or " + repr(UNKNOWN))

    if lang == UNKNOWN:
        # No pack to match against. Saying so beats checking the text against
        # English phrases it can never contain, which made an urgent message
        # in an unsupported language look calm.
        findings = [Finding(
            INFO, "Language not covered",
            "This message isn't in a language CatPhish has scam-phrase "
            "patterns for, so urgency and credential-request wording wasn't "
            "checked. Checks that don't read the words (sender, links, "
            "reputation) still ran.", category="content")]
        findings += _anomaly_findings(text, lang)
        return lang, findings, []

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
