"""Smishing (SMS/text-message scam) analysis.

Texts have no headers to authenticate, so the investigation leans on the
other analyst signals: who the sender claims to be vs. where the link really
goes, domain age, urgency language, and sender-number heuristics.
Produces the same Case shape as an email scan.
"""

from __future__ import annotations

import re

from .advice import advice_for
from .models import BAD, INFO, OK, WARN, Case, ChainNode, Finding, case_id_for
from .reputation import reputation_findings
from .scanner import _SEV_ORDER, _url_findings, _verdict
from .urlscan import URL_RE, analyze_url, refang

# Pressure phrasing specific to text scams (email urgency list also applies).
SMS_URGENCY = (
    "final notice", "last reminder", "act now", "expires today", "expire",
    "within 24 hours", "on hold", "unpaid", "toll", "refund", "rebate",
    "e-transfer", "etransfer", "suspended", "locked", "verify your",
    "claim", "tax return", "failed delivery", "redelivery", "customs fee",
    "outstanding balance", "avoid penalties",
)

# Organizations smishers impersonate BY NAME in the message text, mapped to
# the domains they actually send from. A brand mention + a link anywhere
# else is the classic smishing lure.
LURE_BRANDS: dict[str, tuple[str, ...]] = {
    "cra": ("canada.ca",),
    "canada revenue": ("canada.ca",),
    "service canada": ("canada.ca",),
    "canada post": ("canadapost.ca", "canadapost-postescanada.ca"),
    "postes canada": ("canadapost.ca", "canadapost-postescanada.ca"),
    "interac": ("interac.ca",),
    "td": ("td.com",),
    "rbc": ("rbc.com", "royalbank.com"),
    "bmo": ("bmo.com",),
    "cibc": ("cibc.com",),
    "scotiabank": ("scotiabank.com",),
    "national bank": ("nbc.ca",),
    "amazon": ("amazon.com", "amazon.ca"),
    "netflix": ("netflix.com",),
    "apple": ("apple.com", "icloud.com"),
    "usps": ("usps.com",),
    "ups": ("ups.com",),
    "fedex": ("fedex.com",),
    "dhl": ("dhl.com",),
    "purolator": ("purolator.com",),
    "e-zpass": ("e-zpassny.com",),
    "407 etr": ("407etr.com",),
}

_EMAIL_SENDER_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_DIGITS_RE = re.compile(r"\d")


def _sender_findings(sender: str) -> list[Finding]:
    sender = sender.strip()
    if not sender:
        return [Finding(INFO, "Sender not provided",
                        "No sender number was given, so number heuristics skipped.",
                        category="sender")]
    digits = "".join(_DIGITS_RE.findall(sender))
    if _EMAIL_SENDER_RE.match(sender):
        return [Finding(WARN, "Sent through an email-to-SMS gateway",
                        f"The text came from an email address ({sender}), not a "
                        "phone number. Legitimate organizations rarely text this "
                        "way; scammers use gateways to send in bulk.",
                        weight=15, category="sender")]
    if len(digits) in (5, 6):
        return [Finding(INFO, "Shortcode sender",
                        f"{sender} is a registered shortcode. These are harder "
                        "to spoof, but shortcodes can still be leased by scammers.",
                        category="sender")]
    if len(digits) >= 10:
        return [Finding(WARN, "Full phone number, not a shortcode",
                        f"The text came from a regular number ({sender}). Banks, "
                        "carriers, and government agencies almost always use "
                        "registered shortcodes, so a 10-digit sender is a smishing "
                        "hallmark.", weight=10, category="sender")]
    return [Finding(INFO, "Unrecognized sender format", sender, category="sender")]


def _lure_findings(text: str, urls) -> list[Finding]:
    findings: list[Finding] = []
    lowered = text.lower()
    link_domains = {u.domain for u in urls if u.domain}

    # Brand named in the text, but no link goes to that brand's real domain.
    for brand, legit in LURE_BRANDS.items():
        if not re.search(rf"\b{re.escape(brand)}\b", lowered):
            continue
        display = brand.upper() if len(brand) <= 4 else brand.title()
        if link_domains and not any(
                d == real or d.endswith("." + real)
                for d in link_domains for real in legit):
            findings.append(Finding(
                BAD, f'Brand lure: "{display}"',
                f"The message invokes {display} but links to "
                f"{', '.join(sorted(link_domains))} instead of {legit[0]}. "
                "Impersonating a trusted brand while linking elsewhere is the "
                "defining smishing pattern.", weight=30, category="domain"))
        break

    hits = [p for p in SMS_URGENCY if p in lowered]
    if hits:
        findings.append(Finding(
            WARN, "Urgency and pressure language",
            "Classic pressure phrasing: " + ", ".join(f'"{h}"' for h in hits[:3])
            + ("…" if len(hits) > 3 else "."),
            weight=min(5 * len(hits), 15), category="content"))

    if not urls and any(w in lowered for w in ("call", "reply", "text back")):
        findings.append(Finding(
            INFO, "Callback lure",
            "No link, but the message asks you to call or reply. Verify any "
            "number independently before responding.", category="content"))
    return findings


def _build_chain(sender: str, urls, findings) -> list[ChainNode]:
    def by_cat(cat: str, sev: str) -> bool:
        return any(f.category == cat and f.severity == sev for f in findings)

    sender_sev = WARN if by_cat("sender", WARN) else INFO
    sender_sub = "gateway/number" if sender_sev == WARN else (sender[:16] or "unknown")
    chain = [ChainNode("Sender", sender_sub, sender_sev)]

    lure_sev = BAD if by_cat("domain", BAD) else \
        WARN if by_cat("content", WARN) else OK
    chain.append(ChainNode("Lure", "brand impersonation" if lure_sev == BAD
                           else "pressure tactics" if lure_sev == WARN
                           else "plain text", lure_sev))

    if urls:
        worst = min(urls, key=lambda u: 0 if u.flags else 1)
        link_sev = WARN if worst.flags else OK
        if by_cat("url", BAD) or by_cat("reputation", BAD) or lure_sev == BAD:
            link_sev = BAD
        chain.append(ChainNode("Link", worst.domain[:22] or "?", link_sev))
        # We never visit links, so the landing page is inferred, not observed.
        chain.append(ChainNode("Landing Page",
                               "suspected phish" if link_sev == BAD else "not visited",
                               link_sev if link_sev == BAD else INFO))
    else:
        chain.append(ChainNode("Payload", "no link", OK))
    return chain


def scan_sms(text: str, sender: str = "", offline: bool = False,
             enrich=None) -> Case:
    """Investigate a text message. `enrich(sender, urls) -> list[Finding]`
    lets the caller add instance history the engine can't know."""
    text = refang(text.strip())
    urls = [analyze_url(m.rstrip(".,;")) for m in dict.fromkeys(URL_RE.findall(text))]

    findings = _sender_findings(sender)
    findings += _lure_findings(text, urls)
    findings += _url_findings(urls)
    findings += reputation_findings("", urls, offline=offline)
    if enrich:
        findings += enrich(sender, urls)
    findings.sort(key=lambda f: _SEV_ORDER.get(f.severity, 9))

    score = min(sum(f.weight for f in findings), 100)
    verdict, confidence = _verdict(score)
    preview = text[:600]

    # Substrings the UI should visually mark: pressure phrases, invoked
    # brand names, and every link that raised a flag.
    lowered = text.lower()
    highlights = [p for p in SMS_URGENCY if p in lowered]
    highlights += [b for b in LURE_BRANDS
                   if re.search(rf"\b{re.escape(b)}\b", lowered)]
    # A brand lure makes the link itself the payload, so mark every link then.
    lure_fired = any(f.category == "domain" and f.severity == BAD
                     for f in findings)
    highlights += [u.url for u in urls if u.flags or lure_fired]

    return Case(
        case_id=case_id_for(f"{sender}\n{text}".encode()),
        verdict=verdict,
        confidence=confidence,
        score=score,
        headers={
            "from": sender or "unknown sender",
            "from_addr": sender.strip().lower(),
            "reply_to": "",
            "return_path": "",
            "subject": (text[:80] + "…") if len(text) > 80 else text,
            "date": "",
        },
        auth={"spf": "n/a", "dkim": "n/a", "dmarc": "n/a",
              "spf_detail": "", "dkim_detail": "", "dmarc_detail": "",
              "sender_ip": ""},
        urls=urls,
        findings=findings,
        chain=_build_chain(sender, urls, findings),
        body_preview=preview,
        attachments=[],
        kind="sms",
        highlights=highlights,
        recommendations=advice_for("sms", verdict, findings),
    )
