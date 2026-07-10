"""Header-level findings: SPF/DKIM/DMARC, spoofing signals, reply-to games."""

from __future__ import annotations

from .models import BAD, INFO, OK, WARN, Finding
from .parser import ParsedEmail
from .urlscan import BRANDS, _deglyph, _registered_domain, match_brand

FREEMAIL = {
    "gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "aol.com",
    "proton.me", "protonmail.com", "icloud.com", "mail.com", "gmx.com",
}

URGENCY_PHRASES = (
    "expires today", "expire in 24", "within 24 hours", "account will be closed",
    "account has been suspended", "verify your account", "immediate action",
    "action required", "final notice", "unusual sign-in", "unusual activity",
    "confirm your identity", "keep your account active", "payment failed",
)


def _fail(result: str) -> bool:
    return result in ("fail", "softfail", "permerror")


def auth_findings(email: ParsedEmail) -> list[Finding]:
    findings: list[Finding] = []

    # --- SPF / DKIM / DMARC -------------------------------------------------
    failed = [m.upper() for m, r in
              (("spf", email.spf), ("dkim", email.dkim), ("dmarc", email.dmarc))
              if _fail(r)]
    passed = [m.upper() for m, r in
              (("spf", email.spf), ("dkim", email.dkim), ("dmarc", email.dmarc))
              if r == "pass"]

    forwarded = email.forwarded or email.auth_earlier_pass
    if failed and forwarded:
        why = ("an earlier hop recorded SPF and DKIM passing for the same domain"
               if email.auth_earlier_pass else
               "the message carries Resent-/Forwarded headers")
        findings.append(Finding(INFO, "Authentication failed after forwarding",
                                f"{' and '.join(failed)} fail at the final hop, but "
                                f"{why}. This pattern matches a forwarded email, "
                                "not sender spoofing. Judge the links and content "
                                "on their own merits.", weight=5, category="auth"))
    elif len(failed) == 3:
        detail = "SPF, DKIM, and DMARC all fail."
        if email.sender_ip:
            detail += f" Sending IP {email.sender_ip} is not authorized for this domain."
        findings.append(Finding(BAD, "Sender authentication failed", detail,
                                weight=35, category="auth"))
    elif failed:
        findings.append(Finding(WARN, "Partial authentication failure",
                                f"{' and '.join(failed)} failed"
                                + (f"; {', '.join(passed)} passed." if passed else "."),
                                weight=15, category="auth"))
    elif len(passed) == 3:
        findings.append(Finding(OK, "Sender authentication passed",
                                "SPF, DKIM, and DMARC all pass.", category="auth"))
    else:
        findings.append(Finding(INFO, "Authentication results incomplete",
                                "One or more of SPF/DKIM/DMARC was not evaluated "
                                "in the headers provided.", category="auth"))

    from_domain = email.from_addr.split("@")[-1] if "@" in email.from_addr else ""
    reply_domain = email.reply_to.split("@")[-1] if "@" in email.reply_to else ""

    # --- Reply-To / Return-Path mismatch -----------------------------------
    if reply_domain and from_domain and reply_domain != from_domain:
        findings.append(Finding(WARN, "Reply-To mismatch",
                                f"From is @{from_domain} but replies are routed to "
                                f"@{reply_domain}.", weight=15, category="auth"))
    return_domain = email.return_path.split("@")[-1] if "@" in email.return_path else ""
    if return_domain and from_domain and return_domain != from_domain \
            and return_domain != reply_domain:
        findings.append(Finding(WARN, "Return-Path mismatch",
                                f"Bounce path @{return_domain} does not match the "
                                f"From domain @{from_domain}.", weight=10, category="auth"))

    # --- Display name / sender domain impersonation ------------------------
    if from_domain:
        hit = match_brand(_registered_domain(from_domain))
        if hit:
            brand, legit, substituted = hit
            detail = (f'{email.from_addr}: the sender domain imitates '
                      f'"{brand}" but is not {legit}.')
            if substituted:
                detail += ' Uses character substitution (e.g. zero for "o").'
            findings.append(Finding(BAD, "Domain impersonation", detail,
                                    weight=30, category="domain"))
        else:
            # Display name claims a brand the sender domain doesn't own.
            display = _deglyph(email.from_display.lower()).replace(" ", "").replace("-", "")
            for brand, legit in BRANDS.items():
                if any(from_domain == d or from_domain.endswith("." + d) for d in legit):
                    continue
                if brand in display:
                    findings.append(Finding(
                        BAD, "Display name impersonation",
                        f'Display name "{email.from_display}" claims "{brand}" '
                        f"but the message was sent from @{from_domain}, "
                        f"not {legit[0]}.", weight=25, category="domain"))
                    break

        if from_domain in FREEMAIL and any(
                w in display for w in ("support", "helpdesk", "billing", "security",
                                       "it ", "admin", "service")):
            findings.append(Finding(WARN, "Corporate identity on freemail",
                                    f'Display name "{email.from_display}" claims an '
                                    f"official role but sends from @{from_domain}.",
                                    weight=15, category="domain"))

    # --- Urgency / pressure language ----------------------------------------
    text = f"{email.subject}\n{email.body_text}".lower()
    hits = [p for p in URGENCY_PHRASES if p in text]
    if hits:
        findings.append(Finding(WARN, "Urgency and pressure language",
                                'Uses classic pressure phrasing: '
                                + ", ".join(f'"{h}"' for h in hits[:3])
                                + ("…" if len(hits) > 3 else "."),
                                weight=min(5 * len(hits), 15), category="content"))

    return findings
