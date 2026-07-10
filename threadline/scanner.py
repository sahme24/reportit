"""Case orchestration: parse → analyze → score → build the attack chain."""

from __future__ import annotations

from . import ocr
from .advice import advice_for
from .auth import URGENCY_PHRASES, auth_findings
from .models import (BAD, INFO, OK, WARN, Case, ChainNode, Finding, UrlInfo,
                     case_id_for)
from .parser import ParsedEmail, parse_email
from .reputation import reputation_findings
from .urlscan import URL_RE, analyze_url, extract_urls

_SEV_ORDER = {BAD: 0, WARN: 1, OK: 2, INFO: 3}


def _url_findings(urls: list[UrlInfo]) -> list[Finding]:
    # Aggregate per registered domain, so a newsletter with 30 links to one
    # bad domain is one finding, not 30 findings' worth of score.
    by_domain: dict[str, list[UrlInfo]] = {}
    for u in urls:
        if u.flags:
            by_domain.setdefault(u.domain or u.url, []).append(u)

    findings: list[Finding] = []
    remaining_weight = 40  # cap the url category's total score contribution
    for domain, flagged in by_domain.items():
        flags = list(dict.fromkeys(f for u in flagged for f in u.flags))
        severity = BAD if any("impersonates" in f or "@" in f for f in flags) else WARN
        weight = min(20 if severity == BAD else 10, remaining_weight)
        remaining_weight -= weight
        count = f" ({len(flagged)} links to this domain)" if len(flagged) > 1 else ""
        findings.append(Finding(
            severity, f"Suspicious link: {domain}",
            f"{flagged[0].defanged}{count}: " + "; ".join(flags) + ".",
            weight=weight, category="url"))

    if urls and not findings:
        findings.append(Finding(OK, "Link heuristics clean",
                                f"{len(urls)} link(s) extracted; no typosquatting, "
                                "shorteners, or redirection tricks detected.",
                                category="url"))
    if not urls:
        findings.append(Finding(INFO, "No links present",
                                "The message body contains no URLs.", category="url"))
    return findings


def _image_findings(email: ParsedEmail) -> tuple[list[Finding], list[UrlInfo]]:
    """OCR attached/inline images and analyze whatever text hides in them.
    Returns the findings plus any URLs recovered from the images so they
    join the normal URL/reputation pipeline."""
    findings: list[Finding] = []
    urls: list[UrlInfo] = []
    if not email.images:
        return findings, urls

    if not ocr.is_available():
        findings.append(Finding(
            INFO, "Image text not checked",
            f"{len(email.images)} image(s) present, but Tesseract OCR isn't "
            "installed on this server, so text inside images wasn't analyzed.",
            category="image"))
        return findings, urls

    for img in email.images[:3]:
        text = ocr.extract_text(img["data"])
        if not text:
            continue
        found = [analyze_url(m.rstrip(".,;"))
                 for m in dict.fromkeys(URL_RE.findall(text))]
        if found:
            urls += found
            severity = BAD if any("impersonates" in flag
                                  for u in found for flag in u.flags) else WARN
            findings.append(Finding(
                severity, "Link hidden inside an image",
                f"OCR read a URL out of {img['filename']}. Putting the link "
                "in a picture is a classic trick to slip past text-based "
                "filters: " + "; ".join(u.defanged for u in found[:3]) + ".",
                weight=25 if severity == BAD else 15, category="image"))
        else:
            hits = [p for p in URGENCY_PHRASES if p in text.lower()]
            if hits:
                findings.append(Finding(
                    WARN, "Pressure language inside an image",
                    f"OCR read pressure phrasing out of {img['filename']}: "
                    + ", ".join(f'"{h}"' for h in hits[:3])
                    + ". Hiding the lure in an image is a filter-evasion "
                    "technique.", weight=10, category="image"))
    return findings, urls


def _attachment_findings(attachments: list[dict]) -> list[Finding]:
    if not attachments:
        return [Finding(OK, "Attachment scan", "No attachments present.",
                        category="attachment")]
    risky_ext = (".exe", ".js", ".vbs", ".scr", ".bat", ".cmd", ".ps1", ".hta",
                 ".iso", ".img", ".lnk", ".jar")
    macro_ext = (".docm", ".xlsm", ".pptm")
    findings = []
    for att in attachments:
        name = att["filename"].lower()
        if name.endswith(risky_ext):
            findings.append(Finding(BAD, "Executable attachment",
                                    f"{att['filename']} ({att['size']} bytes, "
                                    f"sha256 {att['sha256'][:16]}…) is a directly "
                                    "executable file type.", weight=30,
                                    category="attachment"))
        elif name.endswith(macro_ext) or name.endswith(".zip"):
            findings.append(Finding(WARN, "Risky attachment type",
                                    f"{att['filename']} may carry macros or nested "
                                    f"payloads (sha256 {att['sha256'][:16]}…).",
                                    weight=12, category="attachment"))
        else:
            findings.append(Finding(INFO, "Attachment present",
                                    f"{att['filename']} ({att['content_type']}, "
                                    f"{att['size']} bytes).", category="attachment"))
    return findings


def _verdict(score: int) -> tuple[str, str]:
    if score >= 70:
        return "MALICIOUS", "HIGH"
    if score >= 45:
        return "MALICIOUS", "MEDIUM"
    if score >= 20:
        return "SUSPICIOUS", "MEDIUM"
    if score >= 10:
        return "SUSPICIOUS", "LOW"
    return "LIKELY CLEAN", "MEDIUM"


def _build_chain(email: ParsedEmail, urls: list[UrlInfo],
                 findings: list[Finding]) -> list[ChainNode]:
    def by_cat(cat: str, sev: str) -> bool:
        return any(f.category == cat and f.severity == sev for f in findings)

    sender_bad = by_cat("domain", BAD) or by_cat("domain", WARN)
    chain = [ChainNode("Sender",
                       "spoofed" if sender_bad else "verified"
                       if email.spf == "pass" else "unverified",
                       BAD if sender_bad else OK if email.spf == "pass" else INFO)]

    failed_mechs = [m.upper() for m, r in
                    (("spf", email.spf), ("dkim", email.dkim),
                     ("dmarc", email.dmarc))
                    if r in ("fail", "softfail", "permerror")]
    if not failed_mechs:
        chain.append(ChainNode("Auth Check", "pass", OK))
    elif email.forwarded or email.auth_earlier_pass:
        chain.append(ChainNode("Auth Check", "fail (forwarded)", INFO))
    else:
        chain.append(ChainNode("Auth Check",
                               f"{'/'.join(failed_mechs[:2])} fail", BAD))

    if urls:
        worst = min(urls, key=lambda u: 0 if u.flags else 1)
        link_sev = WARN if worst.flags else OK
        if by_cat("url", BAD) or by_cat("reputation", BAD):
            link_sev = BAD
        from .urlscan import _safe_urlparse
        parsed = _safe_urlparse(worst.url)
        path = parsed.path.lstrip("/") or worst.domain
        query = parsed.query
        sub = (path + ("?" + query if query else ""))[:22] or worst.domain
        chain.append(ChainNode("Embedded Link", sub, link_sev))
        chain.append(ChainNode("Redirect", "not traced", INFO))
        # We never visit links, so the landing page is inferred, not observed.
        chain.append(ChainNode("Landing Page",
                               "suspected phish" if link_sev == BAD else "not visited",
                               link_sev if link_sev == BAD else INFO))
    elif email.attachments:
        att_sev = BAD if by_cat("attachment", BAD) else \
            WARN if by_cat("attachment", WARN) else OK
        chain.append(ChainNode("Attachment",
                               email.attachments[0]["filename"][:20], att_sev))
    else:
        chain.append(ChainNode("Payload", "none found", OK))

    return chain


def scan(raw: bytes | str, offline: bool = False, enrich=None) -> Case:
    """Run a full investigation. `enrich(email, urls) -> list[Finding]` lets the
    caller add context the engine can't know (e.g. instance scan history)."""
    email = parse_email(raw)

    url_pairs = extract_urls(email.body_text, email.body_html)
    urls = [analyze_url(u, text) for u, text in url_pairs]

    # OCR any images and merge recovered URLs into the main pipeline so
    # they get the same heuristics + reputation checks as body links.
    image_findings, image_urls = _image_findings(email)
    seen_urls = {u.url for u in urls}
    urls += [u for u in image_urls if u.url not in seen_urls]

    findings = auth_findings(email)
    findings += image_findings
    findings += _url_findings(urls)
    findings += _attachment_findings(email.attachments)
    findings += reputation_findings(email.sender_ip, urls, offline=offline)
    if enrich:
        findings += enrich(email, urls)
    findings.sort(key=lambda f: _SEV_ORDER.get(f.severity, 9))

    score = min(sum(f.weight for f in findings), 100)
    verdict, confidence = _verdict(score)

    preview = (email.body_text or email.body_html)[:600]

    # Substrings the UI should visually mark inside the body preview:
    # matched pressure phrases plus every link that raised a flag.
    lowered = f"{email.subject}\n{email.body_text}".lower()
    highlights = [p for p in URGENCY_PHRASES if p in lowered]
    highlights += [u.url for u in urls if u.flags]

    return Case(
        case_id=case_id_for(email.raw),
        verdict=verdict,
        confidence=confidence,
        score=score,
        headers={
            "from": f"{email.from_display} <{email.from_addr}>".strip(),
            "from_addr": email.from_addr,
            "reply_to": email.reply_to,
            "return_path": email.return_path,
            "subject": email.subject,
            "date": email.date,
        },
        auth={
            "spf": email.spf, "dkim": email.dkim, "dmarc": email.dmarc,
            "spf_detail": email.spf_detail,
            "dkim_detail": email.dkim_detail,
            "dmarc_detail": email.dmarc_detail,
            "sender_ip": email.sender_ip,
        },
        urls=urls,
        findings=findings,
        chain=_build_chain(email, urls, findings),
        body_preview=preview,
        attachments=email.attachments,
        highlights=highlights,
        recommendations=advice_for("email", verdict, findings),
    )
