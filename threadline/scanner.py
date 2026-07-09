"""Case orchestration: parse → analyze → score → build the attack chain."""

from __future__ import annotations

from .auth import auth_findings
from .models import (BAD, INFO, OK, WARN, Case, ChainNode, Finding, UrlInfo,
                     case_id_for)
from .parser import ParsedEmail, parse_email
from .reputation import reputation_findings
from .urlscan import analyze_url, extract_urls

_SEV_ORDER = {BAD: 0, WARN: 1, OK: 2, INFO: 3}


def _url_findings(urls: list[UrlInfo]) -> list[Finding]:
    findings: list[Finding] = []
    for u in urls:
        if not u.flags:
            continue
        severity = BAD if any("impersonates" in f or "@" in f for f in u.flags) else WARN
        findings.append(Finding(
            severity, f"Suspicious link — {u.domain or u.url}",
            f"{u.defanged}: " + "; ".join(u.flags) + ".",
            weight=20 if severity == BAD else 10, category="url"))
    if urls and not findings:
        findings.append(Finding(OK, "Link heuristics clean",
                                f"{len(urls)} link(s) extracted; no typosquatting, "
                                "shorteners, or redirection tricks detected.",
                                category="url"))
    if not urls:
        findings.append(Finding(INFO, "No links present",
                                "The message body contains no URLs.", category="url"))
    return findings


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
    by_cat = lambda cat, sev: any(
        f.category == cat and f.severity == sev for f in findings)

    sender_bad = by_cat("domain", BAD) or by_cat("domain", WARN)
    chain = [ChainNode("Sender",
                       "spoofed" if sender_bad else "verified"
                       if email.spf == "pass" else "unverified",
                       BAD if sender_bad else OK if email.spf == "pass" else INFO)]

    auth_failed = any(f.category == "auth" and f.severity in (BAD, WARN)
                      and "authentication" in f.title.lower() for f in findings)
    failed_mechs = "/".join(m.upper() for m, r in
                            (("spf", email.spf), ("dkim", email.dkim))
                            if r in ("fail", "softfail")) or "SPF/DKIM"
    chain.append(ChainNode("Auth Check",
                           f"{failed_mechs} fail" if auth_failed else "pass",
                           BAD if auth_failed else OK))

    if urls:
        worst = min(urls, key=lambda u: 0 if u.flags else 1)
        link_sev = WARN if worst.flags else OK
        if by_cat("url", BAD) or by_cat("reputation", BAD):
            link_sev = BAD
        from urllib.parse import urlparse
        path = urlparse(worst.url).path.lstrip("/") or worst.domain
        query = urlparse(worst.url).query
        sub = (path + ("?" + query if query else ""))[:22] or worst.domain
        chain.append(ChainNode("Embedded Link", sub, link_sev))
        chain.append(ChainNode("Redirect", "not traced", INFO))
        chain.append(ChainNode("Landing Page",
                               "credential form" if link_sev == BAD else "unknown",
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

    findings = auth_findings(email)
    findings += _url_findings(urls)
    findings += _attachment_findings(email.attachments)
    findings += reputation_findings(email.sender_ip, urls, offline=offline)
    if enrich:
        findings += enrich(email, urls)
    findings.sort(key=lambda f: _SEV_ORDER.get(f.severity, 9))

    score = min(sum(f.weight for f in findings), 100)
    verdict, confidence = _verdict(score)

    preview = (email.body_text or email.body_html)[:600]

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
    )
