"""Markdown report generation.

The report leads with a fill-in-the-blanks checklist shaped like what a
bank, the CRA, or a national fraud centre actually asks for when you
report a phishing/smishing attempt, pre-filled with everything the scan
already knows. The full technical findings follow underneath for anyone
who wants the evidence trail (an abuse desk, IT, or just for your records).
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from .models import BAD, WARN, Case
from .urlscan import defang_text

_SEV_MARK = {"bad": "🔴", "warn": "🟠", "ok": "🟢", "info": "⚪"}
_BLANK = "_____ (fill in before submitting)"
_YESNO = "_____ (Yes / No)"
_QUOTED = re.compile(r'"([^"]+)"')


def _impersonated_org(case: Case) -> str:
    """Best guess at the organization being impersonated, pulled from
    whichever domain-brand finding fired. Blank if nothing matched."""
    for f in case.findings:
        if f.category == "domain" and f.severity in (BAD, WARN):
            m = _QUOTED.search(f.title) or _QUOTED.search(f.detail)
            if m:
                return m.group(1).title()
    return ""


def _urgency_language(case: Case) -> str:
    for f in case.findings:
        if f.category == "content" and "urgency" in f.title.lower():
            return f.detail
    return "None detected by the scan; note anything you noticed yourself."


def _red_flags(case: Case) -> list[str]:
    flags = []
    if any(f.category == "domain" and f.severity in (BAD, WARN) for f in case.findings):
        flags.append("Domain or branding mismatch (sender or link domain "
                     "doesn't match the real organization)")
    if any(f.category == "url" and f.severity in (BAD, WARN) for f in case.findings):
        flags.append("Suspicious link formatting (typosquat, shortener, "
                     "or redirect trickery)")
    if case.kind != "sms" and any(
            f.category == "auth" and f.severity in (BAD, WARN) for f in case.findings):
        flags.append("Sender authentication failed (SPF/DKIM/DMARC)")
    if any(f.category == "reputation" and f.severity in (BAD, WARN) for f in case.findings):
        flags.append("Domain or sender IP has abuse/reputation reports")
    if not flags:
        flags.append("No automated red flags matched; rely on your own judgment "
                     "and the notes below")
    return flags


def _reporter_lines(reporter: dict | None) -> list[str]:
    name = reporter.get("name", "") if reporter else ""
    email = reporter.get("email", "") if reporter else ""
    return [
        f"| Name | {name or _BLANK} |",
        f"| Email | {email or _BLANK} |",
        f"| Phone | {_BLANK} |",
        f"| Province/state of residence | {_BLANK} |",
    ]


def _checklist(case: Case, reporter: dict | None) -> list[str]:
    platform = "Text message (SMS)" if case.kind == "sms" else "Email"
    sender = case.headers.get("from", "") or "unknown"
    date_received = case.headers.get("date", "") or _BLANK

    lines = [
        "## 1. Message Details",
        "",
        "| | |",
        "|---|---|",
        f"| Platform | {platform} |",
        f"| Sender | `{sender}` |",
        f"| Date received | {date_received} |",
        "| Full message text | See \"Message excerpt\" under Automated Scan Details below, "
        "or attach a screenshot |",
        f"| Links in message ({len(case.urls)} found, defanged for safety) | "
        + ("See Indicators of Compromise below" if case.urls else "None") + " |",
        "",
        "## 2. What They Claimed",
        "",
        f"- **Organization impersonated:** {_impersonated_org(case) or _BLANK}",
        f"- **Action requested** (click a link, call a number, enter info, send money): {_BLANK}",
        f"- **Refund/amount mentioned, if any:** {_BLANK}",
        f"- **Urgency or threat language used:** {_urgency_language(case)}",
        "",
        "## 3. Red Flags Noted",
        "",
    ]
    lines += [f"- {flag}" for flag in _red_flags(case)]
    lines += [
        f"- **Spelling/grammar errors noticed:** {_BLANK}",
        f"- **Generic greeting used (\"Dear Customer\"):** {_BLANK}",
        "",
        "## 4. Reporter Info (optional; remove this section if you'd rather stay anonymous)",
        "",
        "| | |",
        "|---|---|",
    ]
    lines += _reporter_lines(reporter)
    lines += [
        "",
        "## 5. Impact",
        "",
        "Fill this in honestly. It's what a bank or fraud investigator needs most,",
        "and there's no wrong answer if the message never got that far.",
        "",
        f"- **Clicked the link?** {_YESNO}",
        f"- **Entered personal info?** {_YESNO}",
        f"- **Sent money?** {_YESNO}",
        f"- **Amount lost, if any:** {_BLANK}",
        "- **Type of info shared** (SIN, banking, passwords, etc.), if any: "
        f"{_BLANK}",
        "",
        "## 6. Additional Context",
        "",
        f"- **How often are you receiving similar messages?** {_BLANK}",
        f"- **Any account compromises noticed since?** {_BLANK}",
        "- **Screenshots or attachments included with this report?** "
        f"{_BLANK}",
    ]
    return lines


def markdown_report(case: Case, reporter: dict | None = None,
                    ai_summary: str | None = None) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        f"# Phishing/Smishing Report: Case #{case.case_id}",
        "",
        f"**Automated verdict:** {case.verdict} ({case.confidence} CONFIDENCE), "
        f"risk score {case.score}/100  ",
        f"**Generated:** {now} by ReportIT.ai",
        "",
        "This report is shaped to submit to your bank's fraud line, the CRA, "
        "or a national fraud centre (e.g. the Canadian Anti-Fraud Centre, "
        "the FTC, Action Fraud). Fill in the blanks below, then attach or "
        "paste this whole document.",
        "",
    ]
    if ai_summary:
        lines += ["## Why This Verdict", "", ai_summary, ""]
    lines += _checklist(case, reporter)
    lines += ["", "---", "", "## Automated Scan Details", ""]

    if case.kind == "sms":
        lines += [
            "### Message (SMS)",
            "",
            "| | |",
            "|---|---|",
            f"| Sender | `{case.headers['from']}` |",
            f"| Message excerpt | {defang_text(case.body_preview[:300])} |",
        ]
    else:
        lines += [
            "### Message",
            "",
            "| | |",
            "|---|---|",
            f"| From | `{case.headers['from']}` |",
            f"| Reply-To | `{case.headers['reply_to'] or '—'}` |",
            f"| Subject | {case.headers['subject']} |",
            f"| Date | {case.headers['date'] or '—'} |",
            f"| Sender IP | `{case.auth['sender_ip'] or 'not identified'}` |",
            f"| Message excerpt | {defang_text(case.body_preview[:300])} |",
            "",
            "### Authentication",
            "",
            "| Mechanism | Result |",
            "|---|---|",
            f"| SPF | {case.auth['spf']} |",
            f"| DKIM | {case.auth['dkim']} |",
            f"| DMARC | {case.auth['dmarc']} |",
        ]
    lines += [
        "",
        "### Findings",
        "",
    ]
    for f in case.findings:
        lines.append(f"- {_SEV_MARK.get(f.severity, '•')} **{f.title}:** {f.detail}")

    lines += ["", "### Attack Chain", ""]
    lines.append(" → ".join(f"**{n.label}** ({n.sub})" for n in case.chain))

    if case.recommendations:
        lines += ["", "### What You Should Do", ""]
        lines += [f"{i}. {step}" for i, step in enumerate(case.recommendations, 1)]

    if case.urls:
        lines += ["", "### Indicators of Compromise", ""]
        for u in case.urls:
            lines.append(f"- URL: `{u.defanged}`")
        if case.auth["sender_ip"]:
            lines.append(f"- IP: `{case.auth['sender_ip']}`")
        for domain in dict.fromkeys(u.domain for u in case.urls if u.domain):
            lines.append(f"- Domain: `{domain.replace('.', '[.]', 1)}`")
    for att in case.attachments:
        lines.append(f"- File: `{att['filename']}` sha256 `{att['sha256']}`")

    lines += ["", "---", "_Generated by ReportIT.ai. URLs are defanged; "
              "do not re-arm indicators outside a sandbox._", ""]
    return "\n".join(lines)
