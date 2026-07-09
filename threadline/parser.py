"""Raw email parsing: headers, auth results, sender IP, body, attachments."""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass, field
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import parseaddr


@dataclass
class ParsedEmail:
    from_display: str
    from_addr: str
    reply_to: str
    return_path: str
    subject: str
    date: str
    sender_ip: str            # best-guess originating public IP, "" if unknown
    spf: str                  # pass | fail | softfail | none | unknown
    dkim: str
    dmarc: str
    spf_detail: str
    dkim_detail: str
    dmarc_detail: str
    body_text: str
    body_html: str
    attachments: list[dict] = field(default_factory=list)
    raw: bytes = b""


_AUTH_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.I)
_CLIENT_IP_RE = re.compile(r"client-ip[=\s]+([0-9a-f.:]+)", re.I)
_SENDER_IP_RE = re.compile(r"sender IP(?: is)?\s+([0-9a-f.:]+)", re.I)
_RECEIVED_IP_RE = re.compile(r"[\[\(]([0-9]{1,3}(?:\.[0-9]{1,3}){3})[\]\)]")


def _is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast)


def _auth_results(msg: EmailMessage) -> dict[str, str]:
    """Combine Authentication-Results / Received-SPF headers into one view."""
    results = {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown"}
    details = {"spf": "", "dkim": "", "dmarc": ""}

    for header in msg.get_all("Authentication-Results", []):
        for mech, outcome in _AUTH_RE.findall(header):
            mech = mech.lower()
            if results.get(mech) in ("unknown", "none"):
                results[mech] = outcome.lower()
                details[mech] = header.strip()

    received_spf = msg.get("Received-SPF", "")
    if received_spf and results["spf"] == "unknown":
        results["spf"] = received_spf.split()[0].strip(";").lower()
        details["spf"] = received_spf.strip()
    elif received_spf and not details["spf"]:
        details["spf"] = received_spf.strip()

    return {**results, **{f"{k}_detail": v for k, v in details.items()}}


def _sender_ip(msg: EmailMessage) -> str:
    """Best-guess originating public IP.

    Preference order: explicit client-ip / "sender IP" annotations, then the
    earliest (bottom-most) Received hop that carries a public address.
    """
    for header in msg.get_all("Received-SPF", []) + msg.get_all("Authentication-Results", []):
        m = _CLIENT_IP_RE.search(header) or _SENDER_IP_RE.search(header)
        if m and _is_public_ip(m.group(1)):
            return m.group(1)

    originating = msg.get("X-Originating-IP", "").strip("[] ")
    if _is_public_ip(originating):
        return originating

    for received in reversed(msg.get_all("Received", [])):
        for ip in _RECEIVED_IP_RE.findall(received):
            if _is_public_ip(ip):
                return ip
    return ""


def _bodies(msg: EmailMessage) -> tuple[str, str]:
    text, html = "", ""
    for part in msg.walk():
        if part.get_content_maintype() != "text" or part.get_filename():
            continue
        try:
            content = part.get_content()
        except Exception:
            continue
        if part.get_content_subtype() == "plain" and not text:
            text = content
        elif part.get_content_subtype() == "html" and not html:
            html = content
    return text, html


def _attachments(msg: EmailMessage) -> list[dict]:
    out = []
    for part in msg.walk():
        filename = part.get_filename()
        if not filename:
            continue
        payload = part.get_payload(decode=True) or b""
        out.append({
            "filename": filename,
            "content_type": part.get_content_type(),
            "size": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        })
    return out


def parse_email(raw: bytes | str) -> ParsedEmail:
    if isinstance(raw, str):
        raw = raw.encode("utf-8", errors="replace")
    msg = BytesParser(policy=policy.default).parsebytes(raw)

    from_display, from_addr = parseaddr(str(msg.get("From", "")))
    _, reply_to = parseaddr(str(msg.get("Reply-To", "")))
    _, return_path = parseaddr(str(msg.get("Return-Path", "")))
    auth = _auth_results(msg)
    text, html = _bodies(msg)

    return ParsedEmail(
        from_display=from_display,
        from_addr=from_addr.lower(),
        reply_to=reply_to.lower(),
        return_path=return_path.lower(),
        subject=str(msg.get("Subject", "")),
        date=str(msg.get("Date", "")),
        sender_ip=_sender_ip(msg),
        spf=auth["spf"],
        dkim=auth["dkim"],
        dmarc=auth["dmarc"],
        spf_detail=auth["spf_detail"],
        dkim_detail=auth["dkim_detail"],
        dmarc_detail=auth["dmarc_detail"],
        body_text=text,
        body_html=html,
        attachments=_attachments(msg),
        raw=raw,
    )
