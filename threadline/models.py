"""Shared data structures for a Threadline case."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict


# Severity levels used everywhere (findings, chain nodes, verdict).
BAD = "bad"      # confirmed-malicious indicator
WARN = "warn"    # suspicious indicator
OK = "ok"        # verified clean / passed check
INFO = "info"    # neutral context, no score impact


@dataclass
class Finding:
    severity: str          # bad | warn | ok | info
    title: str
    detail: str
    weight: int = 0        # contribution to the malice score
    category: str = ""     # auth | domain | url | reputation | content | attachment


@dataclass
class ChainNode:
    label: str             # e.g. "Sender"
    sub: str               # short mono caption, e.g. "spoofed"
    severity: str          # bad | warn | ok | info


@dataclass
class UrlInfo:
    url: str
    domain: str
    defanged: str
    flags: list[str] = field(default_factory=list)


@dataclass
class Case:
    case_id: str
    verdict: str           # MALICIOUS | SUSPICIOUS | LIKELY CLEAN
    confidence: str        # HIGH | MEDIUM | LOW
    score: int
    headers: dict
    auth: dict             # spf/dkim/dmarc results + sender ip
    urls: list[UrlInfo]
    findings: list[Finding]
    chain: list[ChainNode]
    body_preview: str
    attachments: list[dict]

    def to_dict(self) -> dict:
        return asdict(self)


def case_id_for(raw: bytes) -> str:
    """Stable 4-digit case number derived from the message content."""
    digest = hashlib.sha256(raw).hexdigest()
    return f"{int(digest[:8], 16) % 10000:04d}"
