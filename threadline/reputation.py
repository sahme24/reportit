"""Reputation lookups against public threat-intel sources.

Keyless sources (RDAP domain age) always run unless --offline.
Keyed sources (VirusTotal, AbuseIPDB, URLhaus) run only when the matching
environment variable is set:

    VT_API_KEY, ABUSEIPDB_API_KEY, URLHAUS_API_KEY

Keys can also live in a .env file in the working directory.
Every lookup fails soft, so a dead API never breaks a scan.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

import requests

from .models import BAD, INFO, OK, WARN, Finding
from .urlscan import UrlInfo

TIMEOUT = 8
_UA = {"User-Agent": "Threadline/0.1 (phishing investigation tool)"}


def load_dotenv(path: str | Path = ".env") -> None:
    """Minimal .env loader for KEY=VALUE lines, no dependency needed."""
    p = Path(path)
    if not p.is_file():
        return
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


# --------------------------------------------------------------------------
# RDAP: domain registration age (no key required)
# --------------------------------------------------------------------------

def domain_age_days(domain: str) -> int | None:
    try:
        r = requests.get(f"https://rdap.org/domain/{domain}",
                         headers=_UA, timeout=TIMEOUT)
        if r.status_code != 200:
            return None
        for event in r.json().get("events", []):
            if event.get("eventAction") == "registration":
                registered = datetime.fromisoformat(
                    event["eventDate"].replace("Z", "+00:00"))
                return (datetime.now(timezone.utc) - registered).days
    except Exception:
        pass
    return None


# --------------------------------------------------------------------------
# Keyed providers
# --------------------------------------------------------------------------

def _virustotal_domain(domain: str, key: str) -> Finding | None:
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}",
                         headers={"x-apikey": key, **_UA}, timeout=TIMEOUT)
        if r.status_code != 200:
            return None
        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        bad = stats.get("malicious", 0) + stats.get("suspicious", 0)
        total = sum(stats.values()) or 1
        if bad:
            return Finding(BAD if stats.get("malicious", 0) >= 3 else WARN,
                           "VirusTotal detections",
                           f"{domain}: {bad}/{total} engines flag this domain.",
                           weight=25 if stats.get("malicious", 0) >= 3 else 12,
                           category="reputation")
        return Finding(OK, "VirusTotal clean",
                       f"{domain}: 0/{total} engines flag this domain.",
                       category="reputation")
    except Exception:
        return None


def _abuseipdb(ip: str, key: str) -> Finding | None:
    try:
        r = requests.get("https://api.abuseipdb.com/api/v2/check",
                         params={"ipAddress": ip, "maxAgeInDays": 90},
                         headers={"Key": key, "Accept": "application/json", **_UA},
                         timeout=TIMEOUT)
        if r.status_code != 200:
            return None
        data = r.json()["data"]
        score = data.get("abuseConfidenceScore", 0)
        reports = data.get("totalReports", 0)
        if score >= 50:
            return Finding(BAD, "Sender IP known-abusive",
                           f"{ip}: AbuseIPDB confidence {score}% "
                           f"({reports} reports in 90 days).",
                           weight=20, category="reputation")
        if score > 0:
            return Finding(WARN, "Sender IP has abuse reports",
                           f"{ip}: AbuseIPDB confidence {score}% "
                           f"({reports} reports in 90 days).",
                           weight=8, category="reputation")
        return Finding(OK, "Sender IP reputation clean",
                       f"{ip}: no AbuseIPDB reports in the last 90 days.",
                       category="reputation")
    except Exception:
        return None


def _urlhaus(url: str, key: str) -> Finding | None:
    try:
        r = requests.post("https://urlhaus-api.abuse.ch/v1/url/",
                          data={"url": url},
                          headers={"Auth-Key": key, **_UA}, timeout=TIMEOUT)
        if r.status_code != 200:
            return None
        data = r.json()
        if data.get("query_status") == "ok":
            threat = data.get("threat", "listed")
            return Finding(BAD, "Link flagged on URLhaus",
                           f"Known-malicious URL (threat: {threat}), "
                           f"first seen {data.get('date_added', 'unknown')}.",
                           weight=30, category="reputation")
    except Exception:
        pass
    return None


# --------------------------------------------------------------------------
# Orchestrator
# --------------------------------------------------------------------------

def reputation_findings(sender_ip: str, urls: list[UrlInfo],
                        offline: bool = False) -> list[Finding]:
    if offline:
        return [Finding(INFO, "Reputation checks skipped",
                        "Running in offline mode. No external lookups performed.",
                        category="reputation")]

    load_dotenv()
    findings: list[Finding] = []
    domains = list(dict.fromkeys(u.domain for u in urls if u.domain))

    # Domain age via RDAP (keyless)
    for domain in domains[:5]:
        age = domain_age_days(domain)
        if age is None:
            continue
        if age <= 30:
            findings.append(Finding(BAD, "Newly registered domain",
                                    f"{domain} was registered {age} day(s) ago.",
                                    weight=25, category="reputation"))
        elif age <= 180:
            findings.append(Finding(WARN, "Recently registered domain",
                                    f"{domain} was registered {age} days ago.",
                                    weight=10, category="reputation"))
        else:
            findings.append(Finding(INFO, "Domain age",
                                    f"{domain} registered {age // 365} year(s) ago.",
                                    category="reputation"))

    vt_key = os.environ.get("VT_API_KEY", "")
    abuse_key = os.environ.get("ABUSEIPDB_API_KEY", "")
    urlhaus_key = os.environ.get("URLHAUS_API_KEY", "")

    if vt_key:
        for domain in domains[:4]:
            if f := _virustotal_domain(domain, vt_key):
                findings.append(f)
    if abuse_key and sender_ip:
        if f := _abuseipdb(sender_ip, abuse_key):
            findings.append(f)
    if urlhaus_key:
        flagged = 0
        for u in urls[:10]:
            if f := _urlhaus(u.url, urlhaus_key):
                findings.append(f)
                flagged += 1
        if urls and not flagged:
            findings.append(Finding(INFO, "URLhaus",
                                    f"0 of {len(urls)} links listed on URLhaus.",
                                    category="reputation"))

    skipped = [name for name, key in (("VirusTotal", vt_key),
                                      ("AbuseIPDB", abuse_key),
                                      ("URLhaus", urlhaus_key)) if not key]
    if skipped:
        findings.append(Finding(INFO, "Some providers skipped",
                                f"No API key configured for: {', '.join(skipped)}. "
                                "Add keys to .env to enable.", category="reputation"))
    return findings
