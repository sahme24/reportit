"""Engine regression tests, all offline, no network, no API keys."""

from pathlib import Path

from threadline.advice import advice_for
from threadline.models import BAD, OK
from threadline.parser import parse_email
from threadline.report import markdown_report
from threadline.scanner import scan
from threadline.sms import scan_sms
from threadline.urlscan import analyze_url, match_brand

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def _scan_sample(name: str):
    return scan((SAMPLES / name).read_bytes(), offline=True)


# --------------------------------------------------------------------- email

def test_phishing_email_is_malicious():
    case = _scan_sample("phish-0ffice365.eml")
    assert case.verdict == "MALICIOUS"
    assert case.score >= 70
    titles = [f.title.lower() for f in case.findings]
    assert any("authentication failed" in t for t in titles)
    assert any("impersonation" in t for t in titles)


def test_clean_email_is_clean():
    case = _scan_sample("clean-notification.eml")
    assert case.verdict == "LIKELY CLEAN"
    assert case.score < 10


def test_case_carries_advice_and_highlights():
    case = _scan_sample("phish-0ffice365.eml")
    assert case.recommendations, "malicious case must include next steps"
    assert case.highlights, "phish sample should highlight urgency phrases"
    assert any("reportphishing@apwg.org" in s for s in case.recommendations)


# ----------------------------------------------------------------------- sms

def test_smishing_text_flags_brand_lure():
    text = (SAMPLES / "smish-cra.txt").read_text(encoding="utf-8")
    case = scan_sms(text, sender="+1 (873) 555-0193", offline=True)
    assert case.kind == "sms"
    assert case.verdict in ("MALICIOUS", "SUSPICIOUS")
    assert any(f.category == "domain" and f.severity == "bad"
               for f in case.findings), "brand lure should fire"
    assert any("7726" in s for s in case.recommendations)


def test_sms_shortcode_is_not_penalized():
    case = scan_sms("Your verification code is 123456.", sender="80101",
                    offline=True)
    assert case.verdict == "LIKELY CLEAN"


# ---------------------------------------------------------------------- urls

def test_homoglyph_typosquat_detected():
    info = analyze_url("https://0ffice365-secure.com/reset?id=1")
    assert any("impersonates" in f for f in info.flags)


def test_real_brand_domains_not_flagged():
    for url in ("https://www.canadapost.ca/track",
                "https://github.com/notifications",
                "https://www.microsoft.com/account"):
        info = analyze_url(url)
        assert not any("impersonates" in f for f in info.flags), url


def test_malformed_urls_never_crash_the_scanner():
    # Defanged brackets and bad IPv6 literals used to raise ValueError.
    body = ("Click https://evil[.]example[.]com/x and http://[::bad and "
            "https://reminder-craportal.com/refund")
    case = scan(f"From: a@b.com\nSubject: hi\n\n{body}".encode(), offline=True)
    assert case.verdict  # any verdict is fine, the point is it didn't 500
    info = analyze_url("http://[::broken")
    assert info.flags == ["unparseable URL"]


def test_match_brand_boundaries():
    assert match_brand("0ffice365-secure.com") is not None
    assert match_brand("groups.com") is None       # "ups" inside a word
    assert match_brand("canadapost.ca") is None    # the real domain


# ------------------------------------------------------------- forwarded mail

def test_sender_ip_prefers_authenticated_origin_over_relay():
    """A message forwarded through a second mailbox (Hotmail -> Gmail)
    fails auth at the final hop but passed cleanly at the real origin.
    The reputation check must use the origin's IP, not whichever relay
    forwarded it last -- otherwise it's checking the reputation of a
    shared ESP IP (Microsoft 365, Google, etc.) that says nothing about
    who actually sent the message."""
    raw = b"""\
Authentication-Results: mx.google.com; dkim=neutral (body hash did not verify); spf=softfail (google.com: domain of transitioning bounce@example.com does not designate 2a01:111:f403:c105::5 as permitted sender)
Authentication-Results: spf=pass (sender IP is 172.82.216.13) smtp.mailfrom=canadapost-postescanada.ca; dkim=pass (signature was verified) header.d=canadapost-postescanada.ca; dmarc=pass action=none
Received-SPF: softfail (google.com: domain of transitioning bounce@example.com does not designate 2a01:111:f403:c105::5 as permitted sender) client-ip=2a01:111:f403:c105::5;
Resent-From: <someone@hotmail.com>
From: "Postes Canada" <notify@canadapost-postescanada.ca>
Subject: Test
Date: Fri, 10 Jul 2026 19:20:36 +0200
To: <someone@example.com>

Body text.
"""
    parsed = parse_email(raw)
    assert parsed.sender_ip == "172.82.216.13"
    assert parsed.auth_earlier_pass is True


# ---------------------------------------------------------------- reputation

def test_abuseipdb_low_confidence_is_not_flagged(monkeypatch):
    """AbuseIPDB's own guidance treats scores below ~25% as noise -- a
    shared mail relay accumulates some reports from other tenants'
    traffic regardless of any single message sent through it."""
    import threadline.reputation as reputation

    class FakeResponse:
        status_code = 200
        def json(self):
            return {"data": {"abuseConfidenceScore": 26, "totalReports": 19}}

    monkeypatch.setattr(reputation.requests, "get", lambda *a, **k: FakeResponse())
    finding = reputation._abuseipdb("2a01:111:f403:c105::5", "fake-key")
    assert finding.severity == OK


def test_abuseipdb_high_confidence_is_flagged(monkeypatch):
    import threadline.reputation as reputation

    class FakeResponse:
        status_code = 200
        def json(self):
            return {"data": {"abuseConfidenceScore": 90, "totalReports": 200}}

    monkeypatch.setattr(reputation.requests, "get", lambda *a, **k: FakeResponse())
    finding = reputation._abuseipdb("1.2.3.4", "fake-key")
    assert finding.severity == BAD


# -------------------------------------------------------------------- report

def test_report_includes_advice_and_defanged_urls():
    case = _scan_sample("phish-0ffice365.eml")
    report = markdown_report(case)
    assert "What You Should Do" in report
    assert "hxxps://" in report and "[.]" in report
    assert "https://0ffice365-secure.com" not in report, "URLs must be defanged"


def test_report_checklist_is_filled_and_message_excerpt_defanged():
    case = _scan_sample("phish-0ffice365.eml")
    report = markdown_report(case, reporter={"name": "Jane Doe",
                                             "email": "jane@example.com"})
    for heading in ("Message Details", "What They Claimed", "Red Flags Noted",
                    "Reporter Info", "## 5. Impact", "Additional Context"):
        assert heading in report
    assert "Jane Doe" in report and "jane@example.com" in report
    # The message excerpt embeds the phishing link verbatim in the raw
    # body; it must come out defanged like every other URL in the report.
    assert "https://0ffice365-secure.com" not in report
    assert "hxxps://0ffice365-secure[.]com" in report


# -------------------------------------------------------------------- advice

def test_advice_is_verdict_specific():
    assert any("7726" in s for s in advice_for("sms", "MALICIOUS", []))
    assert any("Verify directly" in s for s in advice_for("email", "SUSPICIOUS", []))
    clean = advice_for("email", "LIKELY CLEAN", [])
    assert any("Golden rule" in s for s in clean)
