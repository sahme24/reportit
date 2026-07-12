"""API smoke tests, run against a temp database, no network calls."""

import os
import tempfile

os.environ["THREADLINE_DB"] = os.path.join(tempfile.mkdtemp(), "test.db")

from fastapi.testclient import TestClient  # noqa: E402

import app as app_module  # noqa: E402
from threadline import db  # noqa: E402

client = TestClient(app_module.app)


_next_user = iter(range(10_000))


def _signed_in_client() -> TestClient:
    """Fresh account per call so AI-quota tests can't leak usage into each
    other via a shared user, the way they would with one fixed email."""
    n = next(_next_user)
    user = db.upsert_google_user(f"tester{n}@example.com", "Tester", f"sub-{n}")
    token = db.create_session(user["id"])
    c = TestClient(app_module.app)
    c.cookies.set("__session", token)
    return c


def test_public_pages_render():
    for path in ("/", "/login", "/scan"):
        r = client.get(path)
        assert r.status_code == 200, path


def test_scan_requires_auth():
    r = client.post("/api/scan", json={"raw": "hello"})
    assert r.status_code == 401


def test_scan_roundtrip_and_history():
    c = _signed_in_client()
    raw = (app_module.SAMPLES / "phish-0ffice365.eml").read_text(encoding="utf-8")
    r = c.post("/api/scan", json={"raw": raw, "offline": True})
    assert r.status_code == 200
    case = r.json()
    assert case["verdict"] == "MALICIOUS"
    assert case["recommendations"] and case["report_markdown"]

    history = c.get("/api/history").json()["scans"]
    assert history and history[0]["case_id"] == case["case_id"]


def test_ai_verdict_replaces_heuristic_verdict(monkeypatch):
    """There's one result, not two: when the AI's read differs from the
    heuristic score's, the AI verdict becomes the case's verdict (and the
    advice list is recomputed to match), not a second opinion shown next
    to a conflicting top-level badge."""
    c = _signed_in_client()
    monkeypatch.setattr(app_module.ai, "is_configured", lambda: True)
    monkeypatch.setattr(app_module.ai, "analyze_case", lambda case: {
        "verdict": "LIKELY CLEAN", "confidence": "HIGH",
        "summary": "stub", "actions": ["check it yourself"]})

    # This sample is heuristically MALICIOUS; the mocked AI disagrees.
    raw = (app_module.SAMPLES / "phish-0ffice365.eml").read_text(encoding="utf-8")
    r = c.post("/api/scan", json={"raw": raw})
    assert r.status_code == 200
    case = r.json()

    assert case["verdict"] == "LIKELY CLEAN"
    assert case["confidence"] == "HIGH"
    # The AI-side payload carries explanation only, not a rival verdict.
    assert "verdict" not in case["ai_opinion"]
    assert case["ai_opinion"]["summary"] == "stub"
    # Advice matches the FINAL verdict, not the original heuristic one.
    assert case["recommendations"]
    assert not any("don't click" in s.lower() for s in case["recommendations"])
    # The report's own verdict line and the AI section both reflect it too.
    assert "LIKELY CLEAN" in case["report_markdown"]


def test_scan_quota_enforced(monkeypatch):
    """There's one scan action (heuristics + AI together), not a separate
    'unlimited scans, limited AI' split -- the daily cap gates the scan
    itself once AI is configured."""
    c = _signed_in_client()
    monkeypatch.setattr(app_module.ai, "is_configured", lambda: True)
    monkeypatch.setattr(app_module.ai, "analyze_case", lambda case: {
        "verdict": "MALICIOUS", "confidence": "HIGH",
        "summary": "stub", "actions": []})

    raw = (app_module.SAMPLES / "phish-0ffice365.eml").read_text(encoding="utf-8")
    allowed = [c.post("/api/scan", json={"raw": raw})
               for _ in range(app_module._AI_DAILY_LIMIT)]
    assert all(r.status_code == 200 for r in allowed)
    assert all(r.json()["verdict"] == "MALICIOUS" for r in allowed)
    assert allowed[-1].json()["uses_left"] == 0

    blocked = c.post("/api/scan", json={"raw": raw})
    assert blocked.status_code == 429
    detail = blocked.json()["detail"]
    # Rolling 24h window: the response tells the client when a slot frees up.
    assert detail["refresh_at"] is not None

    # Offline mode never touches the AI, so it stays unmetered even once
    # the daily quota is spent.
    offline = c.post("/api/scan", json={"raw": raw, "offline": True})
    assert offline.status_code == 200


def test_explain_retry_does_not_spend_quota(monkeypatch):
    """/api/explain retries the AI portion of an already-scanned case; it
    must not re-check or consume the scan quota, since that's spent once
    when the scan itself runs."""
    c = _signed_in_client()
    monkeypatch.setattr(app_module.ai, "is_configured", lambda: True)
    monkeypatch.setattr(app_module.ai, "analyze_case", lambda case: {
        "verdict": "MALICIOUS", "confidence": "HIGH",
        "summary": "stub", "actions": []})

    payload = {"case": {"verdict": "MALICIOUS"}}
    responses = [c.post("/api/explain", json=payload)
                 for _ in range(app_module._AI_DAILY_LIMIT + 2)]
    assert all(r.status_code == 200 for r in responses)
    assert all("uses_left" not in r.json() for r in responses)


def test_personal_dashboard_stats():
    c = _signed_in_client()
    s = c.get("/api/my/stats").json()
    assert {"scans", "malicious", "suspicious", "clean",
            "ai_uses_left", "ai_limit", "recent", "instance"} <= s.keys()
    assert {"scans", "users", "threats"} <= s["instance"].keys()


def test_public_stats_expose_threats():
    s = client.get("/api/stats").json()
    assert "threats" in s and s["threats"] >= 0
