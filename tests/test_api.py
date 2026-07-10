"""API smoke tests, run against a temp database, no network calls."""

import os
import tempfile

os.environ["THREADLINE_DB"] = os.path.join(tempfile.mkdtemp(), "test.db")

from fastapi.testclient import TestClient  # noqa: E402

import app as app_module  # noqa: E402
from threadline import db  # noqa: E402

client = TestClient(app_module.app)


def _signed_in_client() -> TestClient:
    user = db.upsert_google_user("tester@example.com", "Tester", "sub-123")
    token = db.create_session(user["id"])
    c = TestClient(app_module.app)
    c.cookies.set("threadline_session", token)
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


def test_ai_daily_limit_enforced(monkeypatch):
    c = _signed_in_client()
    monkeypatch.setattr(app_module.ai, "is_configured", lambda: True)
    monkeypatch.setattr(app_module.ai, "analyze_case", lambda case: {
        "verdict": "MALICIOUS", "confidence": "HIGH",
        "agrees_with_scanner": True, "summary": "stub", "actions": []})

    payload = {"case": {"verdict": "MALICIOUS"}}
    allowed = [c.post("/api/explain", json=payload)
               for _ in range(app_module._AI_DAILY_LIMIT)]
    assert all(r.status_code == 200 for r in allowed)
    assert allowed[-1].json()["uses_left"] == 0

    blocked = c.post("/api/explain", json=payload)
    assert blocked.status_code == 429
    detail = blocked.json()["detail"]
    # Rolling 24h window: the response tells the client when a slot frees up.
    assert detail["refresh_at"] is not None


def test_personal_dashboard_stats():
    c = _signed_in_client()
    s = c.get("/api/my/stats").json()
    assert {"scans", "malicious", "suspicious", "clean",
            "ai_uses_left", "ai_limit", "recent", "instance"} <= s.keys()
    assert {"scans", "users", "threats"} <= s["instance"].keys()


def test_public_stats_expose_threats():
    s = client.get("/api/stats").json()
    assert "threats" in s and s["threats"] >= 0
