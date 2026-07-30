"""API smoke tests, run against a temp database, no network calls."""

import contextlib
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


def test_repeat_offender_only_flags_prior_bad_verdicts():
    """A sender/domain scanned before is only a warning sign if those
    prior scans were themselves MALICIOUS/SUSPICIOUS -- not just for
    having appeared before, which would penalize any real, high-volume
    sender (a bank, a delivery service, a government agency) more the
    more of its legitimate mail gets scanned.

    Domains are made unique per call so this test doesn't collide with
    scan history left behind by other tests sharing the same database.
    """
    n = next(_next_user)
    malicious_raw = (app_module.SAMPLES / "phish-0ffice365.eml").read_text(
        encoding="utf-8").replace("0ffice365-secure.com", f"evil{n}.example")
    clean_raw = (app_module.SAMPLES / "clean-notification.eml").read_text(
        encoding="utf-8").replace("github.com", f"clean{n}.example")

    def titles(case):
        return {f["title"] for f in case["findings"]}

    case1 = _signed_in_client().post(
        "/api/scan", json={"raw": malicious_raw, "offline": True}).json()
    assert "Repeat offender" not in titles(case1)

    case2 = _signed_in_client().post(
        "/api/scan", json={"raw": malicious_raw, "offline": True}).json()
    assert "Repeat offender" in titles(case2)

    case3 = _signed_in_client().post(
        "/api/scan", json={"raw": clean_raw, "offline": True}).json()
    assert "Repeat offender" not in titles(case3)

    case4 = _signed_in_client().post(
        "/api/scan", json={"raw": clean_raw, "offline": True}).json()
    assert "Repeat offender" not in titles(case4)
    assert "Known sender" in titles(case4)


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
    when the scan itself runs. It does, however, require that a scan
    actually happened: with no recorded AI use there's nothing to retry,
    and an ungated endpoint would be a free side door to the AI."""
    c = _signed_in_client()
    monkeypatch.setattr(app_module.ai, "is_configured", lambda: True)
    monkeypatch.setattr(app_module.ai, "analyze_case", lambda case: {
        "verdict": "MALICIOUS", "confidence": "HIGH",
        "summary": "stub", "actions": []})

    payload = {"case": {"verdict": "MALICIOUS"}}
    # No scan yet -> nothing to retry.
    assert c.post("/api/explain", json=payload).status_code == 400

    raw = (app_module.SAMPLES / "phish-0ffice365.eml").read_text(encoding="utf-8")
    assert c.post("/api/scan", json={"raw": raw}).status_code == 200

    # Retries after a real scan are unmetered, even past the daily limit.
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


# ------------------------------------------------------------- security

def test_security_headers_on_every_response():
    r = client.get("/")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    assert "frame-ancestors 'none'" in r.headers["Content-Security-Policy"]
    assert r.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"


def test_api_responses_are_never_cacheable():
    # Behind a CDN, a cached per-user API response served to the wrong
    # person is a cross-user data leak. Every /api/ response must opt out.
    for path in ("/api/me", "/api/stats", "/api/config"):
        assert client.get(path).headers["Cache-Control"] == "no-store", path


def test_oversized_scan_rejected():
    c = _signed_in_client()
    r = c.post("/api/scan", json={"raw": "x" * 2_000_000, "offline": True})
    assert r.status_code == 413


def test_history_is_isolated_between_users():
    """User B must never see user A's cases: every history/stats query is
    scoped to the session's own user id."""
    a, b = _signed_in_client(), _signed_in_client()
    raw = (app_module.SAMPLES / "phish-0ffice365.eml").read_text(encoding="utf-8")
    case = a.post("/api/scan", json={"raw": raw, "offline": True}).json()

    a_ids = {s["case_id"] for s in a.get("/api/history").json()["scans"]}
    b_ids = {s["case_id"] for s in b.get("/api/history").json()["scans"]}
    assert case["case_id"] in a_ids
    assert case["case_id"] not in b_ids
    assert b.get("/api/my/stats").json()["scans"] == 0


# ------------------------------------------------- streaming scan (websocket)

@contextlib.asynccontextmanager
async def _fake_browser():
    """Stands in for a real Chromium so detonation paths can be exercised
    on a machine with no browser installed."""
    yield object()


def _drain_ws(ws) -> list[dict]:
    """Collect every event up to and including the terminal one."""
    events = []
    while True:
        msg = ws.receive_json()
        events.append(msg)
        if msg["type"] in ("scan_complete", "error"):
            return events


def test_ws_scan_requires_auth():
    """An unauthenticated socket must be closed, not served."""
    from starlette.websockets import WebSocketDisconnect
    try:
        with client.websocket_connect("/ws/scan") as ws:
            ws.receive_json()
        raise AssertionError("unauthenticated websocket was not closed")
    except WebSocketDisconnect as e:
        assert e.code == 1008


def test_ws_scan_streams_stages_then_the_same_case_as_post():
    """The streaming endpoint is the POST endpoint with progress events in
    front of it: the stages must arrive in order and the final case must
    match what /api/scan produces for the same message."""
    c = _signed_in_client()
    raw = (app_module.SAMPLES / "phish-0ffice365.eml").read_text(encoding="utf-8")

    with c.websocket_connect("/ws/scan") as ws:
        ws.send_json({"raw": raw, "offline": True})
        events = _drain_ws(ws)

    kinds = [e["type"] for e in events]
    assert kinds[-1] == "scan_complete"
    # The progress callback fires from a worker thread; if it were dropped
    # (e.g. an un-awaited coroutine) these stages would simply never arrive.
    for stage in ("parse_started", "urls_extracted",
                  "reputation_check_started", "reputation_check_completed"):
        assert stage in kinds, f"missing {stage}: {kinds}"
    assert kinds.index("parse_started") < kinds.index("urls_extracted")
    assert kinds.index("urls_extracted") < kinds.index("reputation_check_started")

    urls_event = events[kinds.index("urls_extracted")]["data"]
    assert urls_event["count"] >= 1
    assert urls_event["urls"][0]["domain"]

    case = events[-1]["data"]
    expected = _signed_in_client().post(
        "/api/scan", json={"raw": raw, "offline": True}).json()
    assert case["verdict"] == expected["verdict"] == "MALICIOUS"
    assert case["score"] == expected["score"]
    assert case["report_markdown"]

    # ...and it landed in history, same as a POST scan would.
    assert any(s["case_id"] == case["case_id"]
               for s in c.get("/api/history").json()["scans"])


def test_ws_scan_skips_sandbox_when_playwright_is_missing(monkeypatch):
    """Playwright is an optional dependency: with no browser installed the
    scan must still finish rather than erroring or hanging on that stage."""
    monkeypatch.setattr(app_module.sandbox, "is_available", lambda: False)
    c = _signed_in_client()
    raw = (app_module.SAMPLES / "phish-0ffice365.eml").read_text(encoding="utf-8")

    with c.websocket_connect("/ws/scan") as ws:
        ws.send_json({"raw": raw, "offline": False})
        events = _drain_ws(ws)

    kinds = [e["type"] for e in events]
    assert kinds[-1] == "scan_complete"
    assert "sandbox_starting" not in kinds
    assert "sandbox" not in events[-1]["data"]


def test_ws_scan_offline_never_opens_links(monkeypatch):
    """Offline mode is a promise that nothing leaves this machine, so it must
    suppress detonation even when a browser IS available."""
    monkeypatch.setattr(app_module.sandbox, "is_available", lambda: True)

    async def _boom(*a, **kw):
        raise AssertionError("offline scan attempted to open a link")
    monkeypatch.setattr(app_module.sandbox, "detonate", _boom)

    c = _signed_in_client()
    raw = (app_module.SAMPLES / "phish-0ffice365.eml").read_text(encoding="utf-8")
    with c.websocket_connect("/ws/scan") as ws:
        ws.send_json({"raw": raw, "offline": True})
        events = _drain_ws(ws)
    assert events[-1]["type"] == "scan_complete"


def test_ws_scan_detonation_findings_change_the_verdict(monkeypatch):
    """A sandbox hit has to actually move the case: its finding is added and
    the score/verdict recomputed, not left at the pre-sandbox value."""
    monkeypatch.setattr(app_module.sandbox, "is_available", lambda: True)
    monkeypatch.setattr(app_module.sandbox, "browser_session", _fake_browser)

    async def _fake(url, timeout_ms=0, browser=None):
        return {"url": url, "landed_on": "evil.example", "title": "Sign in",
                "threat_level": "malicious", "screenshot": None, "error": "",
                "threat_signals": ["asks for credentials on a domain the link "
                                   "didn't claim to go to"],
                "observations": ["collects password"]}
    monkeypatch.setattr(app_module.sandbox, "detonate", _fake)

    c = _signed_in_client()
    raw = (app_module.SAMPLES / "clean-notification.eml").read_text(encoding="utf-8")
    with c.websocket_connect("/ws/scan") as ws:
        ws.send_json({"raw": raw, "offline": False})
        events = _drain_ws(ws)

    kinds = [e["type"] for e in events]
    assert "sandbox_starting" in kinds
    assert "sandbox_url_result" in kinds

    case = events[-1]["data"]
    assert any(f["category"] == "sandbox" for f in case["findings"])
    assert case["verdict"] in ("SUSPICIOUS", "MALICIOUS")
    # Screenshots are streamed for display but must not bloat the stored case.
    assert all("screenshot" not in entry for entry in case["sandbox"])


def test_post_scan_also_detonates_links(monkeypatch):
    """Firebase Hosting doesn't forward websocket upgrades, so for anyone on
    the public domain the POST endpoint is the only path that runs. Gating
    detonation on the transport would make the sandbox unreachable for real
    users, so /api/scan has to detonate too."""
    monkeypatch.setattr(app_module.sandbox, "is_available", lambda: True)
    monkeypatch.setattr(app_module.sandbox, "browser_session", _fake_browser)

    async def _fake(url, timeout_ms=0, browser=None):
        return {"url": url, "landed_on": "evil.example", "title": "Sign in",
                "threat_level": "malicious", "error": "",
                "screenshot": "Zm9v", "observations": ["collects password"],
                "threat_signals": ["asks for credentials on a domain the link "
                                   "didn't claim to go to"]}
    monkeypatch.setattr(app_module.sandbox, "detonate", _fake)

    c = _signed_in_client()
    raw = (app_module.SAMPLES / "clean-notification.eml").read_text(encoding="utf-8")
    case = c.post("/api/scan", json={"raw": raw, "offline": False}).json()

    assert any(f["category"] == "sandbox" for f in case["findings"])
    assert case["verdict"] in ("SUSPICIOUS", "MALICIOUS")
    assert case["sandbox"] and "screenshot" not in case["sandbox"][0]
    # Screenshots ride alongside for display rather than inside the case.
    assert case["sandbox_screenshots"][0]["screenshot"] == "Zm9v"


def test_post_scan_offline_never_opens_links(monkeypatch):
    monkeypatch.setattr(app_module.sandbox, "is_available", lambda: True)
    monkeypatch.setattr(app_module.sandbox, "browser_session", _fake_browser)

    async def _boom(*a, **kw):
        raise AssertionError("offline scan attempted to open a link")
    monkeypatch.setattr(app_module.sandbox, "detonate", _boom)

    c = _signed_in_client()
    raw = (app_module.SAMPLES / "phish-0ffice365.eml").read_text(encoding="utf-8")
    r = c.post("/api/scan", json={"raw": raw, "offline": True})
    assert r.status_code == 200
    assert "sandbox" not in r.json()


def test_ws_scan_rejects_oversized_input():
    c = _signed_in_client()
    with c.websocket_connect("/ws/scan") as ws:
        ws.send_json({"raw": "x" * 2_000_000, "offline": True})
        msg = ws.receive_json()
    assert msg["type"] == "error"
    assert "too large" in msg["message"]


def test_expired_sessions_are_purged():
    n = next(_next_user)
    user = db.upsert_google_user(f"purge{n}@example.com", "Purge", f"sub-p{n}")
    token = db.create_session(user["id"])
    with db._connect() as conn:
        conn.execute("UPDATE sessions SET expires_at = '2000-01-01T00:00:00'"
                     " WHERE token = ?", (token,))
    db.purge_stale()
    assert db.user_for_session(token) is None
    with db._connect() as conn:
        row = conn.execute("SELECT 1 FROM sessions WHERE token = ?",
                           (token,)).fetchone()
    assert row is None
