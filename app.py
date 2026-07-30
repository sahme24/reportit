"""ReportIT.ai web app: landing, Google sign-in, scanner, history, dashboard.

Run:  uvicorn app:app --reload
Then open http://127.0.0.1:8000

Sign-in is Google-only. Create OAuth credentials at
https://console.cloud.google.com/apis/credentials (Web application; add
<your-url>/auth/google/callback as an authorized redirect URI) and put
GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET in .env.
"""

from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path
from urllib.parse import urlencode, urlparse

import anthropic
import requests as http
from fastapi import (Cookie, Depends, FastAPI, HTTPException, Request,
                     Response, WebSocket, WebSocketDisconnect)
from fastapi.responses import FileResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from threadline import ai, db, sandbox
from threadline.advice import advice_for
from threadline.models import OK, WARN, Finding
from threadline.report import markdown_report
from threadline.reputation import load_dotenv
from threadline.scanner import _SEV_ORDER, _verdict, scan
from threadline.sms import scan_sms

load_dotenv()

app = FastAPI(title="ReportIT.ai", version="0.4.0")
STATIC = Path(__file__).parent / "static"
SAMPLES = Path(__file__).parent / "samples"
logger = logging.getLogger(__name__)

db.init_db()
app.mount("/static", StaticFiles(directory=STATIC), name="static")

# The one public domain this app should ever be used from (Firebase Hosting
# proxies to Cloud Run). Derived from OAUTH_REDIRECT_URL so it's unset -- and
# this redirect a no-op -- in local dev.
_CANONICAL_HOST = (
    urlparse(os.environ["OAUTH_REDIRECT_URL"]).hostname
    if os.environ.get("OAUTH_REDIRECT_URL") else None
)


@app.middleware("http")
async def canonicalize_host(request: Request, call_next):
    """Redirect any request that didn't arrive via the canonical domain
    before it reaches a route. Without this, someone who lands on the raw
    Cloud Run URL gets their OAuth state cookie scoped to *that* origin,
    but Google then sends them back to the callback pinned at
    OAUTH_REDIRECT_URL -- a different origin -- so the cookie never comes
    back and sign-in fails with a state mismatch."""
    if _CANONICAL_HOST:
        host = (request.headers.get("x-forwarded-host")
               or request.url.hostname or "").split(",")[0].strip()
        if host and host != _CANONICAL_HOST:
            target = f"https://{_CANONICAL_HOST}{request.url.path}"
            if request.url.query:
                target += f"?{request.url.query}"
            return RedirectResponse(target, status_code=307)
    return await call_next(request)


# Everything the site needs and nothing more: same-origin by default,
# inline scripts/styles (the pages use them), Google Fonts, data: images
# (favicons/SVG). No frames, no plugins, no cross-origin fetches.
_CSP = ("default-src 'self'; script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; img-src 'self' data:; "
        # ws:/wss: spelled out: 'self' is supposed to cover same-origin
        # WebSockets under CSP3, but enough shipping browsers disagree that
        # the streaming scanner silently fails to connect without this.
        "connect-src 'self' ws: wss:; object-src 'none'; base-uri 'self'; "
        "form-action 'self'; frame-ancestors 'none'")


def _is_https(request: Request) -> bool:
    # Behind Firebase Hosting / Cloud Run the TLS hop terminates upstream,
    # so the original scheme arrives in X-Forwarded-Proto.
    return request.headers.get(
        "x-forwarded-proto", request.url.scheme) == "https"


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    h = response.headers
    h.setdefault("Content-Security-Policy", _CSP)
    h.setdefault("X-Content-Type-Options", "nosniff")
    h.setdefault("X-Frame-Options", "DENY")
    h.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    h.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    if _is_https(request):
        h.setdefault("Strict-Transport-Security",
                     "max-age=31536000; includeSubDomains")
    # Per-user responses must never be cached: this app sits behind a CDN
    # (Firebase Hosting/Fastly), and a cached /api/* response served to the
    # wrong person would be a cross-user data leak. no-store closes that
    # class of bug outright, for every cache between us and the browser.
    if request.url.path.startswith(("/api/", "/auth/")):
        h["Cache-Control"] = "no-store"
    return response


# Firebase Hosting's rewrite to Cloud Run strips every request cookie
# except one literally named "__session" -- this MUST be that name, or
# nobody can stay signed in when the app is accessed via Firebase Hosting.
_COOKIE = "__session"

_GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
_GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
_GOOGLE_TOKENINFO_URL = "https://oauth2.googleapis.com/tokeninfo"


def _google_configured() -> bool:
    return bool(os.environ.get("GOOGLE_CLIENT_ID")
                and os.environ.get("GOOGLE_CLIENT_SECRET"))


def _redirect_uri(request: Request) -> str:
    # OAUTH_REDIRECT_URL wins (needed behind a reverse proxy / custom domain).
    return os.environ.get("OAUTH_REDIRECT_URL") or \
        str(request.base_url).rstrip("/") + "/auth/google/callback"


# --------------------------------------------------------------------------
# Auth plumbing
# --------------------------------------------------------------------------

def current_user(session_cookie: str = Cookie(default="", alias=_COOKIE)) -> dict | None:
    return db.user_for_session(session_cookie)


def require_user(user: dict | None = Depends(current_user)) -> dict:
    if not user:
        raise HTTPException(status_code=401, detail="Sign in to open a case.")
    return user


@app.get("/auth/google")
def auth_google(request: Request) -> RedirectResponse:
    """Kick off the Google OAuth 2.0 authorization-code flow."""
    if not _google_configured():
        return RedirectResponse("/login?error=not_configured")
    # Stored server-side, not in a cookie: Firebase Hosting strips every
    # request cookie except "__session" before it reaches Cloud Run, so a
    # second cookie here would never come back on the callback.
    state = db.create_oauth_state()
    params = urlencode({
        "client_id": os.environ["GOOGLE_CLIENT_ID"],
        "redirect_uri": _redirect_uri(request),
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        # select_account: always show Google's account chooser, even when
        # the browser already has exactly one active Google session. This
        # is a security tool -- a silent, no-confirmation sign-in (which is
        # what Google does by default here) reads as "this site logged me
        # in without asking," which is exactly what happened and alarmed
        # a user testing in what they believed was a clean session.
        "prompt": "select_account",
    })
    return RedirectResponse(f"{_GOOGLE_AUTH_URL}?{params}")


@app.get("/auth/google/callback")
def auth_google_callback(request: Request, code: str = "", state: str = ""
                         ) -> RedirectResponse:
    if not code or not db.consume_oauth_state(state):
        return RedirectResponse("/login?error=state")
    try:
        token = http.post(_GOOGLE_TOKEN_URL, data={
            "code": code,
            "client_id": os.environ["GOOGLE_CLIENT_ID"],
            "client_secret": os.environ["GOOGLE_CLIENT_SECRET"],
            "redirect_uri": _redirect_uri(request),
            "grant_type": "authorization_code",
        }, timeout=10).json()
        # Google validates the id_token's signature server-side for us.
        info = http.get(_GOOGLE_TOKENINFO_URL,
                        params={"id_token": token["id_token"]},
                        timeout=10).json()
    except Exception:
        return RedirectResponse("/login?error=google")

    if info.get("aud") != os.environ["GOOGLE_CLIENT_ID"] \
            or info.get("email_verified") not in ("true", True) \
            or not info.get("email"):
        return RedirectResponse("/login?error=verify")

    user = db.upsert_google_user(info["email"], info.get("name", ""),
                                 info.get("sub", ""))
    response = RedirectResponse("/dashboard")
    # secure=True everywhere except plain-HTTP local dev, so the session
    # token can never travel over an unencrypted connection.
    response.set_cookie(_COOKIE, db.create_session(user["id"]),
                        max_age=db.SESSION_DAYS * 86400,
                        httponly=True, samesite="lax",
                        secure=_is_https(request))
    return response


@app.post("/api/logout")
def api_logout(response: Response,
               session_cookie: str = Cookie(default="", alias=_COOKIE)) -> dict:
    db.delete_session(session_cookie)
    response.delete_cookie(_COOKIE)
    return {"ok": True}


@app.get("/api/me")
def api_me(user: dict | None = Depends(current_user)) -> dict:
    return {"user": user}


# --------------------------------------------------------------------------
# Scanning
# --------------------------------------------------------------------------

class ScanRequest(BaseModel):
    raw: str
    offline: bool = False
    kind: str = "email"    # email | sms
    sender: str = ""       # SMS sender number/address (sms only)


def _sightings_finding(sender: str, urls) -> list[Finding]:
    """Cross-reference this instance's scan history.

    Only a track record of prior MALICIOUS/SUSPICIOUS verdicts for this
    sender/domain counts as a warning sign. Raw appearance count doesn't:
    a high-volume real sender (a bank, a delivery service, a government
    agency) gets scanned by cautious users a lot too, and that should
    never make its legitimate mail look more suspicious over time.
    """
    top_domain = next((u.domain for u in urls if u.domain), "")
    seen = db.prior_sightings(sender, top_domain)
    bad = []
    if seen["sender_bad"]:
        bad.append(f"sender {sender} in {seen['sender_bad']} prior flagged case(s)")
    if seen["domain_bad"]:
        bad.append(f"domain {top_domain} in {seen['domain_bad']} prior flagged case(s)")
    if bad:
        return [Finding(WARN, "Repeat offender",
                        "Seen before on this instance: " + " and ".join(bad) + ".",
                        weight=10, category="history")]
    if seen["sender_total"] or seen["domain_total"]:
        return [Finding(OK, "Known sender",
                        "Seen before on this instance with no prior "
                        "malicious or suspicious verdicts.", category="history")]
    return []


def _email_enrichment(email, urls) -> list[Finding]:
    return _sightings_finding(email.from_addr, urls)


def _sms_enrichment(sender: str, urls) -> list[Finding]:
    return _sightings_finding(sender.strip().lower(), urls)


def _ai_opinion(case_dict: dict) -> dict | None:
    """Independent AI read of a finished case, or None on any failure.
    Fails soft: the heuristic verdict stands alone when this returns None."""
    try:
        return ai.analyze_case(case_dict)
    except Exception:
        return None


# Generous for any real email (most are under 100 KB with headers), but a
# hard stop against someone feeding the parser/OCR multi-hundred-MB blobs.
_MAX_RAW_CHARS = 1_500_000

# Sandbox detonation limits. A newsletter can carry 40 links and each one is a
# real browser page load, so cap the count, run a few at a time, and give any
# single page a hard deadline.
_SANDBOX_MAX_URLS = int(os.environ.get("REPORTIT_SANDBOX_MAX_URLS", "5"))
_SANDBOX_CONCURRENCY = int(os.environ.get("REPORTIT_SANDBOX_CONCURRENCY", "3"))
_SANDBOX_TIMEOUT_MS = int(os.environ.get("REPORTIT_SANDBOX_TIMEOUT_MS", "20000"))
# Base64 chars, ~= 400 KB of JPEG. Bigger screenshots are dropped, not cut.
_SANDBOX_MAX_SHOT_B64 = 550_000


@app.post("/api/scan")
async def api_scan(req: ScanRequest, user: dict = Depends(require_user)) -> dict:
    if not req.raw.strip():
        raise HTTPException(status_code=400, detail="Paste a message first.")
    if len(req.raw) > _MAX_RAW_CHARS:
        raise HTTPException(
            status_code=413,
            detail="That message is too large to scan (1.5 MB limit). "
                   "Paste the headers plus the visible body, not an "
                   "entire mailbox export.")

    # Every online scan runs the full toolset plus the AI analysis as one
    # unit, so the daily quota gates the scan itself, not a separate "AI
    # opinion" add-on. Offline mode (no network/AI at all) stays unmetered.
    ai_enabled = ai.is_configured() and not req.offline
    used = 0
    if ai_enabled:
        used, refresh_at = db.ai_usage(user["id"])
        if used >= _AI_DAILY_LIMIT:
            # Frontend renders refresh_at in the user's local time,
            # Claude/ChatGPT-style ("more scans at 3:45 PM").
            raise HTTPException(
                status_code=429,
                detail={"message": f"You've used your {_AI_DAILY_LIMIT} free "
                                   "scans for today. Each one frees up 24 "
                                   "hours after it ran.",
                        "refresh_at": refresh_at})

    # Off the event loop: scan() is synchronous and does blocking network I/O,
    # so running it inline would stall every other request on this worker.
    if req.kind == "sms":
        case = await asyncio.to_thread(
            scan_sms, req.raw, sender=req.sender, offline=req.offline,
            enrich=_sms_enrichment)
    else:
        case = await asyncio.to_thread(
            scan, req.raw, offline=req.offline, enrich=_email_enrichment)

    # Links get detonated here too, not only on the streaming endpoint.
    # Firebase Hosting doesn't forward WebSocket upgrades, so for anyone on
    # the public domain this is the only path that runs -- gating the sandbox
    # on the transport would make it unreachable for real users.
    sandbox_results = await _detonate_case(case, req.offline)

    result = await asyncio.to_thread(
        _finalize_case, case, user, ai_enabled, used)
    if sandbox_results:
        result["sandbox"] = [{k: v for k, v in r.items() if k != "screenshot"}
                             for r in sandbox_results]
        result["sandbox_screenshots"] = [
            {"landed_on": r.get("landed_on", ""),
             "screenshot": r["screenshot"]}
            for r in sandbox_results
            if r.get("screenshot")
            and len(r["screenshot"]) <= _SANDBOX_MAX_SHOT_B64]
    return result


def _finalize_case(case, user: dict, ai_enabled: bool, used: int) -> dict:
    """AI pass, report, quota accounting, persistence -> the response dict.

    Shared by the POST endpoint and the WebSocket one so the two can't drift
    into producing different results for the same message.
    """
    opinion = None
    if ai_enabled:
        db.record_ai_use(user["id"])
        opinion = _ai_opinion(case.to_dict())
        if opinion:
            # The AI verdict becomes THE verdict, not a second one shown
            # next to the heuristic score, so there's only ever one result
            # on screen. Recompute the advice list so it matches too.
            case.verdict = opinion["verdict"]
            case.confidence = opinion["confidence"]
            case.recommendations = advice_for(case.kind, case.verdict, case.findings)

    result = case.to_dict()
    result["report_markdown"] = markdown_report(
        case, reporter=user, ai_summary=opinion["summary"] if opinion else None)
    if opinion:
        result["ai_opinion"] = {"summary": opinion["summary"],
                                "actions": opinion["actions"]}
        result["uses_left"] = max(_AI_DAILY_LIMIT - used - 1, 0)

    db.record_scan(user["id"], result)
    return result


# Sentinel: the client hung up mid-detonation, so stop rather than finish.
_ABORTED = object()


async def _detonate_case(case, offline: bool, on_result=None):
    """Open the case's links in a sandbox, fold the results into the case.

    Shared by both scan endpoints. `on_result(url_info, result)` is awaited per
    link for streaming callers and may return False to abort; POST callers pass
    nothing. Returns the raw per-link results, or `_ABORTED`.

    Detonation is skipped entirely for offline scans -- opening a link reveals
    this server's IP to the sender and confirms the message was read, which is
    exactly what offline mode promises not to do.
    """
    if offline or not (sandbox.is_available() and case.urls):
        return []

    targets = case.urls[:_SANDBOX_MAX_URLS]
    if on_result and not await on_result(None, {"_starting": len(targets)}):
        return _ABORTED

    results: list[dict] = []
    limiter = asyncio.Semaphore(_SANDBOX_CONCURRENCY)
    aborted = False
    try:
        # One browser for the batch, a context per link: a browser per URL is
        # hundreds of MB each and OOMs the container.
        async with sandbox.browser_session() as browser:

            async def run_one(url_info):
                async with limiter:
                    return url_info, await sandbox.detonate(
                        url_info.url, timeout_ms=_SANDBOX_TIMEOUT_MS,
                        browser=browser)

            for coro in asyncio.as_completed([run_one(u) for u in targets]):
                try:
                    url_info, res = await coro
                except Exception as e:
                    logger.warning("detonation task failed: %s", e)
                    continue
                results.append(res)
                finding = sandbox.sandbox_finding(res, url_info.defanged)
                if finding:
                    case.findings.append(finding)
                if on_result and not await on_result(url_info, res):
                    aborted = True
                    break
    except Exception as e:
        # No browser on this host, or it died mid-batch. The scan still has
        # every non-sandbox finding, so finish it rather than failing.
        logger.warning("sandbox stage unavailable: %s", e)

    if aborted:
        return _ABORTED

    if results:
        # Findings changed, so score and verdict have to be recomputed rather
        # than left at whatever the pre-sandbox pass decided.
        case.findings.sort(key=lambda f: _SEV_ORDER.get(f.severity, 9))
        case.score = min(sum(f.weight for f in case.findings), 100)
        case.verdict, case.confidence = _verdict(case.score)
        case.recommendations = advice_for(case.kind, case.verdict, case.findings)
    return results


@app.websocket("/ws/scan")
async def ws_scan(websocket: WebSocket,
                  session_cookie: str = Cookie(default="", alias=_COOKIE)):
    """Streaming version of /api/scan.

    Same inputs, same final result -- the difference is that the stages
    report as they finish instead of the caller waiting on one long POST,
    and that links get detonated in a sandbox when Playwright is installed.
    """
    user = db.user_for_session(session_cookie)
    if not user:
        # Policy violation close code; the browser sees it as a clean close.
        await websocket.close(code=1008)
        return
    await websocket.accept()

    async def send(kind: str, **payload) -> bool:
        """Send one event. False once the socket is gone, so callers stop."""
        try:
            await websocket.send_json({"type": kind, **payload})
            return True
        except (WebSocketDisconnect, RuntimeError):
            return False

    try:
        req = await websocket.receive_json()
    except (WebSocketDisconnect, ValueError):
        return

    raw = (req.get("raw") or "")
    kind = req.get("kind") or "email"
    offline = bool(req.get("offline"))
    sender = req.get("sender") or ""

    if not raw.strip():
        await send("error", message="Paste a message first.")
        await websocket.close()
        return
    if len(raw) > _MAX_RAW_CHARS:
        await send("error",
                   message="That message is too large to scan (1.5 MB limit). "
                           "Paste the headers plus the visible body, not an "
                           "entire mailbox export.")
        await websocket.close()
        return

    ai_enabled = ai.is_configured() and not offline
    used = 0
    if ai_enabled:
        used, refresh_at = db.ai_usage(user["id"])
        if used >= _AI_DAILY_LIMIT:
            await send("error",
                       message=f"You've used your {_AI_DAILY_LIMIT} free scans "
                               "for today. Each one frees up 24 hours after it "
                               "ran.",
                       refresh_at=refresh_at)
            await websocket.close()
            return

    loop = asyncio.get_running_loop()
    events: asyncio.Queue = asyncio.Queue()

    def on_progress(step: str, data: dict) -> None:
        """Called from the scan worker THREAD, so hand off thread-safely
        rather than touching the socket or the loop directly."""
        loop.call_soon_threadsafe(events.put_nowait, (step, data))

    async def pump() -> None:
        while True:
            item = await events.get()
            if item is None:
                return
            step, data = item
            if not await send(step, data=data):
                return

    pump_task = asyncio.create_task(pump())
    try:
        # scan()/scan_sms() are synchronous and do blocking network I/O. Run
        # them off the event loop or every other request on this worker --
        # including other people's scans -- stalls until this one finishes.
        if kind == "sms":
            case = await asyncio.to_thread(
                scan_sms, raw, sender=sender, offline=offline,
                enrich=_sms_enrichment, on_progress=on_progress)
        else:
            case = await asyncio.to_thread(
                scan, raw, offline=offline, enrich=_email_enrichment,
                on_progress=on_progress)
    except Exception as e:
        logger.exception("scan failed")
        events.put_nowait(None)
        await pump_task
        await send("error", message=f"Scan failed: {type(e).__name__}")
        await websocket.close()
        return
    finally:
        if not pump_task.done():
            events.put_nowait(None)
            await pump_task

    # --- sandbox detonation ------------------------------------------------
    # Opening attacker-controlled links is deliberately opt-in-by-deployment:
    # it reveals this server's IP to the sender and confirms the message was
    # opened, so it only runs when Playwright is installed and the user
    # didn't ask for an offline scan.
    async def _emit_shot(url_info, res) -> bool:
        if url_info is None:      # batch is starting
            return await send("sandbox_starting",
                              data={"url_count": res["_starting"]})
        # A JPEG screenshot is ~40-150 KB of base64. Send it when it's
        # reasonable and drop it when it isn't -- never truncate, since a
        # sliced base64 string decodes to a broken image.
        shot = res.get("screenshot")
        if shot and len(shot) > _SANDBOX_MAX_SHOT_B64:
            shot = None
        return await send("sandbox_url_result", data={
            "url": url_info.defanged,
            "domain": url_info.domain,
            "landed_on": res.get("landed_on", ""),
            "title": res.get("title", ""),
            "threat_level": res.get("threat_level", "none"),
            "threat_signals": res.get("threat_signals", []),
            "observations": res.get("observations", []),
            "error": res.get("error", ""),
            "screenshot": shot})

    sandbox_results = await _detonate_case(case, offline, on_result=_emit_shot)
    if sandbox_results is _ABORTED:
        return

    if not await send("ai_started", data={"enabled": ai_enabled}):
        return

    try:
        result = await asyncio.to_thread(
            _finalize_case, case, user, ai_enabled, used)
    except Exception as e:
        logger.exception("finalize failed")
        await send("error", message=f"Scan failed: {type(e).__name__}")
        await websocket.close()
        return

    if sandbox_results:
        result["sandbox"] = [
            {k: v for k, v in r.items() if k != "screenshot"}
            for r in sandbox_results]

    await send("scan_complete", data=result)
    await websocket.close()


@app.get("/api/history")
def api_history(user: dict = Depends(require_user)) -> dict:
    return {"scans": db.user_scans(user["id"])}


@app.get("/api/my/stats")
def api_my_stats(user: dict = Depends(require_user)) -> dict:
    """Personal dashboard: the user's own numbers + instance totals."""
    stats = db.user_stats(user["id"])
    used, refresh_at = db.ai_usage(user["id"])
    stats["ai_enabled"] = ai.is_configured()
    stats["ai_uses_left"] = max(_AI_DAILY_LIMIT - used, 0)
    stats["ai_limit"] = _AI_DAILY_LIMIT
    stats["ai_refresh_at"] = refresh_at
    stats["recent"] = db.user_scans(user["id"], limit=5)
    stats["instance"] = db.public_stats()
    return stats


@app.get("/api/sample/{name}")
def api_sample(name: str) -> PlainTextResponse:
    safe = {"phish": "phish-0ffice365.eml", "clean": "clean-notification.eml",
            "smish": "smish-cra.txt"}
    if name not in safe:
        raise HTTPException(status_code=404, detail="unknown sample")
    return PlainTextResponse((SAMPLES / safe[name]).read_text(encoding="utf-8"))


# --------------------------------------------------------------------------
# Stats
# --------------------------------------------------------------------------

# Free AI analyses per user per UTC day (keeps API costs predictable).
_AI_DAILY_LIMIT = int(os.environ.get("REPORTIT_AI_DAILY_LIMIT", "3"))


@app.get("/api/config")
def api_config() -> dict:
    """What optional integrations are configured on this instance."""
    return {"google": _google_configured(), "ai": ai.is_configured(),
            "ai_daily_limit": _AI_DAILY_LIMIT}


class ExplainRequest(BaseModel):
    case: dict


@app.post("/api/explain")
def api_explain(req: ExplainRequest, user: dict = Depends(require_user)) -> dict:
    """Retries the AI portion of an already-scanned case, e.g. after a
    transient API hiccup during the original scan. Doesn't touch the daily
    quota: that's spent once when the scan itself runs, not per AI call."""
    if not ai.is_configured():
        raise HTTPException(
            status_code=503,
            detail="The AI analyst isn't configured on this server. Add an "
                   "ANTHROPIC_API_KEY to .env to enable it.")
    # This endpoint exists only to retry a scan that already spent a quota
    # slot. Requiring a recorded use in the window (and a sane payload
    # size) stops it from being a free, unmetered side door to the AI.
    if len(str(req.case)) > 100_000:
        raise HTTPException(status_code=413, detail="Case payload too large.")
    used, _ = db.ai_usage(user["id"])
    if used == 0:
        raise HTTPException(
            status_code=400,
            detail="Nothing to retry: run a scan first.")
    try:
        return ai.analyze_case(req.case)
    except anthropic.RateLimitError:
        raise HTTPException(status_code=429,
                            detail="The AI analyst is busy. Try again in a "
                                   "minute.")
    except anthropic.APIStatusError as e:
        raise HTTPException(status_code=502,
                            detail=f"AI analyst error ({e.status_code}).")
    except anthropic.APIConnectionError:
        raise HTTPException(status_code=502,
                            detail="Couldn't reach the AI analyst. Check the "
                                   "server's network connection.")


@app.get("/api/stats")
def api_stats() -> dict:
    return db.public_stats()


# --------------------------------------------------------------------------
# Pages
# --------------------------------------------------------------------------

_PAGES = {"/": "index.html", "/login": "auth.html", "/scan": "scan.html",
          "/history": "history.html", "/dashboard": "dashboard.html"}


@app.get("/")
def page_index() -> FileResponse:
    return FileResponse(STATIC / "index.html")


@app.get("/login")
def page_login() -> FileResponse:
    return FileResponse(STATIC / "auth.html")


@app.get("/scan")
def page_scan() -> FileResponse:
    return FileResponse(STATIC / "scan.html")


@app.get("/history")
def page_history() -> FileResponse:
    return FileResponse(STATIC / "history.html")


@app.get("/dashboard")
def page_dashboard() -> FileResponse:
    return FileResponse(STATIC / "dashboard.html")
