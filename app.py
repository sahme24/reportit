"""ReportIT.ai web app: landing, Google sign-in, scanner, history, dashboard.

Run:  uvicorn app:app --reload
Then open http://127.0.0.1:8000

Sign-in is Google-only. Create OAuth credentials at
https://console.cloud.google.com/apis/credentials (Web application; add
<your-url>/auth/google/callback as an authorized redirect URI) and put
GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET in .env.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path
from urllib.parse import urlencode

import anthropic
import requests as http
from fastapi import Cookie, Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from threadline import ai, db
from threadline.advice import advice_for
from threadline.models import WARN, Finding
from threadline.report import markdown_report
from threadline.reputation import load_dotenv
from threadline.scanner import scan
from threadline.sms import scan_sms

load_dotenv()

app = FastAPI(title="ReportIT.ai", version="0.4.0")
STATIC = Path(__file__).parent / "static"
SAMPLES = Path(__file__).parent / "samples"

db.init_db()
app.mount("/static", StaticFiles(directory=STATIC), name="static")

_COOKIE = "threadline_session"
_STATE_COOKIE = "reportit_oauth_state"

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

def current_user(threadline_session: str = Cookie(default="")) -> dict | None:
    return db.user_for_session(threadline_session)


def require_user(user: dict | None = Depends(current_user)) -> dict:
    if not user:
        raise HTTPException(status_code=401, detail="Sign in to open a case.")
    return user


@app.get("/auth/google")
def auth_google(request: Request) -> RedirectResponse:
    """Kick off the Google OAuth 2.0 authorization-code flow."""
    if not _google_configured():
        return RedirectResponse("/login?error=not_configured")
    state = secrets.token_urlsafe(24)
    params = urlencode({
        "client_id": os.environ["GOOGLE_CLIENT_ID"],
        "redirect_uri": _redirect_uri(request),
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        # No "prompt" param: forcing select_account makes Google show its
        # full account-chooser screen (every signed-in Google identity in
        # the browser, name + email) on every login. Without it, Google
        # silently uses the browser's existing session when there's only
        # one, which is what most people expect from "Sign in with Google".
    })
    response = RedirectResponse(f"{_GOOGLE_AUTH_URL}?{params}")
    response.set_cookie(_STATE_COOKIE, state, max_age=600,
                        httponly=True, samesite="lax")
    return response


@app.get("/auth/google/callback")
def auth_google_callback(request: Request, code: str = "", state: str = "",
                         reportit_oauth_state: str = Cookie(default="")
                         ) -> RedirectResponse:
    if not code or not state or state != reportit_oauth_state:
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
    response.set_cookie(_COOKIE, db.create_session(user["id"]),
                        max_age=db.SESSION_DAYS * 86400,
                        httponly=True, samesite="lax")
    response.delete_cookie(_STATE_COOKIE)
    return response


@app.post("/api/logout")
def api_logout(response: Response,
               threadline_session: str = Cookie(default="")) -> dict:
    db.delete_session(threadline_session)
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
    """Cross-reference this instance's scan history (roadmap v2 feature)."""
    top_domain = next((u.domain for u in urls if u.domain), "")
    seen = db.prior_sightings(sender, top_domain)
    if not (seen["sender"] or seen["domain"]):
        return []
    what = []
    if seen["sender"]:
        what.append(f"sender {sender} in {seen['sender']} previous case(s)")
    if seen["domain"]:
        what.append(f"domain {top_domain} in {seen['domain']} previous case(s)")
    return [Finding(WARN, "Repeat offender",
                    "Seen before on this instance: " + " and ".join(what) + ".",
                    weight=10, category="history")]


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


@app.post("/api/scan")
def api_scan(req: ScanRequest, user: dict = Depends(require_user)) -> dict:
    if not req.raw.strip():
        raise HTTPException(status_code=400, detail="Paste a message first.")

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

    if req.kind == "sms":
        case = scan_sms(req.raw, sender=req.sender, offline=req.offline,
                        enrich=_sms_enrichment)
    else:
        case = scan(req.raw, offline=req.offline, enrich=_email_enrichment)

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
