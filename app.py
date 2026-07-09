"""Threadline web app — landing, auth, scanner, history, and admin dashboard.

Run:  uvicorn app:app --reload
Then open http://127.0.0.1:8000

The first account created on a fresh database becomes the admin.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import Cookie, Depends, FastAPI, HTTPException, Response
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from threadline import db
from threadline.models import WARN, Finding
from threadline.report import markdown_report
from threadline.scanner import scan

app = FastAPI(title="ReportIT.ai", version="0.3.0")
STATIC = Path(__file__).parent / "static"
SAMPLES = Path(__file__).parent / "samples"

db.init_db()
app.mount("/static", StaticFiles(directory=STATIC), name="static")

_COOKIE = "threadline_session"


# --------------------------------------------------------------------------
# Auth plumbing
# --------------------------------------------------------------------------

def current_user(threadline_session: str = Cookie(default="")) -> dict | None:
    return db.user_for_session(threadline_session)


def require_user(user: dict | None = Depends(current_user)) -> dict:
    if not user:
        raise HTTPException(status_code=401, detail="Sign in to open a case.")
    return user


def require_admin(user: dict = Depends(require_user)) -> dict:
    if not user["is_admin"]:
        raise HTTPException(status_code=403, detail="Admin access required.")
    return user


def _start_session(response: Response, user: dict) -> dict:
    token = db.create_session(user["id"])
    response.set_cookie(_COOKIE, token, max_age=db.SESSION_DAYS * 86400,
                        httponly=True, samesite="lax")
    return {"user": user}


class SignupRequest(BaseModel):
    name: str = ""
    email: str
    password: str


class LoginRequest(BaseModel):
    email: str
    password: str


@app.post("/api/signup")
def api_signup(req: SignupRequest, response: Response) -> dict:
    user, error = db.create_user(req.email, req.name, req.password)
    if error:
        raise HTTPException(status_code=400, detail=error)
    return _start_session(response, user)


@app.post("/api/login")
def api_login(req: LoginRequest, response: Response) -> dict:
    user = db.verify_user(req.email, req.password)
    if not user:
        raise HTTPException(status_code=401, detail="Wrong email or password.")
    return _start_session(response, user)


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


def _history_enrichment(email, urls) -> list[Finding]:
    """Cross-reference this instance's scan history — roadmap v2 feature."""
    top_domain = next((u.domain for u in urls if u.domain), "")
    seen = db.prior_sightings(email.from_addr, top_domain)
    findings = []
    if seen["sender"] or seen["domain"]:
        what = []
        if seen["sender"]:
            what.append(f"sender {email.from_addr} in {seen['sender']} previous case(s)")
        if seen["domain"]:
            what.append(f"domain {top_domain} in {seen['domain']} previous case(s)")
        findings.append(Finding(
            WARN, "Repeat offender",
            "Seen before on this instance: " + " and ".join(what) + ".",
            weight=10, category="history"))
    return findings


@app.post("/api/scan")
def api_scan(req: ScanRequest, user: dict = Depends(require_user)) -> dict:
    if not req.raw.strip():
        raise HTTPException(status_code=400, detail="Paste a raw email first.")
    case = scan(req.raw, offline=req.offline, enrich=_history_enrichment)
    result = case.to_dict()
    result["report_markdown"] = markdown_report(case)
    db.record_scan(user["id"], result)
    return result


@app.get("/api/history")
def api_history(user: dict = Depends(require_user)) -> dict:
    return {"scans": db.user_scans(user["id"])}


@app.get("/api/sample/{name}")
def api_sample(name: str) -> PlainTextResponse:
    safe = {"phish": "phish-0ffice365.eml", "clean": "clean-notification.eml"}
    if name not in safe:
        raise HTTPException(status_code=404, detail="unknown sample")
    return PlainTextResponse((SAMPLES / safe[name]).read_text(encoding="utf-8"))


# --------------------------------------------------------------------------
# Stats
# --------------------------------------------------------------------------

@app.get("/api/stats")
def api_stats() -> dict:
    return db.public_stats()


@app.get("/api/admin/stats")
def api_admin_stats(user: dict = Depends(require_admin)) -> dict:
    return db.admin_stats()


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
