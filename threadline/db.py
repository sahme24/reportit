"""SQLite storage: users, sessions, and scan history.

Single-file database (threadline.db by default, THREADLINE_DB to override).
Sign-in is Google-only: no passwords are stored, just the verified Google
identity (email, name, subject id) and a session token.
"""

from __future__ import annotations

import os
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

_DB_PATH = Path(os.environ.get("THREADLINE_DB", "threadline.db"))
SESSION_DAYS = 30

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    pw_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    is_admin INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER REFERENCES users(id),
    case_id TEXT NOT NULL,
    verdict TEXT NOT NULL,
    confidence TEXT NOT NULL,
    score INTEGER NOT NULL,
    from_addr TEXT,
    subject TEXT,
    top_domain TEXT,
    bad_findings INTEGER NOT NULL DEFAULT 0,
    kind TEXT NOT NULL DEFAULT 'email',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_user ON scans(user_id, created_at);
CREATE INDEX IF NOT EXISTS idx_scans_sender ON scans(from_addr);
CREATE INDEX IF NOT EXISTS idx_scans_domain ON scans(top_domain);
CREATE TABLE IF NOT EXISTS ai_uses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ai_uses_user ON ai_uses(user_id, created_at);
CREATE TABLE IF NOT EXISTS oauth_states (
    state TEXT PRIMARY KEY,
    created_at TEXT NOT NULL
);
"""

_OAUTH_STATE_MAX_AGE = timedelta(minutes=10)


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(_DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    with _connect() as conn:
        conn.executescript(_SCHEMA)
        # migration for databases created before SMS support
        try:
            conn.execute("ALTER TABLE scans ADD COLUMN kind TEXT NOT NULL"
                         " DEFAULT 'email'")
        except sqlite3.OperationalError:
            pass  # column already exists
        # migration for databases created before Google-only sign-in
        try:
            conn.execute("ALTER TABLE users ADD COLUMN google_sub TEXT")
        except sqlite3.OperationalError:
            pass  # column already exists


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# --------------------------------------------------------------------------
# Users & sessions
# --------------------------------------------------------------------------

def upsert_google_user(email: str, name: str, google_sub: str) -> dict:
    """Create or link an account from a verified Google identity.

    Accounts that existed before the Google-only switch are linked by email,
    so they keep their scan history and admin flag. The first account ever
    created on the instance becomes the admin.
    """
    email = email.strip().lower()
    with _connect() as conn:
        row = conn.execute("SELECT * FROM users WHERE email = ?",
                           (email,)).fetchone()
        if row:
            conn.execute(
                "UPDATE users SET google_sub = ?, name = ? WHERE id = ?",
                (google_sub, name.strip() or row["name"], row["id"]))
            user_id = row["id"]
        else:
            first_user = conn.execute(
                "SELECT COUNT(*) c FROM users").fetchone()["c"] == 0
            cur = conn.execute(
                "INSERT INTO users (email, name, pw_hash, salt, is_admin,"
                " google_sub, created_at) VALUES (?, ?, '', '', ?, ?, ?)",
                (email, name.strip() or email.split("@")[0],
                 int(first_user), google_sub, _now()))
            user_id = cur.lastrowid
    # look up outside the with-block so the write is committed first
    return get_user(user_id)


def get_user(user_id: int) -> dict | None:
    with _connect() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return _public_user(row) if row else None


def _public_user(row: sqlite3.Row) -> dict:
    return {"id": row["id"], "email": row["email"], "name": row["name"],
            "is_admin": bool(row["is_admin"]), "created_at": row["created_at"]}


def create_session(user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    expires = (datetime.now(timezone.utc) + timedelta(days=SESSION_DAYS)).isoformat()
    with _connect() as conn:
        conn.execute("INSERT INTO sessions (token, user_id, expires_at) VALUES (?,?,?)",
                     (token, user_id, expires))
    return token


def user_for_session(token: str) -> dict | None:
    if not token:
        return None
    with _connect() as conn:
        row = conn.execute(
            "SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id"
            " WHERE s.token = ? AND s.expires_at > ?", (token, _now())).fetchone()
    return _public_user(row) if row else None


def delete_session(token: str) -> None:
    with _connect() as conn:
        conn.execute("DELETE FROM sessions WHERE token = ?", (token,))


# --------------------------------------------------------------------------
# OAuth CSRF state
#
# Stored server-side rather than in a cookie: Firebase Hosting's rewrite to
# Cloud Run strips every request cookie except one literally named
# "__session", so a second cookie for the OAuth state never survives the
# round trip to Google and back.
# --------------------------------------------------------------------------

def create_oauth_state() -> str:
    state = secrets.token_urlsafe(24)
    with _connect() as conn:
        conn.execute("INSERT INTO oauth_states (state, created_at) VALUES (?,?)",
                     (state, _now()))
    return state


def consume_oauth_state(state: str) -> bool:
    """Single-use: valid only once, within 10 minutes of creation."""
    if not state:
        return False
    cutoff = (datetime.now(timezone.utc) - _OAUTH_STATE_MAX_AGE).isoformat()
    with _connect() as conn:
        conn.execute("DELETE FROM oauth_states WHERE created_at < ?", (cutoff,))
        row = conn.execute("SELECT 1 FROM oauth_states WHERE state = ?",
                           (state,)).fetchone()
        if not row:
            return False
        conn.execute("DELETE FROM oauth_states WHERE state = ?", (state,))
    return True


# --------------------------------------------------------------------------
# Scans
# --------------------------------------------------------------------------

def record_scan(user_id: int | None, case: dict) -> None:
    top_domain = next((u["domain"] for u in case["urls"] if u["domain"]), "")
    bad = sum(1 for f in case["findings"] if f["severity"] == "bad")
    with _connect() as conn:
        conn.execute(
            "INSERT INTO scans (user_id, case_id, verdict, confidence, score,"
            " from_addr, subject, top_domain, bad_findings, kind, created_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (user_id, case["case_id"], case["verdict"], case["confidence"],
             case["score"], case["headers"]["from_addr"],
             case["headers"]["subject"][:200], top_domain, bad,
             case.get("kind", "email"), _now()))


def prior_sightings(from_addr: str, domain: str) -> dict:
    """How many earlier cases on this instance saw the same sender or domain."""
    with _connect() as conn:
        sender = conn.execute(
            "SELECT COUNT(*) c FROM scans WHERE from_addr = ? AND from_addr != ''",
            (from_addr,)).fetchone()["c"] if from_addr else 0
        dom = conn.execute(
            "SELECT COUNT(*) c FROM scans WHERE top_domain = ? AND top_domain != ''",
            (domain,)).fetchone()["c"] if domain else 0
    return {"sender": sender, "domain": dom}


def ai_usage(user_id: int) -> tuple[int, str | None]:
    """Rolling 24-hour AI quota (Claude/ChatGPT style).

    Returns (uses_in_last_24h, refresh_at_iso). refresh_at is when the
    OLDEST use in the window expires, i.e. when a slot frees up.
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    with _connect() as conn:
        rows = conn.execute(
            "SELECT created_at FROM ai_uses WHERE user_id = ? AND"
            " created_at >= ? ORDER BY created_at", (user_id, cutoff)).fetchall()
    if not rows:
        return 0, None
    oldest = datetime.fromisoformat(rows[0]["created_at"])
    return len(rows), (oldest + timedelta(hours=24)).isoformat()


def record_ai_use(user_id: int) -> None:
    with _connect() as conn:
        conn.execute("INSERT INTO ai_uses (user_id, created_at) VALUES (?, ?)",
                     (user_id, _now()))


def user_scans(user_id: int, limit: int = 50) -> list[dict]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT case_id, verdict, confidence, score, from_addr, subject,"
            " top_domain, kind, created_at FROM scans WHERE user_id = ?"
            " ORDER BY id DESC LIMIT ?", (user_id, limit)).fetchall()
    return [dict(r) for r in rows]


# --------------------------------------------------------------------------
# Stats
# --------------------------------------------------------------------------

def public_stats() -> dict:
    with _connect() as conn:
        return {
            "scans": conn.execute("SELECT COUNT(*) c FROM scans").fetchone()["c"],
            "users": conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"],
            "threats": conn.execute(
                "SELECT COUNT(*) c FROM scans WHERE verdict IN"
                " ('MALICIOUS', 'SUSPICIOUS')").fetchone()["c"],
            "indicators": conn.execute(
                "SELECT COALESCE(SUM(bad_findings),0) c FROM scans").fetchone()["c"],
        }


def user_stats(user_id: int) -> dict:
    """Personal dashboard numbers for one signed-in user."""
    with _connect() as conn:
        verdicts = {r["verdict"]: r["c"] for r in conn.execute(
            "SELECT verdict, COUNT(*) c FROM scans WHERE user_id = ?"
            " GROUP BY verdict", (user_id,))}
        kinds = {r["kind"]: r["c"] for r in conn.execute(
            "SELECT kind, COUNT(*) c FROM scans WHERE user_id = ?"
            " GROUP BY kind", (user_id,))}
        last = conn.execute(
            "SELECT created_at FROM scans WHERE user_id = ?"
            " ORDER BY id DESC LIMIT 1", (user_id,)).fetchone()
    return {
        "scans": sum(verdicts.values()),
        "malicious": verdicts.get("MALICIOUS", 0),
        "suspicious": verdicts.get("SUSPICIOUS", 0),
        "clean": verdicts.get("LIKELY CLEAN", 0),
        "email": kinds.get("email", 0),
        "sms": kinds.get("sms", 0),
        "last_scan_at": last["created_at"] if last else None,
    }
