# Streaming scans and sandboxed link detonation

Two features that ship together:

1. **`/ws/scan`** — the same investigation as `POST /api/scan`, but each stage
   reports as it finishes instead of the page sitting on one long request.
2. **Link detonation** — the scanner opens each link in a throwaway headless
   Chromium and reports what the landing page actually does, including a
   screenshot of it.

`POST /api/scan` is unchanged and still works. The browser uses it as an
automatic fallback wherever a WebSocket can't be established.

---

## Progress events

The client opens a socket, sends `{raw, offline, kind, sender}`, and reads
events until a terminal one. Every event is `{"type": ..., "data": {...}}`.

| `type` | when | notable `data` |
|---|---|---|
| `parse_started` | message parsing begins | — |
| `urls_extracted` | links pulled out | `count`, `urls[{url, domain}]` |
| `reputation_check_started` | threat-intel lookups begin | `url_count` |
| `reputation_check_completed` | lookups done | `findings_count` |
| `sandbox_starting` | detonation begins | `url_count` |
| `sandbox_url_result` | one link finished | see below |
| `ai_started` | AI pass begins | `enabled` |
| `scan_complete` | **terminal** — the full case | the same dict `/api/scan` returns |
| `error` | **terminal** — nothing usable | `message`, sometimes `refresh_at` |

`sandbox_url_result.data`: `url`, `domain`, `landed_on`, `title`,
`threat_level`, `threat_signals[]`, `observations[]`, `error`, and
`screenshot` (base64 JPEG, or `null` when capture failed or the image was
over ~400 KB — it is dropped rather than truncated, since a sliced base64
string decodes to a broken image).

Auth failure closes the socket with code **1008** before any event.

---

## What detonation looks at

`threadline/sandbox.py` observes; it does not guess from keywords.

**Observed:** final URL after redirects, page title, credential inputs
(checking `type`/`name`/`id`/`placeholder`, since kits use `type="text"` with
`name="passwd"` to dodge scanners), iframe count, third-party hosts contacted,
console errors, urgency wording (reusing the scanner's existing
`URGENCY_PHRASES`).

**Scored:** only *combinations*. A login form on its own is not a signal —
real banks have login forms. What scores is a credential form somewhere the
link didn't claim to go, or over plain HTTP, or on a high-abuse TLD:

| signal | points |
|---|---|
| landed on a different registered domain than the link claimed | 20 |
| credentials requested over plain HTTP | 35 |
| credentials on a cross-domain landing | 30 |
| credentials on a high-abuse TLD | 30 |
| credentials + pressure wording | 20 |
| credentials + embedded frames | 15 |
| high-abuse TLD, no credential form | 15 |
| obfuscated script (`eval`/`atob`/`unescape`) | 15 |

`>= 55` → **malicious** (BAD finding, weight 30) ·
`>= 25` → **suspicious** (WARN finding, weight 15) · otherwise nothing.

A legitimate HTTPS sign-in page on its own domain scores **0**. After
detonation the case score and verdict are recomputed, so a sandbox hit can
change the verdict.

---

## Setup

```bash
pip install -r requirements.txt
playwright install chromium
```

Both matter, and for different reasons:

- **`websockets`** — bare `uvicorn` ships no WebSocket protocol
  implementation and `/ws/scan` returns 404 with *"No supported WebSocket
  library detected"*. Starlette's `TestClient` talks ASGI directly and will
  **not** catch this; it only appears over a real socket.
- **`playwright install chromium`** — `pip install playwright` installs the
  Python bindings only, not the browser. The Dockerfile runs this (adds
  ~400 MB).

### Configuration

| env var | default | meaning |
|---|---|---|
| `REPORTIT_SANDBOX` | `on` | `off` disables detonation entirely |
| `REPORTIT_SANDBOX_MAX_URLS` | `5` | links detonated per scan |
| `REPORTIT_SANDBOX_CONCURRENCY` | `3` | pages open at once |
| `REPORTIT_SANDBOX_TIMEOUT_MS` | `20000` | deadline per page |

---

## Degradation

Every one of these completes the scan rather than failing it:

- **No `websockets`, or a proxy that drops the upgrade** → the browser falls
  back to `POST /api/scan`; the sandbox stage shows *"needs live connection"*.
- **No Playwright / no Chromium** → detonation is skipped. The first launch
  failure caused by a missing binary latches `is_available()` to `False`, so
  later scans don't re-pay the timeout.
- **Offline mode** → never opens a link, even where a browser is available.
  There is a test asserting this.
- **A link that hangs or refuses** → that one link reports `error`; the rest
  of the scan is unaffected.

---

## Deployment note: Firebase Hosting

`firebase.json` rewrites `**` to Cloud Run. Cloud Run supports WebSockets;
**Firebase Hosting's rewrite layer does not forward the upgrade.** This is
confirmed, not suspected — the same request logs two different ways:

```
"WebSocket /ws/scan" 403      # hit Cloud Run directly: upgrade handled
"GET /ws/scan HTTP/1.1" 404   # same request via Firebase Hosting
```

Hosting strips the upgrade headers, so the request arrives as an ordinary
GET and 404s. **Every visitor on `catphish.web.app` therefore takes the
HTTP fallback**, and the WebSocket path only runs against the raw
`*.run.app` URL.

Because of that, detonation must never live only on the socket. Both
endpoints call the same `_detonate_case()` in `app.py`, so the sandbox runs
either way. The only thing the transport decides is whether progress
*streams*: over the socket the stages tick live, and on the fallback the
POST returns once with everything filled in.

To get live progress on the public domain you'd have to bypass Hosting
entirely — map the domain straight to Cloud Run — which is a DNS change,
not a code one.

---

## Privacy

Detonation opens attacker-controlled URLs **from the server**, never from the
user's browser. That is a deliberate trade: it reveals the server's IP to the
sender and confirms the message was opened. Offline mode skips it, and the
landing page copy says so plainly. Screenshots stream to the page for display
but are stripped from the stored case — `db.record_scan` persists metadata
columns only.
