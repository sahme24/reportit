---
title: CatPhish
emoji: 🐱
colorFrom: yellow
colorTo: red
sdk: docker
app_port: 8080
pinned: false
short_description: Paste a suspicious email, get an analyst-grade verdict
---

# 🐱 CatPhish

[![CI/CD](https://github.com/YOURUSERNAME/reportit/actions/workflows/ci.yml/badge.svg)](https://github.com/YOURUSERNAME/reportit/actions/workflows/ci.yml)

<!-- The YAML block above configures the Hugging Face Space this deploys to
     (GitHub renders it as a small table, Hugging Face reads it as config).
     app_port must match the port the Dockerfile's uvicorn listens on. -->


**Phishing and smishing investigation for everyone, delivered as a hosted
web app.** (Private repository. See License below.)

Ever gotten a phishing email? Everyone has. CatPhish reads it the way a
security analyst would: parsing headers, verifying authentication, hunting
typosquats, querying threat intel, and tracing the attack chain from spoofed
sender to landing page. (The analysis engine lives in the `threadline/`
package. Every scan traces the thread of the attack.)

Enterprises have SOC teams and commercial platforms for this. The average
person has a spam folder. CatPhish closes that gap: free to use, no
setup, live on the web.

## Features

- **Phishing AND smishing:** scan raw emails or paste a scam text message;
  SMS mode checks brand lures, sender-number heuristics, and link forensics
- **Analyst-grade checks:** 40+ heuristics across headers, URLs, attachments,
  and content, plus optional reputation lookups
- **Attack chain visualization:** sender → auth check → link → landing page,
  color-coded by risk
- **Case files, not pass/fail:** every scan gets a case number, a 0–100 risk
  score, findings in plain language, and an exportable markdown/JSON report
- **Evidence highlighting:** pressure language, brand lures, and flagged
  links are marked right inside the message preview
- **"What you should do" on every case:** concrete, verdict-specific next
  steps (report to 7726 / reportphishing@apwg.org, block, password advice) in
  the UI, the CLI, and the exported report
- **AI baked into every scan:** the heuristic toolset and an independent
  AI analysis run together as one pass, not as separate features, the AI
  forms its own verdict that confirms or challenges the automated findings,
  plus a plain-English explanation and tailored actions
- **OCR for image-based phishing:** links and pressure language hidden
  inside attached or inline images are extracted with Tesseract and run
  through the same URL/urgency/reputation checks
- **Google-only sign-in:** no passwords stored, ever; your case history is
  saved to your account and repeat offenders (same sender/domain across
  cases) are flagged automatically
- **Personal dashboard:** your own scan totals, threats caught, and case
  history, plus the instance's community-wide numbers
- **Light & dark themes:** clean SaaS light or deep-navy dark
- **CLI included:** everything works from the terminal too

## Quick start

```bash
git clone https://github.com/YOURUSERNAME/reportit
cd reportit
pip install -r requirements.txt
cp .env.example .env   # then add your Google OAuth credentials (below)

# web app
uvicorn app:app
# then open http://127.0.0.1:8000

# or straight from the terminal (no account needed)
python -m threadline samples/phish-0ffice365.eml
python -m threadline suspicious.eml --report case.md
python -m threadline suspicious.eml --json

# text messages (smishing)
python -m threadline samples/smish-cra.txt --sms --sender "+1 555 013 4477"
```

`--offline` skips all network lookups; header and URL heuristics still run.

## Google sign-in (required for the web app)

Sign-in is Google-only by design, so no passwords are ever stored. Setup
takes two minutes:

1. Go to [console.cloud.google.com/apis/credentials](https://console.cloud.google.com/apis/credentials)
   → **Create credentials → OAuth client ID → Web application**
2. Add an **authorized redirect URI**:
   `http://127.0.0.1:8000/auth/google/callback` (add your public URL too when
   you deploy, and set `OAUTH_REDIRECT_URL` in `.env` if you're behind a proxy)
3. Put the client ID and secret in `.env`:

```
GOOGLE_CLIENT_ID=...apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=...
```

Accounts created before the Google-only switch are linked automatically by
email address (they keep their history and admin flag).

## OCR for image-based phishing (optional)

Scammers put the whole lure in a picture so text filters see nothing.
With the [Tesseract](https://github.com/tesseract-ocr/tesseract) binary
installed, CatPhish reads attached and inline images and runs the hidden
text through the same URL, typosquat, urgency, and reputation checks:

```bash
sudo apt install tesseract-ocr        # Debian/Ubuntu (already in the Docker image)
brew install tesseract                # macOS
choco install tesseract               # Windows
```

No Tesseract? Scans still work. Cases with images just note that image
text wasn't checked.

## AI analyst (optional)

With an [Anthropic API key](https://platform.claude.com) in `.env`, every
scan **is** the AI analyst, not an add-on to it: the heuristic toolset
gathers the evidence, and the AI's verdict on that evidence becomes the
case's verdict, the one thing shown, not a second opinion that can
contradict a separate heuristic badge. The heuristic score still exists
under the hood as one more piece of evidence for the AI to weigh, and the
"What You Should Do" list is recomputed to match whatever verdict the AI
lands on, so there's one verdict, one advice list, one result. A plain-
English explanation and case-specific extra steps come with it (an
"Explain this case" button retries just the AI portion for free, e.g.
after a transient API hiccup, without spending another scan). The analyst
only sees the scan results (links defanged); it never visits anything.

Costs stay predictable: the default model is Claude Haiku (the cheapest
tier) and each user gets **3 scans per rolling 24 hours.** Each use frees
up exactly 24 hours after it happened, and the UI tells the user the local
time their next one unlocks, the same way Claude and ChatGPT do it. With no
`ANTHROPIC_API_KEY` set, this cap doesn't apply and scanning is unlimited,
just without the AI portion.

```
ANTHROPIC_API_KEY=sk-ant-...
# REPORTIT_AI_MODEL=claude-haiku-4-5   # default
# REPORTIT_AI_DAILY_LIMIT=3            # per user, rolling 24h
```

## What gets checked

| Category | Checks |
|---|---|
| Authentication | SPF / DKIM / DMARC results, sender IP recovered from the `Received` chain |
| Spoofing | Reply-To / Return-Path mismatches, display-name brand claims, corporate identity on freemail |
| URLs | Homoglyph typosquats (`0ffice365`, `paypa1`, `rnicrosoft`), punycode, `@`-userinfo tricks, high-abuse TLDs, shorteners, anchor-text/href mismatch, IP-literal links |
| Attachments | Executable & macro-capable types, SHA-256 for every file |
| Content | Urgency and pressure language |
| Reputation | Domain age via RDAP (keyless), VirusTotal, AbuseIPDB, URLhaus |
| History | Repeat senders/domains across this instance's previous cases |
| SMS (smishing) | Brand-name lures pointing at unofficial domains, gateway/full-number senders, pressure language, all URL checks |
| Images (OCR) | Links and pressure language hidden inside attached/inline images, extracted with Tesseract, then run through every URL check |
| AI analysis | Weighs every finding above to produce the case's one verdict, plus a plain-English summary and case-specific extra steps |

## Threat-intel keys (optional)

Providers activate automatically when a key exists. Create a `.env` file:

```
VT_API_KEY=...          # virustotal.com, free tier
ABUSEIPDB_API_KEY=...   # abuseipdb.com, free tier
URLHAUS_API_KEY=...     # auth.abuse.ch, free
```

No keys? CatPhish still runs every offline heuristic plus RDAP domain-age
checks. Lookups fail soft, so a dead API never breaks a scan.

## Why users can trust it

- **Bodies analyzed, then discarded:** the database keeps verdict, sender,
  subject, and defanged indicators, never the message body
- **Defanged by design:** reports neutralize URLs (`hxxps://…[.]com`);
  links found in a message are never visited
- **No passwords, ever:** sign-in is Google OAuth only; the database stores
  just your name, email, and case metadata (message bodies are analyzed and
  discarded)
- **Your data stays put:** accounts and scan history live in a local
  `threadline.db`; the only outbound traffic is the reputation lookups you
  enable and the optional AI analyst

## Project layout

```
threadline/         the investigation engine
  parser.py         raw email → headers, auth results, sender IP, bodies, attachments
  auth.py           SPF/DKIM/DMARC + spoofing findings
  urlscan.py        URL extraction + typosquat/heuristic analysis
  reputation.py     RDAP, VirusTotal, AbuseIPDB, URLhaus
  scanner.py        orchestration, scoring, attack-chain builder
  sms.py            smishing (text-message) analysis
  report.py         markdown report generation
  db.py             SQLite: users, sessions, scan history
  cli.py            terminal interface
app.py              FastAPI backend (pages + JSON API)
static/             web UI: landing, auth, scanner, history, dashboard
samples/            sanitized test emails (one phish, one clean)
```

## Roadmap

- [ ] Sandboxed landing-page screenshots
- [ ] Sophistication scoring (spray vs. spear-phishing)
- [ ] Safe redirect-chain tracing
- [ ] Rate limiting & email verification for public instances
- [ ] Browser extension / "forward to scan" address

## CI/CD

Every push and pull request runs the pipeline in
[`.github/workflows/ci.yml`](.github/workflows/ci.yml):

1. **Lint:** `ruff check .`
2. **Test:** `pytest` (engine regression tests + API smoke tests, all
   offline: verdicts on the sample phish/clean/smish, typosquat detection,
   defanged reports, auth enforcement, and the AI daily limit)
3. **Deploy:** on pushes to the default branch, a Docker image is built and
   published to GitHub Container Registry as
   `ghcr.io/<you>/reportit:latest` (plus a per-commit SHA tag)

Run the same checks locally:

```bash
pip install -r requirements-dev.txt
ruff check . && pytest

# and the production container:
docker build -t reportit .
docker run -p 8080:8080 -v reportit-data:/data --env-file .env reportit
```

## Deploy

Live on **Hugging Face Spaces** — see
[`deploy/huggingface.md`](deploy/huggingface.md). The config is the YAML
block at the top of this file; secrets go in the Space's settings, never in
the repo.

```bash
git remote add space https://huggingface.co/spaces/<you>/catphish
git push space main
```

Spaces was chosen because it needs no credit card and still has enough
memory to run headless Chromium, so link detonation survives. The costs are
that storage resets on every rebuild (the database starts empty; sign-in is
Google OAuth so nothing irreplaceable is lost) and the Space sleeps after
48h idle.

**On your own VM instead:** [`deploy/README.md`](deploy/README.md) covers
Docker Compose plus Caddy on any machine with a public IP — persistent
storage, no sleeping, and TLS via Let's Encrypt automatically. Back the
database up with [`deploy/backup.sh`](deploy/backup.sh) on a cron; on a VM
nothing else will.

> **This used to deploy to Google Cloud Run**, fronted by Firebase Hosting,
> via a `deploy.sh`, `firebase.json` and `cloudbuild.yaml` no longer in the
> tree (`git log -- deploy.sh` to recover them). Two things drove the move:
> Cloud Run requires an active billing account, and Firebase Hosting's
> rewrite layer silently drops WebSocket upgrades, so live scan progress
> never worked on the public domain. Both go away by hosting the container
> anywhere else.

## Contributing (collaborators)

If you're adding a heuristic, include a sanitized sample message that
triggers it. Never commit real phishing payloads, live malicious URLs
(defang them), or anyone's personal data.

## License

**Private, closed-source project.** Not licensed for redistribution or
self-hosting. (The [MIT](LICENSE) file is retained in case the project is
re-opened later.)
