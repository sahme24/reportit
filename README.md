# 🛡️ ReportIT.ai

[![CI/CD](https://github.com/YOURUSERNAME/reportit/actions/workflows/ci.yml/badge.svg)](https://github.com/YOURUSERNAME/reportit/actions/workflows/ci.yml)

**Phishing and smishing investigation for everyone, delivered as a hosted
web app.** (Private repository. See License below.)

Ever gotten a phishing email? Everyone has. ReportIT.ai reads it the way a
security analyst would: parsing headers, verifying authentication, hunting
typosquats, querying threat intel, and tracing the attack chain from spoofed
sender to landing page. (The analysis engine lives in the `threadline/`
package. Every scan traces the thread of the attack.)

Enterprises have SOC teams and commercial platforms for this. The average
person has a spam folder. ReportIT.ai closes that gap: free to use, no
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
installed, ReportIT.ai reads attached and inline images and runs the hidden
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

No keys? ReportIT.ai still runs every offline heuristic plus RDAP domain-age
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

## Deploy to Google Cloud Run

The Dockerfile is Cloud Run ready (it listens on `$PORT`, defaulting to
8080). Cloud Run's free tier covers 2 million requests a month and scales
to zero when idle, so a low-traffic instance costs nothing beyond an
attached billing account.

**Prerequisites:** the [`gcloud` CLI](https://cloud.google.com/sdk/docs/install),
signed in (`gcloud auth login`) with a project selected (`gcloud config set
project YOUR_PROJECT_ID`).

**1. One-time storage setup.** Cloud Run containers are stateless: local
disk resets on every cold start and isn't shared across instances. Mount a
Cloud Storage bucket at `/data` so `threadline.db` survives redeploys:

```bash
gcloud storage buckets create gs://YOUR_PROJECT_ID-reportit-data --location=us-central1
```

**2. Store secrets.** Don't pass API keys as plain env vars; put them in
Secret Manager instead:

```bash
echo -n "YOUR_GOOGLE_CLIENT_ID" | gcloud secrets create reportit-google-client-id --data-file=-
echo -n "YOUR_GOOGLE_CLIENT_SECRET" | gcloud secrets create reportit-google-client-secret --data-file=-
echo -n "YOUR_ANTHROPIC_API_KEY" | gcloud secrets create reportit-anthropic-key --data-file=-
```

**3. Deploy.** `--source .` builds the Dockerfile with Cloud Build and
deploys in one step, no separate registry setup needed:

```bash
gcloud run deploy reportit \
  --source . \
  --region us-central1 \
  --allow-unauthenticated \
  --min-instances=0 \
  --max-instances=1 \
  --add-volume=name=data,type=cloud-storage,bucket=YOUR_PROJECT_ID-reportit-data \
  --add-volume-mount=volume=data,mount-path=/data \
  --set-secrets=GOOGLE_CLIENT_ID=reportit-google-client-id:latest,GOOGLE_CLIENT_SECRET=reportit-google-client-secret:latest,ANTHROPIC_API_KEY=reportit-anthropic-key:latest
```

`--max-instances=1` matters here: SQLite handles one writer well but isn't
built for multiple Cloud Run instances hitting the same file concurrently.
For this project's traffic level that's the right tradeoff; if you outgrow
it, the next step is a managed database rather than raising the instance
cap.

**4. Register the callback URL.** `gcloud run deploy` prints a service URL
like `https://reportit-xxxxx-uc.a.run.app`. Add
`https://reportit-xxxxx-uc.a.run.app/auth/google/callback` as an authorized
redirect URI in the [Google Cloud Console](https://console.cloud.google.com/apis/credentials)
(same OAuth client as local dev, one more entry in the list; see the
Google sign-in section above for why both `localhost` and `127.0.0.1`
variants matter for local testing). No code change is needed since
`app.py` builds the callback URL from the incoming request's own host.

**Redeploying manually:** re-run `./deploy.sh` (wraps steps 1–4 above, safe
to run repeatedly). This deploys whatever's on disk in this folder, not
whatever's on GitHub, so a push to GitHub does nothing to the live site on
its own — see "Auto-deploy on push" below to close that gap.

## A shorter URL

Cloud Run's auto-generated URL (`reportit-476314376398.us-central1.run.app`)
can't be renamed or shortened directly. [`firebase.json`](firebase.json) sets
up Firebase Hosting as a free reverse proxy in front of it instead, giving
you `https://reportit-ai.web.app` (or whatever site ID you pick, subject to
availability, since `web.app` subdomains are global) with the same backend
and zero code changes, since `app.py` already builds all its URLs from
whatever host actually served the request.

**1. Add Firebase to the GCP project** (one-time, browser): go to
[the Firebase console](https://console.firebase.google.com/), **Add
project**, choose the existing GCP project (`exalted-pattern-502023-i8`)
from the dropdown rather than creating a new one, skip Google Analytics.
Firebase Hosting's Cloud Run integration needs the
[Blaze plan](https://firebase.google.com/pricing) (pay-as-you-go), not the
free Spark plan — you're already on a billing-enabled project from the
Cloud Run setup, so this is just a plan toggle, not a new account.

**2. Sign in and claim the site ID.** `firebase-tools` is already installed:

```bash
firebase login
firebase hosting:sites:create reportit-ai --project exalted-pattern-502023-i8
```

If `reportit-ai` is taken, pick another id and update the `"site"` value in
`firebase.json` to match.

**3. Deploy:**

```bash
firebase deploy --only hosting
```

Firebase prints the live URL when it's done.

**4. Register the new callback URL** in the
[Google Cloud Console](https://console.cloud.google.com/apis/credentials):
add `https://reportit-ai.web.app/auth/google/callback` alongside the
existing ones (the old `run.app` URL keeps working too — nothing needs to
be removed).

**Redeploying:** `firebase deploy --only hosting` again after any Cloud Run
change (it just repoints the proxy; the Cloud Run service itself still
deploys the normal way via `./deploy.sh` or the Cloud Build trigger).

## Auto-deploy on push

Once set up, every push to `main` rebuilds and redeploys automatically via
[Cloud Build](https://console.cloud.google.com/cloud-build), using
[`cloudbuild.yaml`](cloudbuild.yaml). This is separate from the GitHub
Actions pipeline above (that one lints, tests, and builds a GHCR image for
anyone self-hosting via Docker; this one deploys the actual Cloud Run
service). Uses Cloud Build's native GitHub integration, not a service
account key, so there's no long-lived credential to store as a GitHub
secret.

This is a one-time setup, done once the manual deploy above has run at
least once (the bucket and secrets it creates are reused, not recreated,
by every automatic deploy):

**1. Connect the repo.** In the
[Cloud Build console](https://console.cloud.google.com/cloud-build/triggers) →
**Connect Repository** → **GitHub** → authorize the Cloud Build GitHub App
→ select this repo. Since the repo is private, this needs to be done by
someone with admin access to it.

**2. Create the trigger.** **Create Trigger** →
- Event: **Push to a branch**
- Branch: `^main$`
- Configuration: **Cloud Build configuration file**, location `cloudbuild.yaml`

**3. Grant Cloud Build deploy permission.** Cloud Build's own service
account needs permission to update the Cloud Run service and push images,
which it doesn't have by default:

```bash
chmod +x setup-cicd.sh
./setup-cicd.sh
```

From here, every push to `main` triggers a build automatically; watch it at
the [Cloud Build history page](https://console.cloud.google.com/cloud-build/builds).
Secrets and the storage bucket aren't touched by these automatic builds —
if you rotate a key, update it with `gcloud secrets versions add` (or rerun
`deploy.sh`, which is idempotent) rather than through the trigger.

## Contributing (collaborators)

If you're adding a heuristic, include a sanitized sample message that
triggers it. Never commit real phishing payloads, live malicious URLs
(defang them), or anyone's personal data.

## License

**Private, closed-source project.** Not licensed for redistribution or
self-hosting. (The [MIT](LICENSE) file is retained in case the project is
re-opened later.)
