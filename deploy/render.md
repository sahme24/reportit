# Deploying CatPhish to Render

The current home of the live app. Free, no credit card, and no verification
step that can fail — which is why it was chosen over the alternatives.

[`render.yaml`](../render.yaml) in the repo root configures the service, so
Render reads it rather than making you fill in a form.

---

## What you give up, and what you don't

Render's free instance has **512 MB of RAM**. Headless Chromium needs about
a gigabyte before it will start, so **link detonation is off here**
(`REPORTIT_SANDBOX=off`, and the browser isn't even built into the image —
it would add 400 MB and several minutes to every deploy for a feature that
could only OOM).

Everything else works: header parsing, SPF/DKIM/DMARC, sender-IP recovery,
typosquat and homoglyph detection, VirusTotal, AbuseIPDB, URLhaus, RDAP
domain age, OCR, the AI verdict, exports, history. The scan reports the
sandbox as unavailable rather than failing.

Detonation itself is verified working — it just needs a machine with more
memory. `deploy/README.md` covers a VM deployment where it runs.

**The database resets on redeploy.** Free instances have no persistent disk.
Sign-in is Google OAuth, so users just sign in again, but scan history and
the dashboard's community counters restart each time.

---

## Setup

**1. Create a fresh Google OAuth client.** The old one lives in the
abandoned GCP project and dies with it. At
[console.cloud.google.com](https://console.cloud.google.com) create a **new**
project (OAuth clients need no billing), then APIs & Services → Credentials
→ OAuth client ID → Web application. Leave the redirect URI blank for now —
you don't know the hostname yet.

**2. Create the service.** At
[dashboard.render.com](https://dashboard.render.com) → **New** →
**Blueprint** → connect `sahme24/reportit` → Render reads `render.yaml`.

It will prompt for the values marked `sync: false`:

| Key | Value |
|---|---|
| `OAUTH_REDIRECT_URL` | leave blank for now, filled in at step 3 |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | from step 1 |
| `ANTHROPIC_API_KEY` | optional — omit to run without the AI analyst |
| `VT_API_KEY`, `ABUSEIPDB_API_KEY`, `URLHAUS_API_KEY` | optional |

**3. Wire up the hostname.** Render assigns something like
`https://catphish.onrender.com`. Now:

- Set `OAUTH_REDIRECT_URL` to `https://<that-host>/auth/google/callback`
- Add the same URL as an authorised redirect URI on the OAuth client

`OAUTH_REDIRECT_URL` is both the OAuth callback *and* the source of
`_CANONICAL_HOST` in `app.py`, which redirects anything arriving on a
different hostname. If the app loads into a redirect loop, this is why.

**4. Stop it sleeping.** Free services sleep after 15 minutes idle and take
30–60s to wake. [`.github/workflows/keepalive.yml`](../.github/workflows/keepalive.yml)
pings `/healthz` every 10 minutes to prevent that. Set the repository
variable so it knows where to ping:

GitHub repo → Settings → Secrets and variables → Actions → **Variables** →
New variable → `SITE_URL` = `https://catphish.onrender.com`

750 free instance-hours a month covers a ~730-hour month, so running around
the clock still fits the quota.

**5. Check it.**

```bash
curl -s -o /dev/null -w "%{http_code}\n" https://<your-host>/healthz   # 200
```

Then sign in and run a scan.

---

## Afterwards

**Deploys happen on push** to `main` — Render watches the repo, so there's
no separate deploy step.

**If it sleeps anyway**, check the keepalive workflow actually ran. GitHub
disables scheduled workflows in repos with no commits for 60 days, and it
does so quietly.

**Moving somewhere with more memory** later only means building with
`--build-arg INSTALL_BROWSER=true` and dropping `REPORTIT_SANDBOX=off`.
Nothing in the application code is host-specific.
