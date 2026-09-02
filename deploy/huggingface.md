# Deploying CatPhish to Hugging Face Spaces

The current home of the live app. Free, no credit card at any point, and
enough memory that link detonation actually runs — which no other free tier
offers.

The config lives in the YAML block at the top of the repo's root
`README.md`; Hugging Face reads it, GitHub renders it as a small table.

---

## Why here

Cloud Run needs a live billing account, and Oracle wants a card at signup.
Both declined the same card. Spaces asks for neither.

The concrete win over Render (the other card-free option) is memory. Render
gives 512 MB; headless Chromium needs about a gigabyte before it will even
start, so detonation would have to be switched off there. Spaces' free CPU
tier has roughly 16 GB, so the sandbox survives the move intact.

---

## What you give up

- **Storage resets.** Free Spaces have no persistent disk, so the database
  starts empty after every rebuild and every wake-from-sleep. Users sign in
  again (Google OAuth, so nothing is lost but the row), scan history goes,
  and the dashboard's community counters restart at zero. Nothing else in
  the app depends on stored state.
- **It sleeps after 48 hours idle** and takes ~30s to wake. Far better than
  Render's 15 minutes, but a link shared cold can still be slow to open.
- **The Space is public.** The code is visible, and it sits in an
  ML-demo directory, which is an odd neighbourhood for a security tool.
  Sign-in still gates every scan, so nobody can use your API keys.

---

## Setup

**1. Create the Space.** At
[huggingface.co/new-space](https://huggingface.co/new-space):

- Owner: your account
- Space name: `catphish`
- License: whatever matches the repo
- SDK: **Docker** → *Blank*
- Hardware: CPU basic (free)
- Visibility: Public

Your URL will be `https://<your-username>-catphish.hf.space`.

**2. Register the OAuth callback.** Sign-in is Google-only, and the client
currently lives in the abandoned `exalted-pattern-502023-i8` project. If
Google deletes that project, sign-in breaks. Create a **new** GCP project —
OAuth clients need no billing — and add this redirect URI:

```
https://<your-username>-catphish.hf.space/auth/google/callback
```

**3. Add the secrets.** Space → *Settings* → *Variables and secrets*. As
**Secrets**, never Variables (Variables are publicly visible):

| Name | Value |
|---|---|
| `OAUTH_REDIRECT_URL` | `https://<user>-catphish.hf.space/auth/google/callback` |
| `GOOGLE_CLIENT_ID` | from the new project |
| `GOOGLE_CLIENT_SECRET` | from the new project |
| `ANTHROPIC_API_KEY` | optional — omit to run without the AI analyst |
| `VT_API_KEY` | optional |
| `ABUSEIPDB_API_KEY` | optional |
| `URLHAUS_API_KEY` | optional |

`OAUTH_REDIRECT_URL` does double duty: it's the OAuth callback *and* the
source of `_CANONICAL_HOST` in `app.py`, which redirects any request
arriving on a different hostname. If it's wrong, every request bounces
somewhere unexpected — that's the first thing to check if the Space loads
to a redirect loop.

**4. Push the code.**

```bash
git remote add space https://huggingface.co/spaces/<your-username>/catphish
git push space main
```

The build takes 10–15 minutes the first time: it installs dependencies and
downloads Chromium. Watch the *Logs* tab.

**5. Check it.** Open the Space URL, sign in, and scan a message with a
link in it. If "Where the links went" shows a screenshot, **the sandbox is
working in a container for the first time** — that has never been verified
anywhere.

---

## Afterwards

**Updating** is `git push space main`; the Space rebuilds automatically.
Keep GitHub as your primary remote and treat the Space as a deploy target.

**If detonation fails**, the Logs tab will say why. It's the one part that
has never run in a container, so a first-time failure is plausible. To
disable it without touching code, add a Space secret:

```
REPORTIT_SANDBOX = off
```

Everything except link detonation keeps working.

**Live scan progress should work here.** Spaces proxies WebSockets — Gradio
depends on them — so the stage-by-stage progress that Firebase Hosting
silently dropped ought to run for the first time. Worth confirming: if the
stage list ticks along during a scan rather than sitting still until
results appear, the WebSocket path is live.

---

## Running it on a VM instead

If you ever get a working card, [`README.md`](README.md) in this directory
covers a plain-VM deployment with Docker Compose and Caddy, which gets you
persistent storage and no sleeping.
