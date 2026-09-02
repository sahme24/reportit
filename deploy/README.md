# Running CatPhish on your own VM

Written for Oracle Cloud's Always Free tier, but nothing here is
Oracle-specific except step 3 — any Ubuntu box with a public IP works.

Unlike Cloud Run, this is a machine you own: no per-request billing, no
scale-to-zero, no cold starts. The trade is that certificates, the
firewall and restarts are now yours to run.

---

## Before you start: three things that will block you

**1. Oracle asks for a credit card at signup.** It's an identity check —
they authorise about $1 and refund it, and the Always Free resources stay
free afterwards. If the card that's currently declining is declining
because of a problem at the *bank* rather than at Google, it will decline
here too. Find that out first, before doing any of the work below.

**2. The 24 GB ARM shape is often unavailable.** `VM.Standard.A1.Flex` is
the one worth having, and busy regions return "Out of capacity" for days.
Retry, or pick a quieter region at signup — the home region can't be
changed later. The always-available fallback (`VM.Standard.E2.1.Micro`) has
**1 GB of RAM**, which is not enough for Chromium: on that shape set
`REPORTIT_SANDBOX=off` and you lose link detonation but keep every other
check.

**3. Your OAuth client is in a project you're abandoning.** Sign-in is
Google-only, and the existing client lives in the delinquent GCP project.
If Google suspends or deletes that project, nobody can sign in, wherever
the app is hosted. Fix it before it happens — OAuth clients cost nothing
and need no billing:

- Create a **new** GCP project (console.cloud.google.com, no billing needed)
- APIs & Services → OAuth consent screen → External → fill in the basics
- Credentials → Create credentials → OAuth client ID → Web application
- Authorised redirect URI: `https://YOUR_DOMAIN/auth/google/callback`
- Copy the new client ID and secret into `.env` below

---

## You need a domain name

Let's Encrypt will not issue a certificate for a bare IP address, and
Google OAuth will not redirect to a plain-http callback. So the VM's IP
alone is not enough.

If you don't want to buy one, [DuckDNS](https://duckdns.org) gives free
subdomains (`catphish.duckdns.org`) — sign in, pick a name, point it at the
VM's public IP. Caddy issues the certificate automatically from there.

---

## Steps

**1. Create the VM.** Ubuntu 22.04 or 24.04, `VM.Standard.A1.Flex`, 4 OCPU
/ 24 GB if you can get it. Save the SSH key it offers — there's no way to
retrieve it later.

**2. Get the code onto it.**

```bash
ssh -i your-key.pem ubuntu@YOUR_VM_IP
git clone https://github.com/sahme24/reportit.git catphish
cd catphish
sudo bash deploy/bootstrap.sh
```

**3. Open the firewall in the OCI console.** This is the step everyone
misses. Oracle has *two* firewalls and `bootstrap.sh` only configured the
one on the machine. In the console: Networking → Virtual Cloud Networks →
your VCN → Subnets → your subnet → Security Lists → Default → **Add Ingress
Rules**:

| Source CIDR | Protocol | Destination port |
|-------------|----------|------------------|
| `0.0.0.0/0` | TCP      | 80               |
| `0.0.0.0/0` | TCP      | 443              |

Symptom of skipping it: connections to the site hang forever rather than
refusing, and Caddy's certificate request times out.

**4. Point DNS at the VM.** An `A` record for your domain → the VM's public
IP. Confirm before continuing, because Caddy's first certificate request
will fail otherwise and Let's Encrypt rate-limits repeats:

```bash
dig +short YOUR_DOMAIN
```

**5. Write `.env` in the repo root** (not in `deploy/`):

```bash
CATPHISH_DOMAIN=catphish.duckdns.org
OAUTH_REDIRECT_URL=https://catphish.duckdns.org/auth/google/callback

GOOGLE_CLIENT_ID=...          # from the NEW project, see above
GOOGLE_CLIENT_SECRET=...
ANTHROPIC_API_KEY=...         # omit to run without the AI analyst
VT_API_KEY=...                # all three below are optional
ABUSEIPDB_API_KEY=...
URLHAUS_API_KEY=...

# On the 1 GB micro shape, uncomment -- Chromium will not fit:
# REPORTIT_SANDBOX=off
```

`OAUTH_REDIRECT_URL` does double duty: it's the OAuth callback *and* the
source of `_CANONICAL_HOST` in `app.py`, which redirects any request
arriving on a different hostname. Get it wrong and every request bounces
somewhere unexpected.

**6. Start it.**

```bash
cd deploy
docker compose up -d --build
```

First build takes 10–15 minutes — it compiles dependencies and downloads
Chromium, on ARM.

**7. Check it worked.**

```bash
curl -sI https://YOUR_DOMAIN | head -1     # expect: HTTP/2 200
docker compose logs -f app                  # app output
docker compose logs caddy | grep -i certif  # certificate issuance
```

---

## Afterwards

**Updating:**

```bash
git pull && cd deploy && docker compose up -d --build
```

**Backups.** The database is a Docker named volume, so it survives rebuilds
and reboots but *not* `docker compose down -v`. Copy it somewhere real:

```bash
docker compose cp app:/data/threadline.db ./threadline-backup.db
```

**WebSockets work here.** Firebase Hosting was dropping the upgrade, which
forced every scan onto the HTTP fallback. Caddy proxies WebSockets
natively, so live scan progress works on this setup — something that was
never possible on the old domain.

**Memory.** Each scan opens a real browser. On the 24 GB shape that's a
non-issue; `REPORTIT_SANDBOX_CONCURRENCY` (default 3) caps how many pages
open at once if you ever need to tighten it.
