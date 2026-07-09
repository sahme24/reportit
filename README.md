# 🛡️ ReportIT.ai

**Open-source phishing investigation for everyone.**

Ever gotten a phishing email? Everyone has. ReportIT.ai reads it the way a
security analyst would — parsing headers, verifying authentication, hunting
typosquats, querying threat intel, and tracing the attack chain from spoofed
sender to landing page. (The analysis engine lives in the `threadline/`
package — every scan traces the thread of the attack.)

Enterprises have SOC teams and commercial platforms for this. The average
person has a spam folder. ReportIT.ai closes that gap — free, self-hostable,
and fully auditable.

## Features

- **Phishing AND smishing** — scan raw emails or paste a scam text message;
  SMS mode checks brand lures, sender-number heuristics, and link forensics
- **Analyst-grade checks** — 40+ heuristics across headers, URLs, attachments,
  and content, plus optional reputation lookups
- **Attack chain visualization** — sender → auth check → link → landing page,
  color-coded by risk
- **Case files, not pass/fail** — every scan gets a case number, a 0–100 risk
  score, findings in plain language, and an exportable markdown/JSON report
- **Accounts & case history** — your investigations are saved; repeat
  offenders (same sender/domain across cases) are flagged automatically
- **Admin dashboard** — user growth, scans per day, verdict breakdown
- **Light & dark themes** — clean SaaS light or deep-navy dark
- **CLI included** — everything works from the terminal too

## Quick start

```bash
git clone https://github.com/YOURUSERNAME/reportit
cd reportit
pip install -r requirements.txt

# web app
uvicorn app:app
# → open http://127.0.0.1:8000
# the FIRST account you create becomes the admin (that's you — sign up first!)

# or straight from the terminal
python -m threadline samples/phish-0ffice365.eml
python -m threadline suspicious.eml --report case.md
python -m threadline suspicious.eml --json

# text messages (smishing)
python -m threadline samples/smish-cra.txt --sms --sender "+1 555 013 4477"
```

`--offline` skips all network lookups; header and URL heuristics still run.

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

## Threat-intel keys (optional)

Providers activate automatically when a key exists. Create a `.env` file:

```
VT_API_KEY=...          # virustotal.com — free tier
ABUSEIPDB_API_KEY=...   # abuseipdb.com — free tier
URLHAUS_API_KEY=...     # auth.abuse.ch — free
```

No keys? ReportIT.ai still runs every offline heuristic plus RDAP domain-age
checks. Lookups fail soft — a dead API never breaks a scan.

## Why you can trust it

- **Every heuristic is public code** — read [`threadline/`](threadline), it's small on purpose
- **Runs on your machine** — Python + SQLite, no cloud dependency
- **Defanged by design** — reports neutralize URLs (`hxxps://…[.]com`);
  links found in a message are never visited
- **Your data stays put** — accounts and scan history live in a local
  `threadline.db`; the only outbound traffic is the reputation lookups you
  enable

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
static/             web UI — landing, auth, scanner, history, admin dashboard
samples/            sanitized test emails (one phish, one clean)
```

## Roadmap

- [ ] Sandboxed landing-page screenshots
- [ ] Sophistication scoring (spray vs. spear-phishing)
- [ ] Safe redirect-chain tracing
- [ ] Rate limiting & email verification for public instances
- [ ] Browser extension / "forward to scan" address

## Contributing

Issues and PRs welcome. If you're adding a heuristic, include a sanitized
sample email that triggers it. Never commit real phishing payloads, live
malicious URLs (defang them), or anyone's personal data.

## License

[MIT](LICENSE) — use it, fork it, ship it.
