# 🧵 Threadline

**Open-source phishing investigation for everyone.**

Every phishing email tells a story. Threadline reads it — automating the manual
investigation a security analyst does by hand: parsing headers, verifying
authentication, hunting typosquats, querying threat intel, and tracing the
attack chain from spoofed sender to landing page.

Enterprises have SOC teams and commercial platforms for this. The average
person has a spam folder. Threadline closes that gap — free, self-hostable,
and fully auditable.

## Features

- **Analyst-grade checks** — 40+ heuristics across headers, URLs, attachments,
  and content, plus optional reputation lookups
- **Attack chain visualization** — sender → auth check → link → landing page,
  color-coded by risk
- **Case files, not pass/fail** — every scan gets a case number, a 0–100 risk
  score, findings in plain language, and an exportable markdown/JSON report
- **Accounts & case history** — your investigations are saved; repeat
  offenders (same sender/domain across cases) are flagged automatically
- **Admin dashboard** — user growth, cases per day, verdict breakdown
- **Light & dark themes** — night-shift SOC desk or paper case file
- **CLI included** — everything works from the terminal too

## Quick start

```bash
git clone https://github.com/YOURUSERNAME/threadline
cd threadline
pip install -r requirements.txt

# web app
uvicorn app:app
# → open http://127.0.0.1:8000
# the FIRST account you create becomes the admin (that's you — sign up first!)

# or straight from the terminal
python -m threadline samples/phish-0ffice365.eml
python -m threadline suspicious.eml --report case.md
python -m threadline suspicious.eml --json
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

## Threat-intel keys (optional)

Providers activate automatically when a key exists. Create a `.env` file:

```
VT_API_KEY=...          # virustotal.com — free tier
ABUSEIPDB_API_KEY=...   # abuseipdb.com — free tier
URLHAUS_API_KEY=...     # auth.abuse.ch — free
```

No keys? Threadline still runs every offline heuristic plus RDAP domain-age
checks. Lookups fail soft — a dead API never breaks a scan.

## Why you can trust it

- **Every heuristic is public code** — read [`threadline/`](threadline), it's small on purpose
- **Runs on your machine** — Python + SQLite, no cloud dependency
- **Defanged by design** — reports neutralize URLs (`hxxps://…[.]com`);
  Threadline never visits links found in a message
- **Your data stays put** — accounts and scan history live in a local
  `threadline.db`; the only outbound traffic is the reputation lookups you
  enable

## Project layout

```
threadline/
  parser.py       raw email → headers, auth results, sender IP, bodies, attachments
  auth.py         SPF/DKIM/DMARC + spoofing findings
  urlscan.py      URL extraction + typosquat/heuristic analysis
  reputation.py   RDAP, VirusTotal, AbuseIPDB, URLhaus
  scanner.py      orchestration, scoring, attack-chain builder
  report.py       markdown report generation
  db.py           SQLite: users, sessions, scan history
  cli.py          terminal interface
app.py            FastAPI backend (pages + JSON API)
static/           web UI — landing, auth, scanner, history, admin dashboard
samples/          sanitized test emails (one phish, one clean)
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
