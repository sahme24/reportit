"""Threadline CLI — scan a raw email from a file or stdin."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .report import markdown_report
from .scanner import scan

_COLORS = {"bad": "\033[91m", "warn": "\033[93m", "ok": "\033[92m",
           "info": "\033[90m", "reset": "\033[0m", "bold": "\033[1m"}


def _c(name: str, text: str, enabled: bool) -> str:
    if not enabled:
        return text
    return f"{_COLORS[name]}{text}{_COLORS['reset']}"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="threadline",
        description="Automated phishing investigation — parse, analyze, report.")
    ap.add_argument("email", help="path to a raw email (.eml/.txt), or '-' for stdin")
    ap.add_argument("--offline", action="store_true",
                    help="skip all network reputation lookups")
    ap.add_argument("--json", action="store_true", dest="as_json",
                    help="print the full case as JSON")
    ap.add_argument("--report", metavar="OUT.md",
                    help="write a markdown report to this path")
    args = ap.parse_args(argv)

    # Windows consoles often default to cp1252, which can't print ● / →.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")

    if args.email == "-":
        raw = sys.stdin.buffer.read()
    else:
        path = Path(args.email)
        if not path.is_file():
            print(f"error: {path} not found", file=sys.stderr)
            return 2
        raw = path.read_bytes()

    case = scan(raw, offline=args.offline)

    if args.as_json:
        print(json.dumps(case.to_dict(), indent=2, ensure_ascii=False))
    else:
        color = sys.stdout.isatty()
        sev_color = {"MALICIOUS": "bad", "SUSPICIOUS": "warn",
                     "LIKELY CLEAN": "ok"}[case.verdict]
        print()
        print(_c("bold", f"  REPORTIT.AI · CASE #{case.case_id}", color))
        print(f"  {_c(sev_color, f'● {case.verdict} — {case.confidence} CONFIDENCE', color)}"
              f"  (score {case.score}/100)")
        print()
        print(f"  From:      {case.headers['from']}")
        print(f"  Subject:   {case.headers['subject']}")
        print(f"  Sender IP: {case.auth['sender_ip'] or 'not identified'}")
        print(f"  Auth:      SPF={case.auth['spf']}  DKIM={case.auth['dkim']}"
              f"  DMARC={case.auth['dmarc']}")
        print()
        print(_c("bold", "  FINDINGS", color))
        for f in case.findings:
            print(f"   {_c(f.severity, '●', color)} {_c('bold', f.title, color)}")
            print(f"     {f.detail}")
        print()
        print(_c("bold", "  ATTACK CHAIN", color))
        print("   " + "  →  ".join(
            _c(n.severity, f"{n.label} [{n.sub}]", color) for n in case.chain))
        print()

    if args.report:
        Path(args.report).write_text(markdown_report(case), encoding="utf-8")
        print(f"report written to {args.report}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
