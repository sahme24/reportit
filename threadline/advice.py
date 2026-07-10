"""Actionable next steps — answers "okay, so what do I do now?" for every case.

Deterministic user education: no AI required, works offline, and shows up in
the UI, the CLI, and the exported report.
"""

from __future__ import annotations

from .models import BAD, Finding


def advice_for(kind: str, verdict: str, findings: list[Finding]) -> list[str]:
    sms = kind == "sms"
    bad_categories = {f.category for f in findings if f.severity == BAD}
    steps: list[str] = []

    if verdict == "MALICIOUS":
        steps.append(
            "Don't tap the link or reply — replying tells the scammer your "
            "number is active." if sms else
            "Don't click any links, download attachments, or reply.")
        if "attachment" in bad_categories:
            steps.append("Do not open the attachment — it's a directly "
                         "executable file type.")
        steps.append(
            "Report it: forward the text to 7726 (SPAM) — free in the US and "
            "Canada." if sms else
            'Report it: use your mail app\'s "Report phishing" button, or '
            "forward it to reportphishing@apwg.org.")
        steps.append("Block the sender, then delete the message.")
        steps.append("Already clicked or entered a password? Change that "
                     "password now — typed by hand on the official site — and "
                     "turn on two-factor authentication.")
    elif verdict == "SUSPICIOUS":
        steps.append("Treat the links and phone numbers in this message as "
                     "unsafe until proven otherwise.")
        steps.append("Verify directly with the organization: open their "
                     "official app or type their web address yourself — never "
                     "use the message's links or numbers.")
        steps.append("If it turns out to be fake, " + (
            "forward it to 7726 (SPAM) and block the sender." if sms else
            "report it as phishing in your mail app and block the sender."))
    else:  # LIKELY CLEAN
        steps.append("Nothing dangerous was found — but automated checks "
                     "aren't a guarantee, so stay alert.")
        if any(f.category == "auth" and "forward" in f.title.lower()
               for f in findings):
            steps.append("The authentication failures here come from the "
                         "message being forwarded — that pattern is normal "
                         "and not evidence of spoofing.")
        steps.append("Golden rule: when a message asks you to act, go to the "
                     "site or app yourself instead of using its link.")
    return steps
