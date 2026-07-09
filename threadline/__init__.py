"""Threadline — automated phishing investigation.

Parses a raw email, runs the checks a security analyst would do by hand
(header auth, typosquat detection, reputation lookups), and traces the
attack chain from spoofed sender to landing page.
"""

__version__ = "0.1.0"
