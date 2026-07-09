"""URL extraction and offline domain heuristics (typosquats, bad TLDs, etc.)."""

from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import urlparse

from .models import UrlInfo

URL_RE = re.compile(r"""(?:hxxps?|https?)://[^\s<>"'\)\]]+""", re.I)

# Brands most commonly impersonated, mapped to their legitimate apex domains.
BRANDS: dict[str, tuple[str, ...]] = {
    "office365": ("microsoft.com", "office.com", "microsoftonline.com", "office365.com"),
    "microsoft": ("microsoft.com", "live.com", "outlook.com"),
    "outlook": ("outlook.com", "microsoft.com"),
    "paypal": ("paypal.com",),
    "google": ("google.com", "gmail.com"),
    "apple": ("apple.com", "icloud.com"),
    "amazon": ("amazon.com", "amazon.ca"),
    "netflix": ("netflix.com",),
    "docusign": ("docusign.com", "docusign.net"),
    "dropbox": ("dropbox.com",),
    "linkedin": ("linkedin.com",),
    "facebook": ("facebook.com",),
    "instagram": ("instagram.com",),
    "interac": ("interac.ca",),
    "fedex": ("fedex.com",),
    "dhl": ("dhl.com",),
    "ups": ("ups.com",),
    "canadapost": ("canadapost.ca", "canadapost-postescanada.ca"),
    "cra": ("canada.ca",),
    "chase": ("chase.com",),
    "wellsfargo": ("wellsfargo.com",),
}

SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "icu", "click", "link", "cam", "rest", "buzz",
    "gq", "tk", "ml", "cf", "ga", "work", "support", "loan", "country",
}

# Web-infrastructure domains that appear in HTML boilerplate (DOCTYPEs,
# xmlns declarations, font CDNs) — never meaningful phishing indicators.
INFRA_DOMAINS = {"w3.org", "schema.org", "googleapis.com", "gstatic.com"}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "buff.ly",
    "rebrand.ly", "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc",
}

# Common visual substitutions attackers use ("0ffice", "paypa1", "rnicrosoft").
_HOMOGLYPHS = [("0", "o"), ("1", "l"), ("3", "e"), ("5", "s"), ("7", "t"),
               ("rn", "m"), ("vv", "w"), ("cl", "d")]

# Per-character alternatives for building "brand with substitutions" regexes.
_GLYPH_ALTS = {"o": "[o0]", "l": "[l1]", "i": "[il1]", "e": "[e3]", "s": "[s5]",
               "t": "[t7]", "a": "[a4]", "m": "(?:m|rn)", "w": "(?:w|vv)",
               "d": "(?:d|cl)"}


def _brand_regex(brand: str) -> re.Pattern:
    body = "".join(_GLYPH_ALTS.get(c, re.escape(c)) for c in brand)
    # Letter boundaries so "ups" doesn't match inside "groups.com".
    return re.compile(rf"(?<![a-z]){body}(?![a-z])")


BRAND_PATTERNS = {brand: _brand_regex(brand) for brand in BRANDS}
_ALL_LEGIT = {d for domains in BRANDS.values() for d in domains}


def match_brand(domain: str) -> tuple[str, str, bool] | None:
    """If `domain` imitates a known brand without being the real thing,
    return (brand, legit_domain, used_character_substitution)."""
    if any(domain == d or domain.endswith("." + d) for d in _ALL_LEGIT):
        return None
    label = domain.rsplit(".", 1)[0]
    for brand, legit in BRANDS.items():
        m = BRAND_PATTERNS[brand].search(domain)
        if m:
            return brand, legit[0], m.group(0) != brand
        if _levenshtein(label, brand) <= (1 if len(brand) <= 6 else 2):
            return brand, legit[0], False
    return None


def _defang_host(host: str) -> str:
    parts = host.rsplit(".", 1)
    return "[.]".join(parts) if len(parts) == 2 else host


def refang(url: str) -> str:
    return url.replace("hxxp", "http").replace("[.]", ".").replace("[:]", ":")


def _deglyph(s: str) -> str:
    for fake, real in _HOMOGLYPHS:
        s = s.replace(fake, real)
    return s


def _levenshtein(a: str, b: str) -> int:
    if abs(len(a) - len(b)) > 2:
        return 3  # early out — we only care about distance <= 2
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _registered_domain(host: str) -> str:
    """Crude eTLD+1 — good enough without a public-suffix dependency."""
    parts = host.split(".")
    if len(parts) >= 3 and parts[-2] in ("co", "com", "net", "org", "gc", "gov", "ac"):
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


class _HrefParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[tuple[str, str]] = []  # (href, anchor text)
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href:
            self.links.append((self._href, "".join(self._text).strip()))
            self._href = None


def _is_infra(url: str) -> bool:
    host = (urlparse(url).hostname or "").lower()
    return _registered_domain(host) in INFRA_DOMAINS


def extract_urls(body_text: str, body_html: str) -> list[tuple[str, str]]:
    """Return deduped (url, anchor_text) pairs from both bodies.

    DOCTYPE/xmlns/font-CDN boilerplate (w3.org etc.) is dropped — it appears
    in virtually every HTML email and carries no signal.
    """
    seen: dict[str, str] = {}
    for match in URL_RE.findall(body_text or ""):
        url = refang(match.rstrip(".,;"))
        seen.setdefault(url, "")
    if body_html:
        hp = _HrefParser()
        try:
            hp.feed(body_html)
        except Exception:
            pass
        for href, text in hp.links:
            if href.lower().startswith(("http", "hxxp")):
                seen[refang(href)] = text
        for match in URL_RE.findall(body_html):
            seen.setdefault(refang(match.rstrip(".,;")), "")
    return [(u, t) for u, t in seen.items() if not _is_infra(u)]


def analyze_url(url: str, anchor_text: str = "") -> UrlInfo:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    domain = _registered_domain(host)
    flags: list[str] = []

    if not host:
        return UrlInfo(url=url, domain="", defanged=url, flags=["unparseable URL"])

    # IP-literal target
    if re.fullmatch(r"[0-9.]+", host):
        flags.append("links directly to an IP address")

    # Punycode / IDN
    if host.startswith("xn--") or ".xn--" in host:
        flags.append("punycode (internationalized) hostname — possible homoglyph attack")

    # Credentials-in-URL trick (https://paypal.com@evil.com/)
    if "@" in url.split("://", 1)[-1].split("/", 1)[0]:
        flags.append("contains userinfo '@' — real destination hidden after the @")

    # Suspicious TLD
    tld = host.rsplit(".", 1)[-1]
    if tld in SUSPICIOUS_TLDS:
        flags.append(f"high-abuse TLD .{tld}")

    # Shortener
    if domain in SHORTENERS:
        flags.append("URL shortener — final destination hidden")

    # Excessive subdomain nesting
    if host.count(".") >= 4:
        flags.append("deeply nested subdomains")

    # Plain HTTP
    if parsed.scheme == "http":
        flags.append("unencrypted http link")

    # Brand impersonation: brand string appears in the domain (possibly
    # homoglyphed) but the registered domain isn't the brand's real one.
    match_result = match_brand(domain)
    if match_result:
        brand, legit, substituted = match_result
        note = f'impersonates "{brand}" ({legit} is the real domain)'
        if substituted:
            note += " — uses character substitution"
        flags.append(note)

    # Anchor text says one domain, href goes to another
    if anchor_text:
        m = URL_RE.search(anchor_text)
        if m:
            shown = _registered_domain((urlparse(refang(m.group(0))).hostname or "").lower())
            if shown and shown != domain:
                flags.append(f"link text shows {shown} but points to {domain}")

    defanged = url.replace("http", "hxxp", 1).replace(host, _defang_host(host), 1)
    return UrlInfo(url=url, domain=domain, defanged=defanged, flags=flags)
