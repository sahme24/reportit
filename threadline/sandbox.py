"""Sandboxed link detonation: open a URL in a throwaway headless browser and
report what the landing page actually does.

Everything here is observation, not judgement-by-keyword. A login form is not
suspicious on its own -- real banks have login forms. What's suspicious is a
credential form somewhere the link didn't claim to go, or served over plain
HTTP, or on a throwaway TLD. The scoring below only fires on those
*combinations*, so a legitimate sign-in page scores zero.

Playwright is an optional dependency: when it isn't installed, `is_available()`
returns False and the scan simply skips this stage.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import os

from .auth import URGENCY_PHRASES
from .models import BAD, WARN, Finding
from .urlscan import SUSPICIOUS_TLDS, _registered_domain, _safe_urlparse

logger = logging.getLogger(__name__)

_PLAYWRIGHT_AVAILABLE = False
try:
    from playwright.async_api import Error as PlaywrightError
    from playwright.async_api import TimeoutError as PlaywrightTimeout
    from playwright.async_api import async_playwright
    _PLAYWRIGHT_AVAILABLE = True
except ImportError:  # pragma: no cover - depends on the deployment image
    PlaywrightError = PlaywrightTimeout = Exception

# A real browser UA: many phishing kits serve a blank decoy page to anything
# that self-identifies as automation, which would make every scan look clean.
_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

# Form fields that mean "this page is collecting credentials or payment data".
_CREDENTIAL_FIELDS = ("password", "passwd", "pwd", "cvv", "cvc", "card",
                      "cardnumber", "ssn", "sin", "socialsecurity", "iban",
                      "routing", "accountnumber", "pin", "otp", "mfa", "2fa")

# Console text that indicates deliberately obfuscated payloads.
_OBFUSCATION_MARKERS = ("eval(", "unescape(", "atob(", "fromcharcode",
                        "document.write(")


# Set REPORTIT_SANDBOX=off to keep the server from ever opening a link.
_ENABLED = os.environ.get("REPORTIT_SANDBOX", "on").lower() not in (
    "off", "0", "false", "no")

# Flipped to False the first time a launch fails because the browser binary
# isn't there (`pip install playwright` installs the bindings, not Chromium).
# Without this every scan would burn the full per-URL timeout re-discovering
# the same missing browser.
_BROWSER_USABLE = True


def is_available() -> bool:
    """True when detonation can actually run: bindings importable, a browser
    that has launched at least once, and not disabled by config."""
    return _PLAYWRIGHT_AVAILABLE and _ENABLED and _BROWSER_USABLE


def _blank_result() -> dict:
    return {
        "url": "",
        "final_url": "",
        "title": "",
        "screenshot": None,
        "landed_on": "",
        "cross_domain": False,
        "insecure": False,
        "has_password_field": False,
        "credential_fields": [],
        "iframe_count": 0,
        "urgent_text": "",
        "redirects": [],
        "third_party_hosts": [],
        "console_errors": [],
        "observations": [],
        "threat_level": "none",
        "threat_signals": [],
        "error": "",
    }


async def _observe_page(page) -> dict:
    """Read the loaded page. Pure observation -- no scoring here."""
    out = {
        "title": "",
        "has_password_field": False,
        "credential_fields": [],
        "iframe_count": 0,
        "urgent_text": "",
    }
    try:
        out["title"] = await page.title()
    except Exception:
        pass

    # Credential inputs: check the type plus the name/placeholder/id, since
    # kits routinely use type="text" with a name of "passwd" to dodge scanners.
    try:
        fields: set[str] = set()
        for handle in await page.query_selector_all("input"):
            attrs = []
            for attr in ("type", "name", "id", "placeholder", "autocomplete"):
                try:
                    value = await handle.get_attribute(attr)
                except Exception:
                    value = None
                if value:
                    attrs.append(value.lower())
            if "password" in attrs:
                out["has_password_field"] = True
                fields.add("password")
            blob = " ".join(attrs).replace("-", "").replace("_", "")
            for name in _CREDENTIAL_FIELDS:
                if name in blob:
                    fields.add(name)
                    if name in ("password", "passwd", "pwd"):
                        out["has_password_field"] = True
        out["credential_fields"] = sorted(fields)
    except Exception as e:
        logger.debug("input inspection failed: %s", e)

    try:
        out["iframe_count"] = len(await page.query_selector_all("iframe"))
    except Exception:
        pass

    # Urgency wording on the landing page itself, using the same phrase list
    # the message-content analyzer already uses.
    try:
        body = (await page.inner_text("body", timeout=5000)).lower()
        hit = next((p for p in URGENCY_PHRASES if p in body), "")
        out["urgent_text"] = hit
    except Exception:
        pass

    return out


def _score(result: dict) -> tuple[int, list[str]]:
    """Turn observations into a score. Only combinations score -- a plain
    credential form on its own domain over HTTPS is worth nothing."""
    score = 0
    signals: list[str] = []
    creds = result["has_password_field"] or bool(result["credential_fields"])
    tld = result["landed_on"].rsplit(".", 1)[-1] if result["landed_on"] else ""
    bad_tld = tld in SUSPICIOUS_TLDS

    if result["cross_domain"]:
        score += 20
        signals.append(
            f"the link silently landed on {result['landed_on']}, a different "
            "registered domain than the one in the message")

    if creds and result["insecure"]:
        score += 35
        signals.append("asks for credentials over an unencrypted http "
                       "connection")
    if creds and result["cross_domain"]:
        score += 30
        signals.append("asks for credentials on a domain the link didn't "
                       "claim to go to")
    if creds and bad_tld:
        score += 30
        signals.append(f"asks for credentials on a high-abuse .{tld} domain")
    if creds and result["urgent_text"]:
        score += 20
        signals.append("pairs a credential form with pressure wording "
                       f'("{result["urgent_text"]}")')
    if creds and result["iframe_count"]:
        score += 15
        signals.append("credential form sits alongside embedded frames, a "
                       "common overlay trick")

    if bad_tld and not creds:
        score += 15
        signals.append(f"landing page sits on a high-abuse .{tld} domain")

    obfuscated = [e for e in result["console_errors"]
                  if any(m in e.lower() for m in _OBFUSCATION_MARKERS)]
    if obfuscated:
        score += 15
        signals.append("landing page runs obfuscated script")

    return score, signals


async def detonate(url: str, timeout_ms: int = 30000) -> dict:
    """Open `url` in a disposable browser context and report what it does.

    Never raises: any failure comes back as a result with `error` set, so one
    dead link can't take a scan down.
    """
    result = _blank_result()
    result["url"] = url
    if not _PLAYWRIGHT_AVAILABLE:
        return result

    origin_domain = _registered_domain(
        (_safe_urlparse(url).hostname or "").lower())

    requests_seen: list[str] = []
    redirects: list[dict] = []
    console_errors: list[str] = []

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            try:
                context = await browser.new_context(
                    user_agent=_UA, ignore_https_errors=True,
                    viewport={"width": 1280, "height": 800})
                page = await context.new_page()

                page.on("request", lambda r: requests_seen.append(r.url))
                page.on("response", lambda r: redirects.append({
                    "from": r.request.url,
                    "to": r.headers.get("location", ""),
                    "status": r.status,
                }) if 300 <= r.status < 400 else None)
                page.on("console", lambda m: console_errors.append(m.text)
                        if m.type in ("error", "warning") else None)

                try:
                    await page.goto(url, wait_until="domcontentloaded",
                                    timeout=timeout_ms)
                    # Let client-side redirects and injected forms settle.
                    await asyncio.sleep(2)
                    observed = await _observe_page(page)
                    result.update(observed)
                    result["final_url"] = page.url

                    try:
                        shot = await page.screenshot(
                            type="jpeg", quality=60, timeout=8000)
                        result["screenshot"] = base64.b64encode(shot).decode()
                    except Exception as e:
                        logger.debug("screenshot failed for %s: %s", url, e)

                except PlaywrightTimeout:
                    result["error"] = "timeout"
                    result["final_url"] = page.url or url
                except PlaywrightError as e:
                    # Unreachable host, DNS failure, cert refusal, etc.
                    result["error"] = str(e).splitlines()[0][:160]
            finally:
                await browser.close()
    except Exception as e:  # launch failure, missing browser binary, ...
        global _BROWSER_USABLE
        if "executable doesn't exist" in str(e).lower():
            # No Chromium on this host. Stop trying: otherwise every URL of
            # every later scan pays the same failure again.
            _BROWSER_USABLE = False
            logger.error("sandbox disabled: no Chromium. Run "
                         "`playwright install chromium`.")
        else:
            logger.warning("detonation failed for %s: %s", url, e)
        result["error"] = type(e).__name__
        return result

    final_host = (_safe_urlparse(result["final_url"] or url).hostname or "").lower()
    result["landed_on"] = _registered_domain(final_host)
    result["cross_domain"] = bool(
        result["landed_on"] and origin_domain
        and result["landed_on"] != origin_domain)
    result["insecure"] = (result["final_url"] or url).lower().startswith("http://")
    result["redirects"] = redirects[:10]
    result["console_errors"] = [e[:200] for e in console_errors[:5]]
    result["third_party_hosts"] = sorted({
        h for h in ((_safe_urlparse(r).hostname or "").lower()
                    for r in requests_seen)
        if h and _registered_domain(h) != result["landed_on"]})[:15]

    # Plain-language observations, shown whether or not anything scored.
    obs = []
    if result["credential_fields"]:
        obs.append("collects " + ", ".join(result["credential_fields"][:4]))
    if result["cross_domain"]:
        obs.append(f"redirected to {result['landed_on']}")
    if result["iframe_count"]:
        obs.append(f"{result['iframe_count']} embedded frame(s)")
    if result["third_party_hosts"]:
        obs.append(f"{len(result['third_party_hosts'])} third-party host(s)")
    result["observations"] = obs

    if result["error"] == "timeout":
        result["threat_signals"] = ["page never finished loading within "
                                    f"{timeout_ms // 1000}s"]
        result["threat_level"] = "none"
        return result
    if result["error"]:
        return result

    score, signals = _score(result)
    result["threat_signals"] = signals
    result["threat_level"] = ("malicious" if score >= 55
                              else "suspicious" if score >= 25 else "none")
    return result


# Back-compat alias for the original name.
sandbox_analyze_url = detonate


def sandbox_finding(result: dict, url: str) -> Finding | None:
    """A Finding for a detonated link, or None when nothing notable happened."""
    signals = result.get("threat_signals") or []
    level = result.get("threat_level", "none")

    if level == "malicious":
        return Finding(BAD, f"Landing page is a credential trap: {result['landed_on']}",
                       f"Opened {url} in a sandbox: " + "; ".join(signals) + ".",
                       weight=30, category="sandbox")
    if level == "suspicious":
        return Finding(WARN, f"Landing page behaved suspiciously: {result['landed_on']}",
                       f"Opened {url} in a sandbox: " + "; ".join(signals) + ".",
                       weight=15, category="sandbox")
    return None
