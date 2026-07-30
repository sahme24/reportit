"""Browser-based sandbox analysis: visit URLs and capture threat indicators."""

from __future__ import annotations

import asyncio
import base64
import io
import logging
from typing import Optional

from .models import Finding, BAD, WARN, INFO

logger = logging.getLogger(__name__)

# Detect Playwright availability at module load time
_PLAYWRIGHT_AVAILABLE = False
try:
    from playwright.async_api import async_playwright
    _PLAYWRIGHT_AVAILABLE = True
except ImportError:
    pass


def is_available() -> bool:
    """Check if Playwright sandbox analysis is available."""
    return _PLAYWRIGHT_AVAILABLE


async def _analyze_landing_page(page) -> dict:
    """Analyze the current page for phishing indicators."""
    indicators = []
    has_login_form = False
    has_password_field = False

    try:
        # Check for login forms
        login_keywords = [
            "login", "sign in", "sign-in", "signin", "log in", "log-in", "authenticate",
            "verify account", "verify your account", "confirm identity", "re-verify"
        ]

        form_text = await page.inner_text("body", timeout=5000).catch(lambda: "")
        form_text_lower = form_text.lower()

        if any(keyword in form_text_lower for keyword in login_keywords):
            has_login_form = True
            indicators.append("Page contains login/authentication prompts")

        # Check for password fields
        password_count = await page.query_selector_all("input[type='password']")
        if password_count:
            has_password_field = True
            indicators.append(f"Page has {len(password_count)} password input field(s)")

        # Check for credential-harvesting forms
        inputs = await page.query_selector_all("input")
        input_types = []
        for inp in inputs:
            input_type = await inp.get_attribute("type")
            placeholder = await inp.get_attribute("placeholder")
            name = await inp.get_attribute("name")
            if placeholder:
                input_types.append(placeholder.lower())
            if name:
                input_types.append(name.lower())

        # Suspicious field names
        suspicious_fields = [
            "password", "pwd", "pass", "credit card", "cc", "cvv", "ssn",
            "social security", "bank", "account", "username", "email"
        ]
        found_suspicious = [f for f in input_types if any(s in f for s in suspicious_fields)]
        if found_suspicious:
            indicators.append(f"Suspicious form fields detected: {', '.join(set(found_suspicious)[:3])}")

        # Check for iframes (common phishing tactic)
        iframes = await page.query_selector_all("iframe")
        if iframes:
            indicators.append(f"Page contains {len(iframes)} embedded iframe(s) (used to hide content)")

        # Check page title for spoofing
        title = await page.title()
        spoofing_keywords = [
            "verify", "confirm", "urgent", "action required", "update",
            "suspended", "locked", "limited", "restricted", "unusual activity"
        ]
        if any(keyword in title.lower() for keyword in spoofing_keywords):
            indicators.append(f"Page title contains urgency language: '{title}'")

        # Check for mixed content warnings (HTTP resources on HTTPS)
        mixed_content = [r for r in await page.context.pages[0].query_selector_all("*")
                        if await r.get_attribute("src")]
        # This is a simplified check

        # Check page content for common phishing phrases
        phishing_phrases = [
            "confirm your identity",
            "verify your account",
            "update payment information",
            "unusual activity detected",
            "temporary access",
            "re-enter your password",
            "click here immediately",
            "act now"
        ]
        for phrase in phishing_phrases:
            if phrase in form_text_lower:
                indicators.append(f"Phishing phrase detected: '{phrase}'")
                break

    except Exception as e:
        logger.debug(f"Error analyzing landing page: {e}")

    return {
        "phishing_indicators": indicators,
        "has_login_form": has_login_form,
        "has_password_field": has_password_field,
    }


async def sandbox_analyze_url(
    url: str, timeout_ms: int = 30000, max_screenshot_kb: int = 500
) -> dict:
    """Analyze a URL in a headless browser sandbox by actually visiting it.

    Returns dict with:
    - screenshot: base64 PNG of landing page
    - network_requests: list of {url, status, type} dicts
    - network_threats: list of suspicious domain patterns found
    - redirects: list of redirect chain
    - console_errors: list of JS console errors
    - phishing_indicators: list of detected phishing patterns on landing page
    - title: page title
    - has_login_form: bool - detected login/credential form
    - has_password_field: bool - detected password input field
    - threat_level: "none" | "suspicious" | "malicious"
    - threat_signals: list of threat indicators found
    """
    if not _PLAYWRIGHT_AVAILABLE:
        return {
            "screenshot": None,
            "network_requests": [],
            "network_threats": [],
            "redirects": [],
            "console_errors": [],
            "threat_level": "none",
            "threat_signals": [],
        }

    result = {
        "screenshot": None,
        "network_requests": [],
        "network_threats": [],
        "redirects": [],
        "console_errors": [],
        "phishing_indicators": [],
        "title": "",
        "has_login_form": False,
        "has_password_field": False,
        "threat_level": "none",
        "threat_signals": [],
    }

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(
                # Spoof a real browser to avoid detection
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                )
            )
            page = await context.new_page()

            # Track network activity
            requests_seen = []
            threats_found = []
            redirect_chain = []

            def on_request(request):
                req_url = request.url
                requests_seen.append({
                    "url": req_url,
                    "type": request.resource_type,
                })
                # Flag suspicious request patterns
                if _is_threat_domain(req_url):
                    threats_found.append(req_url)

            def on_response(response):
                # Track redirects (3xx status codes)
                if 300 <= response.status < 400:
                    redirect_chain.append({
                        "from": response.request.url,
                        "to": response.headers.get("location", "?"),
                        "status": response.status,
                    })

            page.on("request", on_request)
            page.on("response", on_response)

            # Capture console output
            console_messages = []
            page.on("console", lambda msg: console_messages.append({
                "type": msg.type,
                "text": msg.text,
            }))

            try:
                # Navigate to URL with timeout
                await page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)

                # Wait briefly for JS execution and dynamic content
                await asyncio.sleep(2)

                # Extract page title
                result["title"] = await page.title()

                # Analyze landing page for phishing indicators
                phishing_checks = await _analyze_landing_page(page)
                result.update(phishing_checks)

                # Capture screenshot (resize to avoid huge images)
                try:
                    screenshot = await page.screenshot(timeout=5000)
                    # Compress if needed
                    if len(screenshot) > max_screenshot_kb * 1024:
                        screenshot = await page.screenshot(
                            timeout=5000, scale="css"
                        )
                    result["screenshot"] = base64.b64encode(screenshot).decode("utf-8")
                except Exception as e:
                    logger.warning(f"Failed to capture screenshot for {url}: {e}")

            except asyncio.TimeoutError:
                result["threat_signals"].append("Page load timeout (suspicious)")
                result["threat_level"] = "suspicious"
            except Exception as e:
                logger.warning(f"Error navigating to {url}: {e}")
                result["threat_signals"].append(f"Navigation error: {type(e).__name__}")

            # Extract threats from console
            errors = [m for m in console_messages if m["type"] == "error"]
            result["console_errors"] = [m["text"][:200] for m in errors[:5]]

            # Analyze collected data
            result["network_requests"] = requests_seen[:50]  # Limit output
            result["network_threats"] = list(set(threats_found))
            result["redirects"] = redirect_chain

            # Determine threat level based on all indicators
            threat_score = 0

            # Network threats
            if result["network_threats"] or redirect_chain:
                threat_score += 25
                result["threat_signals"].append(
                    f"{len(result['network_threats'])} suspicious domains contacted"
                )

            # Console obfuscation
            if any("obfuscate" in m.get("text", "").lower() for m in console_messages):
                threat_score += 15
                result["threat_signals"].append("Obfuscated code detected in console")

            # Phishing indicators on landing page
            if result.get("phishing_indicators"):
                threat_score += 30 + (len(result["phishing_indicators"]) * 5)
                result["threat_signals"].extend(result["phishing_indicators"])

            # Password harvesting form
            if result.get("has_password_field") and result.get("phishing_indicators"):
                threat_score += 20
                result["threat_signals"].append("Password field detected on suspicious login form")

            # Set threat level based on score
            if threat_score >= 60:
                result["threat_level"] = "malicious"
            elif threat_score >= 30:
                result["threat_level"] = "suspicious"
            else:
                result["threat_level"] = "none"

            await context.close()
            await browser.close()

    except Exception as e:
        logger.error(f"Sandbox analysis failed for {url}: {e}")
        result["threat_signals"].append(f"Sandbox error: {type(e).__name__}")

    return result


def _is_threat_domain(url: str) -> bool:
    """Check if a domain in the URL matches known threat patterns."""
    threat_patterns = [
        "malware",
        "ransomware",
        "botnet",
        "phishing",
        "trojan",
        "c2",
        "c&c",
        "exfil",
        "beacon",
    ]
    url_lower = url.lower()
    return any(pattern in url_lower for pattern in threat_patterns)


def sandbox_finding(sandbox_result: dict, url: str) -> Optional[Finding]:
    """Convert sandbox result into a Finding if threats detected."""
    if not sandbox_result.get("threat_signals"):
        return None

    severity = BAD if sandbox_result["threat_level"] == "malicious" else WARN
    detail = "; ".join(sandbox_result["threat_signals"][:3])
    if len(sandbox_result["threat_signals"]) > 3:
        detail += f" (and {len(sandbox_result['threat_signals']) - 3} more)"

    return Finding(
        severity,
        "Sandbox detected threats",
        detail,
        weight=20 if severity == BAD else 10,
        category="sandbox",
    )
