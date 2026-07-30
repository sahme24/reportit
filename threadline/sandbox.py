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


async def sandbox_analyze_url(
    url: str, timeout_ms: int = 30000, max_screenshot_kb: int = 500
) -> dict:
    """Analyze a URL in a headless browser sandbox.

    Returns dict with:
    - screenshot: base64 PNG or None if capture failed
    - network_requests: list of {url, status, type} dicts
    - network_threats: list of suspicious domain patterns found
    - redirects: list of redirect chain
    - console_errors: list of JS console errors
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

                # Wait briefly for JS execution
                await asyncio.sleep(2)

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

            # Determine threat level
            if result["network_threats"] or redirect_chain:
                result["threat_level"] = "suspicious"
                result["threat_signals"].append(
                    f"{len(result['network_threats'])} suspicious domains contacted"
                )
            if any("obfuscate" in m.get("text", "").lower() for m in console_messages):
                result["threat_level"] = "suspicious"
                result["threat_signals"].append("Obfuscated code detected in console")

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
