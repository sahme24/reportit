# Sandbox Link Analysis with Real-Time Progress Streaming

## Overview

This feature adds dynamic URL sandbox analysis and real-time progress updates to the ReportIT.ai scanner. When you scan an email, you'll now see:

1. **Real-time progress updates** as the scan progresses through parsing, URL extraction, reputation checks, and sandbox analysis
2. **Full landing page analysis** by actually visiting URLs in a headless browser:
   - Captures screenshots of the actual page
   - Detects credential harvesting forms (passwords, credit cards, SSN fields)
   - Identifies login pages with urgency language
   - Flags phishing techniques (iframes, obfuscated JS, redirects)
   - Analyzes network requests and tracking domains
3. **Threat scoring** based on phishing indicators found on the landing page (30-59 = SUSPICIOUS, 60+ = MALICIOUS)
4. **Incremental findings** displayed as they're discovered

## Architecture

### Backend

#### WebSocket Endpoint (`/ws/scan`)
- **Protocol**: WebSocket (bidirectional)
- **Authentication**: Session cookie required
- **Flow**:
  1. Client connects and sends scan request: `{raw, offline, kind, sender}`
  2. Server emits progress events in real-time
  3. Client renders progress updates incrementally
  4. Final event contains complete results

#### Progress Events

```json
{
  "type": "parse_started",
  "data": {}
}
```

```json
{
  "type": "urls_extracted",
  "data": {
    "count": 3,
    "urls": [
      {"url": "hxxps://example[.]com", "domain": "example.com"}
    ]
  }
}
```

```json
{
  "type": "reputation_check_started",
  "data": {"url_count": 3}
}
```

```json
{
  "type": "sandbox_starting",
  "data": {"url_count": 3}
}
```

```json
{
  "type": "sandbox_url_result",
  "data": {
    "url": "hxxps://example[.]com",
    "domain": "example.com",
    "threat_level": "suspicious",
    "threat_signals": ["Page load timeout"],
    "screenshot": "<base64-image-data>"
  }
}
```

```json
{
  "type": "scan_complete",
  "data": {
    "case_id": "1234",
    "verdict": "MALICIOUS",
    "confidence": "HIGH",
    "score": 75,
    ...
  }
}
```

### Sandbox Module (`threadline/sandbox.py`)

#### `is_available() -> bool`
Checks if Playwright is installed and available.

#### `sandbox_analyze_url(url, timeout_ms=30000) -> dict`
Visits a URL in a headless Chromium browser and analyzes the landing page:

**Page Analysis:**
- `screenshot`: Base64-encoded PNG of the actual landing page
- `title`: Page title (often spoofed by phishers)
- `has_login_form`: Detected login/authentication prompts
- `has_password_field`: Found password input field(s)
- `phishing_indicators`: List of detected phishing techniques

**Network Monitoring:**
- `network_requests`: List of all network requests made by the page
- `network_threats`: Suspicious domains contacted by the page
- `redirects`: Chain of HTTP redirects (chain length matters)
- `console_errors`: JavaScript console errors and warnings

**Threat Assessment:**
- `threat_level`: "none", "suspicious" (30-59 pts), or "malicious" (60+ pts)
- `threat_signals`: List of specific threat indicators found

**Scoring Formula:**
- Network threats: +25 points
- Obfuscated JS: +15 points  
- Phishing indicators (per indicator): +5 points
- Multiple phishing indicators: +30 base
- Password field + suspicious form: +20 points

#### `sandbox_finding(result, url) -> Finding | None`
Converts sandbox analysis results into a scanner Finding.

### Frontend

#### Progress Panel
Shows 4-stage pipeline with real-time updates:
1. **Parsing** - Extracting email structure
2. **Links** - Finding URLs in the email
3. **Reputation** - Checking reputation databases
4. **Sandbox** - Analyzing URLs in a browser

Each stage shows:
- Status indicator (⏳ running, ✓ done, ✗ error)
- Step details (e.g., number of links found)
- Per-URL results (for sandbox stage)

#### WebSocket Connection
JavaScript connects to `/ws/scan` on button click:
```javascript
const ws = new WebSocket(`ws://${location.host}/ws/scan`);
ws.send(JSON.stringify({
  raw: emailText,
  offline: isOfflineMode,
  kind: "email" | "sms",
  sender: smsSenderNumber
}));
```

Listens for progress events and updates UI incrementally.

## Installation

1. Install Playwright (optional, sandbox will gracefully skip if unavailable):
   ```bash
   pip install -r requirements.txt
   playwright install chromium
   ```

2. Run the app:
   ```bash
   uvicorn app:app --reload
   ```

3. Navigate to `/scan` and submit an email

## Features

### Graceful Degradation
- If Playwright is not installed, sandbox analysis is skipped
- Scan still completes with full results from URLhaus, VirusTotal, etc.
- No errors are raised; the system just doesn't perform dynamic analysis

### Real-Time Progress
- Each step emits progress events as it completes
- UI updates incrementally (no need to wait for entire scan)
- WebSocket allows bidirectional communication
- Progress panel shows which URLs are being analyzed

### Threat Detection
- Screenshots of landing pages
- Network request logging (detects C2 beacons, data exfil)
- JavaScript console error detection
- Redirect chain tracking
- Timeout detection (page hangs = suspicious)

## Configuration

### Environment Variables
- `SANDBOX_ENABLED`: Set to `false` to disable sandbox (default: true if Playwright available)

### Timeouts
- Per-URL sandbox timeout: 30 seconds (configurable in `sandbox.py`)
- Page wait strategy: "domcontentloaded"

### Parallel Analysis
- Maximum 5 concurrent URL analyses
- Prevents resource exhaustion

## Testing

Run the feature test:
```bash
python test_websocket_feature.py
```

Test manually:
1. Open http://localhost:8741/scan (after signing in)
2. Load a sample phishing email
3. Watch the progress panel update in real-time
4. Observe sandbox analysis for each URL (if Playwright installed)

## Backward Compatibility

- Old `/api/scan` POST endpoint still works (no changes)
- New WebSocket `/ws/scan` is addition-only
- Existing exports (JSON/Markdown) still work
- No database schema changes

## Performance

- **Without Playwright**: ~2-5 seconds (same as before)
- **With Playwright**: +30 seconds per URL (up to 5 parallel)
  - Example: 3 URLs → ~30 seconds additional (not 90)

## Known Limitations

1. **30-second timeout per URL** - pages that hang longer are marked as suspicious
2. **Screenshots limited to 500KB** - large pages are downsampled
3. **Network request log limited to 50 requests** - shows first 50 only
4. **Console errors limited to 5** - only reports first 5 JS errors
5. **Only analyzes first 10 URLs** - if email has more than 10 links, only first 10 get sandbox analysis
6. **No file downloads** - doesn't execute or download attachments
7. **No plugin/extension execution** - JavaScript-only analysis (no Flash, Java, etc.)

## What We DO Now (Changed)

✅ **We now visit links** - The sandbox actually navigates to URLs in a headless browser  
✅ **We capture landing pages** - Screenshots of what phishers show victims  
✅ **We detect phishing pages** - Login forms, credential harvesting, urgency tactics  
✅ **We analyze page behavior** - Network requests, redirects, obfuscated code  

This is no longer passive URL checking—it's active threat analysis.

## Future Enhancements

- DOM/HTML analysis for injected phishing elements
- Storage of full page HTML (not just screenshots)
- Cloud-based artifact storage for large screenshots
- Integration with known phishing page databases
- Machine learning classification of phishing likelihood
- Browser fingerprinting detection
- Cookie/tracking detection

## Security Notes

- Browser runs in isolated headless process
- No user data leakage (processes killed after timeout)
- Timeout prevents hanging on adversarial pages
- Network isolation available (if needed for sensitive analysis)
