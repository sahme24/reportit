"""OCR for image-based phishing: reads the text hidden inside images.

Scammers put the entire lure (text + URL) in an image so text-based filters
see nothing. This module extracts that text so the normal URL/urgency
checks can run on it.

Optional capability: requires the Tesseract binary on the system
(`apt install tesseract-ocr`, `choco install tesseract`, or
`brew install tesseract`). Everything fails soft when it's missing, so
scans still work, images just aren't read.
"""

from __future__ import annotations

import io
from functools import lru_cache

_MAX_PIXELS = 25_000_000  # decompression-bomb guard


@lru_cache(maxsize=1)
def is_available() -> bool:
    try:
        import pytesseract
        from PIL import Image  # noqa: F401
        pytesseract.get_tesseract_version()
        return True
    except Exception:
        return False


def extract_text(image_bytes: bytes) -> str:
    """Best-effort OCR. Returns "" on any failure, never raises."""
    if not is_available():
        return ""
    try:
        import pytesseract
        from PIL import Image
        with Image.open(io.BytesIO(image_bytes)) as img:
            if img.width * img.height > _MAX_PIXELS:
                return ""
            return pytesseract.image_to_string(img).strip()
    except Exception:
        return ""
