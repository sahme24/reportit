"""OCR (image-based phishing) tests.

The full pipeline test needs the Tesseract binary and is skipped where it
isn't installed (CI installs it). The fail-soft path is always tested.
"""

import io
from email.message import EmailMessage

import pytest

from threadline import ocr
from threadline.scanner import scan


def _email_with_image(png: bytes) -> bytes:
    msg = EmailMessage()
    msg["From"] = "IT Support <alerts@secure-mail-notify.top>"
    msg["To"] = "victim@example.org"
    msg["Subject"] = "Notice"
    msg.set_content("See attached notice.")
    msg.add_attachment(png, maintype="image", subtype="png",
                       filename="notice.png")
    return bytes(msg)


def _phish_png() -> bytes:
    from PIL import Image, ImageDraw
    img = Image.new("RGB", (900, 220), "white")
    draw = ImageDraw.Draw(img)
    draw.text((20, 40), "Your password expires today.", fill="black")
    draw.text((20, 90), "Verify your account now:", fill="black")
    draw.text((20, 140), "https://0ffice365-secure.com/reset", fill="black")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def test_ocr_never_raises_without_tesseract():
    # extract_text must fail soft on garbage input regardless of install.
    assert ocr.extract_text(b"not an image") == ""


def test_image_email_notes_ocr_state():
    case = scan(_email_with_image(_phish_png()), offline=True)
    categories = {f.category for f in case.findings}
    # With Tesseract: an "image" finding about the hidden link/urgency.
    # Without: the INFO note that images weren't checked. Either way the
    # scan must acknowledge the image.
    assert "image" in categories


@pytest.mark.skipif(not ocr.is_available(), reason="Tesseract not installed")
def test_hidden_link_in_image_is_detected():
    case = scan(_email_with_image(_phish_png()), offline=True)
    image_findings = [f for f in case.findings if f.category == "image"]
    assert any("Link hidden inside an image" in f.title
               for f in image_findings)
    # The OCR'd typosquat joins the URL pipeline and gets flagged there too.
    assert any("0ffice365-secure" in u.url for u in case.urls)
    assert case.verdict in ("MALICIOUS", "SUSPICIOUS")
