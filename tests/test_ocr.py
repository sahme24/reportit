"""OCR (image-based phishing) tests.

The full pipeline test needs the Tesseract binary and is skipped where it
isn't installed (CI installs it). The fail-soft path is always tested.
"""

import io
from email.message import EmailMessage

import pytest

from threadline import ocr
from threadline.content import UNKNOWN, detect_language
from threadline.models import WARN
from threadline.scanner import _image_pressure_findings, scan


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


# The tests below feed text straight to the pressure check, the step that runs
# after OCR, so they run whether or not Tesseract is installed.

def test_english_pressure_language_in_image_is_unchanged():
    # English was the only language this check ever covered, and its finding
    # feeds the score. Routing it through language detection must not change
    # the title, weight or wording an English lure already produced.
    text = "Your password expires today. Verify your account now."
    findings = _image_pressure_findings(text, "notice.png")
    assert len(findings) == 1
    finding = findings[0]
    assert finding.title == "Pressure language inside an image"
    assert finding.severity == WARN
    assert finding.weight == 10
    assert finding.category == "image"
    assert finding.detail == (
        'OCR read pressure phrasing out of notice.png: "expires today", '
        '"verify your account". Hiding the lure in an image is a '
        "filter-evasion technique.")


def test_spanish_pressure_language_in_image_is_flagged():
    # Before this change the image text was only checked against English
    # phrases, so a Spanish lure hidden in a picture scored nothing even
    # though the Spanish pack would have caught it in the message body.
    text = "Su cuenta ha sido suspendida. Verifique su cuenta ahora."
    findings = _image_pressure_findings(text, "aviso.png")
    assert len(findings) == 1
    assert findings[0].title == "Pressure language inside an image"
    assert findings[0].weight == 10
    assert '"su cuenta ha sido suspendida"' in findings[0].detail
    assert "(Spanish patterns)" in findings[0].detail


def test_french_pressure_language_with_accents_in_image_is_flagged():
    # French phrases carry accents ("immédiatement", "bloqué"). The text is
    # casefolded before matching, and an accent lost along the way would
    # quietly turn a real match into a miss.
    text = "Votre compte a été bloqué. Cliquez immédiatement pour le réactiver."
    findings = _image_pressure_findings(text, "avis.png")
    assert len(findings) == 1
    assert '"immédiatement"' in findings[0].detail
    assert "(French patterns)" in findings[0].detail


def test_uppercase_image_text_still_matches():
    # Lures in images are often set in capitals for emphasis, while the
    # packs are stored in lowercase. Without case folding the loudest
    # warnings would be the ones that slip through.
    findings = _image_pressure_findings("YOUR PASSWORD EXPIRES TODAY", "a.png")
    assert len(findings) == 1
    assert '"expires today"' in findings[0].detail


def test_unknown_language_image_text_makes_no_pressure_claim():
    # Dutch has no pack. This text happens to contain the English phrase
    # "action required", which the old English-only check would have
    # reported. A hit on one borrowed English phrase says nothing about the
    # Dutch wording around it, so reporting pressure language would claim a
    # check that never happened.
    text = ("Action required: uw rekening is tijdelijk geblokkeerd wegens "
            "verdachte activiteit. Bevestig direct uw gegevens via "
            "onderstaande pagina.")
    assert detect_language(text) == UNKNOWN
    assert _image_pressure_findings(text, "bericht.png") == []


def test_image_text_without_pressure_wording_is_quiet():
    # A supported language on its own is not a signal. A calm Spanish order
    # confirmation in an image must add nothing to the score, or every
    # non-English receipt would look suspicious.
    text = ("Gracias por su compra. Hemos recibido su pedido y lo enviaremos "
            "pronto.")
    assert _image_pressure_findings(text, "recibo.png") == []


def test_image_pressure_check_rejects_text_that_is_not_a_string():
    # OCR returns "" on failure, never None. A None arriving here means a
    # caller broke that contract, and it should fail at this call rather
    # than deep inside language detection.
    raised = False
    try:
        _image_pressure_findings(None, "notice.png")
    except ValueError:
        raised = True
    assert raised


def test_image_pressure_check_rejects_a_filename_that_is_not_a_string():
    # The filename is written into the finding shown to the analyst. A
    # wrong type would only fail when that text is built, and only for
    # images that matched, so a bug would surface on real lures only.
    raised = False
    try:
        _image_pressure_findings("Your password expires today.", None)
    except ValueError:
        raised = True
    assert raised
