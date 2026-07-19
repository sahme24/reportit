"""Language-aware content layer: detection, per-language patterns, anomalies."""

from threadline.content import content_findings, detect_language
from threadline.sms import scan_sms


def test_detect_language():
    assert detect_language("Votre colis est en attente, veuillez cliquez sur "
                           "le lien pour reprogrammer la livraison") == "fr"
    assert detect_language("حسابك موقوف. اضغط على الرابط لتأكيد هويتك") == "ar"
    assert detect_language("Your package could not be delivered.") == "en"


def test_french_urgency_and_info_request():
    lang, findings, matched = content_findings(
        "Dernier rappel : votre compte sera suspendu sous 24 heures. "
        "Confirmez votre mot de passe et votre numéro de carte.")
    assert lang == "fr"
    titles = [f.title for f in findings]
    assert "Urgency and pressure language" in titles
    assert "Asks for sensitive information" in titles
    assert "dernier rappel" in matched


def test_arabic_smishing_scores_without_any_link():
    case = scan_sms("عاجل: تم تعليق حسابك البنكي. أكد هويتك وأرسل الرمز "
                    "خلال 24 ساعة", sender="+966 55 013 4477", offline=True)
    assert case.language == "ar"
    assert case.verdict in ("SUSPICIOUS", "MALICIOUS")
    assert any(f.category == "content" for f in case.findings)


def test_english_authority_and_anomalies():
    lang, findings, _ = content_findings(
        "This is the Canada Revenue Agency. URGENT FINAL NOTICE!!! "
        "You MUST confirm your PIN NOW or face LEGAL consequences !")
    assert lang == "en"
    titles = [f.title for f in findings]
    assert "Claims institutional authority" in titles
    assert "Excessive punctuation" in titles
    assert "Shouting case" in titles


def test_benign_text_stays_quiet():
    lang, findings, matched = content_findings(
        "Hey, are we still on for lunch tomorrow at noon? My treat.")
    assert lang == "en"
    assert not findings and not matched
