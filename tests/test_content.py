"""Language-aware content layer: detection, per-language patterns, anomalies."""

import json
from pathlib import Path

from threadline.content import (LANGUAGES, UNKNOWN, _LANG_NAMES,
                                content_findings, detect_language)
from threadline.sms import scan_sms

ROOT = Path(__file__).resolve().parent.parent
PATTERN_DIR = ROOT / "threadline" / "patterns"
DASHBOARD = ROOT / "static" / "dashboard.html"

# One realistic scam per newly supported language. Each contains at least one
# urgency phrase and one credential request from that language's pack.
ES_SCAM = ("Estimado cliente, su cuenta ha sido suspendida por actividad inusual. "
           "Ingrese su contraseña y el número de tarjeta para reactivarla.")
PT_SCAM = ("Sua conta foi bloqueada por atividade suspeita. Informe sua senha e "
           "o número do cartão para evitar o bloqueio.")
IT_SCAM = ("Gentile cliente, il tuo conto è stato bloccato. Inserisci la tua "
           "password e il numero della carta entro oggi.")
DE_SCAM = ("Ihr Konto wurde gesperrt. Bitte bestätigen Sie Ihre Identität und "
           "geben Sie Ihr Passwort ein.")
RU_SCAM = ("Ваша карта заблокирована из-за подозрительной активности. "
           "Сообщите код из СМС и номер карты.")
HI_SCAM = "आपका खाता ब्लॉक कर दिया गया है। तुरंत अपना ओटीपी बताएं और कार्ड नंबर भेजें।"
ZH_SCAM = "您的账户已被冻结，请立即验证并提供验证码和银行卡号。"

# Dutch has no pack. This is plainly urgent, which is what makes it a useful
# check that an unsupported language no longer reads as a calm message.
DUTCH_SCAM = ("Beste klant, uw rekening is tijdelijk geblokkeerd wegens verdachte "
              "activiteit. Bevestig direct uw gegevens via onderstaande pagina.")
JA_SCAM = "お客様のアカウントが一時的に停止されました。今すぐ確認してください。"

# The link alone has more Latin letters than the Arabic has letters in total,
# enough to push the Arabic share under the detection threshold if URLs were
# counted.
AR_WITH_LINK = ("حسابك موقوف. اضغط على الرابط "
                "https://secure-verification-center-account-protection-update-"
                "portal.example-banking-services.com/confirm-identity-immediately "
                "لتأكيد هويتك")


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


def test_every_language_has_a_complete_pack():
    # detect_language() can hand back any code in LANGUAGES. A code with no
    # pattern file, or a file missing a family, would make every message in
    # that language match nothing and look calm, which is the silent failure
    # this whole change exists to remove.
    for code in LANGUAGES:
        path = PATTERN_DIR / (code + ".json")
        assert path.is_file(), code + " has no pattern file"
        pack = json.loads(path.read_text(encoding="utf-8"))
        for family in ("urgency", "urgency_sms_extra", "info_request", "authority"):
            assert family in pack, code + " is missing " + family
            assert len(pack[family]) > 0, code + " has an empty " + family
        # Exercises the finding-text path, which looks the language's display
        # name up and would raise if the name were missing.
        content_findings("placeholder text", lang=code)


def test_every_pattern_phrase_can_actually_match():
    # Phrases are compared against the casefolded message. A phrase holding a
    # capital letter, a German ß (casefold turns it into "ss"), or stray
    # spaces at either end can never be found, and nothing else would ever
    # reveal that it was dead.
    for code in LANGUAGES:
        pack = json.loads((PATTERN_DIR / (code + ".json")).read_text(encoding="utf-8"))
        for family in pack:
            if family == "_comment":
                continue
            for phrase in pack[family]:
                assert phrase != "", code + " " + family + " contains an empty phrase"
                assert phrase == phrase.casefold(), code + ": " + phrase + " is not casefolded"
                assert phrase == phrase.strip(), code + ": " + repr(phrase) + " has edge spaces"


def test_each_new_pack_flags_pressure_and_credential_requests():
    # Proves each new language works end to end: recognised, its pack loaded,
    # and real scam wording caught in the two families that carry the most
    # weight. A pack that never fires is indistinguishable from no pack.
    samples = (("es", ES_SCAM), ("pt", PT_SCAM), ("it", IT_SCAM), ("de", DE_SCAM),
               ("ru", RU_SCAM), ("hi", HI_SCAM), ("zh", ZH_SCAM))
    for code, text in samples:
        lang, findings, matched = content_findings(text)
        assert lang == code, code + " was detected as " + lang
        titles = []
        for finding in findings:
            titles.append(finding.title)
        assert "Urgency and pressure language" in titles, code + " missed the urgency"
        assert "Asks for sensitive information" in titles, code + " missed the credential request"
        assert len(matched) > 0, code + " reported no matched phrases to highlight"


def test_spanish_and_portuguese_are_not_confused():
    # Both texts lean on words the two languages share ("pedido", "esta",
    # "para"). Mixing them up runs the wrong pack, and an obvious scam then
    # matches nothing at all.
    assert detect_language("Hemos recibido su pedido y esta es la confirmación "
                           "para usted.") == "es"
    assert detect_language("Seu pedido foi enviado e esta é a confirmação "
                           "para você.") == "pt"


def test_italian_is_not_mistaken_for_spanish():
    # Italian and Spanish share much of their vocabulary. Reading an Italian
    # parcel notice as Spanish would check it against the wrong phrases.
    assert detect_language("Gentile cliente, il tuo pacco è in viaggio e sarà "
                           "consegnato domani.") == "it"


def test_unsupported_language_is_flagged_instead_of_read_as_english():
    # Before this change a Dutch message was checked against English phrases,
    # matched none, and a plainly urgent scam came back looking calm. It must
    # now say the language isn't covered and must not claim to have checked
    # for pressure wording.
    lang, findings, matched = content_findings(DUTCH_SCAM)
    assert lang == UNKNOWN
    titles = []
    for finding in findings:
        titles.append(finding.title)
    assert "Language not covered" in titles
    assert "Urgency and pressure language" not in titles
    assert matched == []


def test_japanese_is_not_read_as_chinese():
    # Japanese uses Chinese characters alongside its own kana. Treating it as
    # Chinese would run the Chinese pack over a language it doesn't cover and
    # report the result as if it meant something.
    assert detect_language(JA_SCAM) == UNKNOWN


def test_a_long_link_does_not_hide_the_message_language():
    # A URL is a long run of Latin letters. Counted as text, one link in an
    # Arabic SMS outweighs the Arabic words, and the message stops being
    # recognised as Arabic.
    assert detect_language(AR_WITH_LINK) == "ar"


def test_very_short_or_empty_message_defaults_to_english():
    # A couple of words is too little to identify a language, and an empty
    # body has none at all. Calling either unknown would pin a "language not
    # covered" note onto every short reply and every image-only email.
    lang, findings, _ = content_findings("Ok, noted.")
    assert lang == "en"
    assert findings == []
    lang, findings, _ = content_findings("")
    assert lang == "en"
    assert findings == []


def test_rejects_an_unsupported_language_code():
    # A mistyped code passed in explicitly would load no pack and come back
    # looking like a clean scan. It has to fail loudly instead.
    raised = False
    try:
        content_findings("hello there", lang="xx")
    except ValueError:
        raised = True
    assert raised


def test_rejects_an_unknown_message_kind():
    # Anything other than "sms" used to be treated as email without a word,
    # so a slip like kind="SMS" quietly dropped every SMS-only phrase.
    raised = False
    try:
        content_findings("hello there", kind="SMS")
    except ValueError:
        raised = True
    assert raised


def test_rejects_text_that_is_not_a_string():
    # Callers build this text from parsed message parts. A None slipping
    # through would otherwise surface as an AttributeError deep inside
    # casefold(), far from where the bad value came from.
    raised = False
    try:
        detect_language(None)
    except ValueError:
        raised = True
    assert raised


def test_dashboard_lists_exactly_the_supported_languages():
    # The "Now supports" line is hard-coded HTML. Checking only that each
    # name appears somewhere would miss a language left listed after its
    # pack was removed, so the list must name exactly the supported
    # languages -- in alphabetical order, which is how the page shows them.
    html = DASHBOARD.read_text(encoding="utf-8")
    start = html.index("Now supports <b>") + len("Now supports <b>")
    end = html.index("</b>", start)
    # Collapse the line wrapping first, so "and" split across lines still
    # reads as a separator.
    text = " ".join(html[start:end].split())
    text = text.replace(" and ", ", ").replace(".", "")
    listed = []
    for part in text.split(","):
        name = part.strip()
        if name != "":
            listed.append(name)
    expected = []
    for code in LANGUAGES:
        expected.append(_LANG_NAMES[code])
    expected.sort()
    assert listed == expected, "dashboard lists " + str(listed)
