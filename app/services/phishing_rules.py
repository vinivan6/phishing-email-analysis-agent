import re
from typing import List, Tuple, Optional
from app.services.email_parser import (
    extract_urls,
    detect_attachment_risks,
    extract_authentication_results,
    extract_return_path,
    count_received_headers,
    extract_reply_to,
    extract_ip_addresses,
    extract_message_id,
)


URGENT_PATTERNS = [
    r"\burgent\b",
    r"\bimmediately\b",
    r"\baction required\b",
    r"\bverify now\b",
    r"\baccount will be suspended\b",
    r"\bmailbox will be disabled\b",
    r"\bfinal warning\b"
]

CREDENTIAL_PATTERNS = [
    r"\bverify your password\b",
    r"\bconfirm your account\b",
    r"\blogin to continue\b",
    r"\breset your password\b",
    r"\bupdate your credentials\b",
    r"\bsign in now\b"
]

GENERIC_GREETING_PATTERNS = [
    r"\bdear user\b",
    r"\bdear customer\b",
    r"\bvalued customer\b",
    r"\bdear account holder\b"
]

SUSPICIOUS_DOMAIN_PATTERNS = [
    r"micr0soft",
    r"paypa1",
    r"g00gle",
    r"arnazon",
    r"secure-login",
    r"account-verify",
    r"support-update"
]

SUSPICIOUS_URL_PATTERNS = [
    r"login",
    r"verify",
    r"reset",
    r"secure",
    r"account",
    r"update"
]

TRUSTED_BRANDS = [
    "microsoft",
    "google",
    "paypal",
    "amazon",
    "apple",
    "outlook",
    "gmail"
]


def find_pattern_matches(text: str, patterns: List[str]) -> List[str]:
    matches = []
    lowered_text = text.lower()

    for pattern in patterns:
        if re.search(pattern, lowered_text):
            matches.append(pattern)

    return matches


def domain_from_email(value: Optional[str]) -> Optional[str]:
    if not value or "@" not in value:
        return None
    return value.split("@")[-1].strip().lower()


def domain_from_message_id(message_id: Optional[str]) -> Optional[str]:
    if not message_id or "@" not in message_id:
        return None
    return message_id.split("@")[-1].strip().lower()


def find_brands_in_text(text: str) -> List[str]:
    if not text:
        return []

    lowered = text.lower()
    found = []

    for brand in TRUSTED_BRANDS:
        if brand in lowered:
            found.append(brand)

    return found


def analyze_email_rules(
    sender: str,
    display_name: Optional[str] = None,
    subject: str = "",
    body: str = "",
    headers: Optional[str] = None,
    attachments: Optional[List[str]] = None
) -> Tuple[str, str, List[str], List[str], str]:
    reasons = []
    indicators = []

    combined_text = f"{subject}\n{body}".lower()
    sender_lower = sender.lower()
    display_name_lower = (display_name or "").lower()

    urgent_matches = find_pattern_matches(combined_text, URGENT_PATTERNS)
    if urgent_matches:
        reasons.append("The email uses urgent or pressure-based language.")
        indicators.append("urgency")

    credential_matches = find_pattern_matches(combined_text, CREDENTIAL_PATTERNS)
    if credential_matches:
        reasons.append("The email asks the recipient to verify, update, or enter credentials.")
        indicators.append("credential_request")

    greeting_matches = find_pattern_matches(combined_text, GENERIC_GREETING_PATTERNS)
    if greeting_matches:
        reasons.append("The email uses a generic greeting instead of addressing the recipient directly.")
        indicators.append("generic_greeting")

    domain_matches = find_pattern_matches(sender_lower, SUSPICIOUS_DOMAIN_PATTERNS)
    if domain_matches:
        reasons.append("The sender address appears to use a lookalike or suspicious domain pattern.")
        indicators.append("lookalike_domain")

    urls = extract_urls(body)
    if urls:
        lowered_urls = " ".join(urls).lower()
        suspicious_url_matches = find_pattern_matches(lowered_urls, SUSPICIOUS_URL_PATTERNS)
        if suspicious_url_matches:
            reasons.append("The email contains links with potentially suspicious account or verification terms.")
            indicators.append("suspicious_url")

    reply_to = extract_reply_to(headers)
    if reply_to and reply_to.lower() != sender_lower:
        reasons.append("The Reply-To header does not match the sender address.")
        indicators.append("reply_to_mismatch")

    auth_results = extract_authentication_results(headers)
    if auth_results.get("spf") == "fail":
        reasons.append("SPF authentication failed.")
        indicators.append("spf_fail")

    if auth_results.get("dkim") == "fail":
        reasons.append("DKIM authentication failed.")
        indicators.append("dkim_fail")

    if auth_results.get("dmarc") == "fail":
        reasons.append("DMARC authentication failed.")
        indicators.append("dmarc_fail")

    return_path = extract_return_path(headers)
    sender_domain = domain_from_email(sender)
    return_path_domain = domain_from_email(return_path)

    if return_path and sender_domain and return_path_domain and sender_domain != return_path_domain:
        reasons.append("The Return-Path domain does not match the sender domain.")
        indicators.append("return_path_mismatch")

    message_id = extract_message_id(headers)
    message_id_domain = domain_from_message_id(message_id)
    if message_id and sender_domain and message_id_domain and sender_domain != message_id_domain:
        reasons.append("The Message-ID domain does not match the sender domain.")
        indicators.append("message_id_mismatch")

    received_count = count_received_headers(headers)
    if received_count >= 5:
        reasons.append("The email passed through a high number of mail hops.")
        indicators.append("many_mail_hops")

    risky_attachments = detect_attachment_risks(attachments)
    if risky_attachments:
        reasons.append("The email includes attachments with file types that are commonly abused in phishing attacks.")
        indicators.append("risky_attachment")

    ip_addresses = extract_ip_addresses(headers)
    if ip_addresses:
        unique_ips = sorted(set(ip_addresses))
        if len(unique_ips) >= 3:
            reasons.append("Multiple IP addresses were observed in the email headers.")
            indicators.append("multiple_header_ips")

    mentioned_brands = find_brands_in_text(f"{display_name_lower}\n{subject}\n{body}")
    if mentioned_brands and sender_domain:
        suspicious_brand_use = True
        for brand in mentioned_brands:
            if brand in sender_domain:
                suspicious_brand_use = False
                break

        if suspicious_brand_use:
            reasons.append("The email references a known brand, but the sender domain does not align with that brand.")
            indicators.append("brand_impersonation")

    if display_name_lower and sender_domain:
        if "microsoft" in display_name_lower and "microsoft" not in sender_domain:
            reasons.append("The display name suggests Microsoft, but the sender domain does not match.")
            indicators.append("display_name_spoofing")
        elif "google" in display_name_lower and "google" not in sender_domain:
            reasons.append("The display name suggests Google, but the sender domain does not match.")
            indicators.append("display_name_spoofing")
        elif "paypal" in display_name_lower and "paypal" not in sender_domain:
            reasons.append("The display name suggests PayPal, but the sender domain does not match.")
            indicators.append("display_name_spoofing")
        elif "amazon" in display_name_lower and "amazon" not in sender_domain:
            reasons.append("The display name suggests Amazon, but the sender domain does not match.")
            indicators.append("display_name_spoofing")
        elif "apple" in display_name_lower and "apple" not in sender_domain:
            reasons.append("The display name suggests Apple, but the sender domain does not match.")
            indicators.append("display_name_spoofing")

    if len(indicators) >= 3:
        verdict = "phishing"
        confidence = "high"
    elif len(indicators) == 2:
        verdict = "suspicious"
        confidence = "medium"
    elif len(indicators) == 1:
        verdict = "suspicious"
        confidence = "low"
    else:
        verdict = "likely_safe"
        confidence = "medium"
        reasons.append("No strong phishing indicators were detected by the rule-based checks.")
        indicators.append("no_strong_indicators")

    if "risky_attachment" in indicators and verdict in {"phishing", "suspicious"}:
        recommended_action = "Do not click links, open attachments, or reply. Report the email to the security team."
    elif verdict == "phishing":
        recommended_action = "Do not click links, open attachments, or reply. Report the email to the security team."
    elif verdict == "suspicious":
        recommended_action = "Treat the email with caution and verify the sender through a trusted channel."
    else:
        recommended_action = "No immediate phishing indicators detected, but continue normal caution."

    return verdict, confidence, reasons, indicators, recommended_action