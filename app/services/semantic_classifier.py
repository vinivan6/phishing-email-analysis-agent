from typing import Dict, List, Optional


SEMANTIC_CATEGORIES = [
    "newsletter_marketing",
    "credential_phishing",
    "financial_scam",
    "extortion_blackmail",
    "job_scam",
    "helpdesk_support_scam",
    "benign_business",
    "uncertain",
]


def classify_semantics(
    subject: str,
    body: str,
    headers: Optional[str] = None,
    indicators: Optional[List[str]] = None,
) -> Dict:
    text = f"{subject}\n{body}".lower()
    header_text = (headers or "").lower()
    indicators = indicators or []

    scores = {
        "newsletter_marketing": 0,
        "credential_phishing": 0,
        "financial_scam": 0,
        "extortion_blackmail": 0,
        "job_scam": 0,
        "helpdesk_support_scam": 0,
        "benign_business": 0,
    }

    signals = []

    # Newsletter / marketing
    if "list-unsubscribe" in header_text:
        scores["newsletter_marketing"] += 4
        signals.append("unsubscribe_header_present")

    if "list-unsubscribe-post" in header_text:
        scores["newsletter_marketing"] += 3
        signals.append("one_click_unsubscribe_present")

    if "x-mailer" in header_text or "campaign" in header_text or "newsletter" in text:
        scores["newsletter_marketing"] += 2
        signals.append("bulk_mailer_or_campaign_pattern")

    if "spf=pass" in header_text and "dkim=pass" in header_text:
        scores["newsletter_marketing"] += 2
        signals.append("spf_dkim_pass_for_bulk_mail")

    # Credential phishing
    credential_terms = [
        "verify your password",
        "login now",
        "sign in now",
        "confirm your account",
        "reset your password",
        "update your credentials",
    ]
    for term in credential_terms:
        if term in text:
            scores["credential_phishing"] += 3
            signals.append(f"credential_term:{term}")

    # Financial scam
    financial_terms = [
        "pending deposit",
        "money received",
        "accept money",
        "transfer to a bank",
        "payment pending",
        "claim funds",
        "account activation",
    ]
    for term in financial_terms:
        if term in text:
            scores["financial_scam"] += 2
            signals.append(f"financial_term:{term}")

    # Extortion / blackmail / crypto coercion
    extortion_terms = [
        "pegasus",
        "i recorded you",
        "i've recorded you",
        "i installed it on all your devices",
        "send the money",
        "your contacts",
        "publish the videos",
        "do not contact the police",
        "48 hours",
        "bitcoin",
        "litecoin",
        "wallet",
        "embarrassing",
        "blackmail",
        "perverted",
    ]
    for term in extortion_terms:
        if term in text:
            scores["extortion_blackmail"] += 3
            signals.append(f"extortion_term:{term}")

    # Job scam
    job_terms = [
        "job offer",
        "remote job",
        "data entry",
        "immediate hire",
        "no experience needed",
        "must be 18",
        "work from home",
        "preferred vendor",
        "reimbursement",
        "check for equipment",
    ]
    for term in job_terms:
        if term in text:
            scores["job_scam"] += 2
            signals.append(f"job_term:{term}")

    # Help desk scam
    helpdesk_terms = [
        "help desk",
        "technical support",
        "it support",
        "password expired",
        "suspicious login",
        "verification code",
        "one-time password",
        "otp",
        "mfa",
        "approve the notification",
        "read me the code",
    ]
    for term in helpdesk_terms:
        if term in text:
            scores["helpdesk_support_scam"] += 2
            signals.append(f"helpdesk_term:{term}")

    # Benign business
    benign_terms = [
        "meeting",
        "schedule",
        "invoice attached",
        "thank you",
        "regards",
        "team lunch",
    ]
    for term in benign_terms:
        if term in text:
            scores["benign_business"] += 1

    # Indicator-aware boosts
    if "credential_request" in indicators:
        scores["credential_phishing"] += 3
    if "financial_action_bait" in indicators or "callback_phishing" in indicators:
        scores["financial_scam"] += 2
    if "job_scam_context" in indicators:
        scores["job_scam"] += 3
    if "helpdesk_impersonation" in indicators or "mfa_bypass_language" in indicators:
        scores["helpdesk_support_scam"] += 3
    if "brand_impersonation" in indicators or "display_name_spoofing" in indicators:
        scores["credential_phishing"] += 1
        scores["helpdesk_support_scam"] += 1

    best_category = max(scores, key=scores.get)
    best_score = scores[best_category]

    if best_score >= 7:
        confidence = "high"
    elif best_score >= 4:
        confidence = "medium"
    elif best_score >= 3:
        confidence = "low"
    else:
        best_category = "uncertain"
        confidence = "low"

    return {
        "category": best_category,
        "confidence": confidence,
        "scores": scores,
        "signals": signals,
    }