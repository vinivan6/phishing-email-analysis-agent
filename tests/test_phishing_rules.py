from app.services.phishing_rules import analyze_email_rules


def test_safe_email_returns_likely_safe():
    verdict, confidence, reasons, indicators, recommended_action = analyze_email_rules(
        sender="hr@company.com",
        display_name="HR Team",
        subject="Team lunch next Friday",
        body="Please let me know your dietary restrictions for Friday lunch.",
        headers="From: hr@company.com\nReply-To: hr@company.com",
        attachments=["menu.pdf"]
    )

    assert verdict == "likely_safe"
    assert "no_strong_indicators" in indicators


def test_obvious_phishing_email_returns_phishing():
    verdict, confidence, reasons, indicators, recommended_action = analyze_email_rules(
        sender="security-update@micr0soft-support.com",
        display_name="Microsoft Security",
        subject="Urgent: Verify your account now",
        body="Your mailbox will be disabled today unless you verify your password immediately using the secure link below.",
        headers=(
            "Authentication-Results: mx.google.com; dkim=fail; spf=fail; dmarc=fail\n"
            "Return-Path: <attacker@evil-domain.com>\n"
            "Reply-To: attacker@evil-domain.com\n"
            "Message-ID: <12345@evil-domain.com>\n"
            "Received: from host1.bad.net by relay1.bad.net\n"
            "Received: from relay1.bad.net by relay2.bad.net\n"
            "Received: from relay2.bad.net by relay3.bad.net\n"
            "Received: from relay3.bad.net by relay4.bad.net\n"
            "Received: from relay4.bad.net by mx.google.com"
        ),
        attachments=["security_update.html"]
    )

    assert verdict == "phishing"
    assert confidence == "high"
    assert "spf_fail" in indicators
    assert "dkim_fail" in indicators
    assert "dmarc_fail" in indicators


def test_display_name_spoofing_detected():
    verdict, confidence, reasons, indicators, recommended_action = analyze_email_rules(
        sender="secure-alerts@account-verify-login.net",
        display_name="Microsoft Security Team",
        subject="Urgent: Verify your Microsoft account",
        body="Microsoft noticed suspicious activity. Verify your account immediately at https://secure-account-check.example.com/login",
        headers=(
            "Authentication-Results: mx.google.com; dkim=fail; spf=fail; dmarc=fail\n"
            "Return-Path: <attacker@evil-domain.com>\n"
            "Reply-To: attacker@evil-domain.com\n"
            "Message-ID: <1234567890@evil-domain.com>\n"
            "Received: from host1.bad.net by relay1.bad.net\n"
            "Received: from relay1.bad.net by relay2.bad.net\n"
            "Received: from relay2.bad.net by relay3.bad.net\n"
            "Received: from relay3.bad.net by relay4.bad.net\n"
            "Received: from relay4.bad.net by mx.google.com"
        ),
        attachments=["security_notice.html"]
    )

    assert verdict == "phishing"
    assert "display_name_spoofing" in indicators
    assert "brand_impersonation" in indicators
    assert "message_id_mismatch" in indicators