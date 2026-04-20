from fastapi import APIRouter
from app.models.request_models import EmailAnalysisRequest
from app.models.response_models import EmailAnalysisResponse
from app.services.artifact_extractor import build_artifacts
from app.services.phishing_rules import analyze_email_rules
from app.services.reputation_service import enrich_reputation, summarize_reputation

router = APIRouter()


def adjust_recommended_action(rule_verdict: str, reputation_overall: str) -> str:
    if reputation_overall in {"malicious", "high_risk"}:
        return "Do not click links, open attachments, reply, or call any numbers. Report immediately."

    if reputation_overall == "suspicious":
        if rule_verdict == "phishing":
            return "High risk. Do not interact with the message. Report immediately."
        return "Proceed with extreme caution and verify the sender independently before taking action."

    if reputation_overall == "caution":
        if rule_verdict == "phishing":
            return "The message shows phishing indicators and some reputation sources returned cautionary findings. Do not interact and report it."
        return "Proceed with caution. Verify the sender and content independently before taking action."

    if reputation_overall == "unavailable":
        if rule_verdict == "phishing":
            return "External reputation checks were unavailable for some indicators. Based on phishing analysis, do not interact with the message and report it."
        return "Some external reputation checks were unavailable. Base your decision primarily on the phishing analysis results and proceed cautiously."

    if reputation_overall == "no_record":
        if rule_verdict == "phishing":
            return "No reputation records were found for some indicators, but the phishing analysis is high risk. Do not interact with the message."
        return "No reputation records were found for some indicators. This does not confirm safety, so continue with caution."

    if rule_verdict == "phishing":
        return "Do not click links, open attachments, reply, or call any numbers. Report the message immediately."
    if rule_verdict == "suspicious":
        return "Treat the email with caution and verify the sender through a trusted channel."
    return "No strong reputation-based threat signal was found. Continue normal caution and rely on the phishing analysis."


@router.get("/health")
def health_check():
    return {"status": "ok"}


@router.post("/analyze-email", response_model=EmailAnalysisResponse)
def analyze_email(request: EmailAnalysisRequest):
    verdict, confidence, reasons, indicators, recommended_action = analyze_email_rules(
        sender=request.sender,
        display_name=request.display_name,
        subject=request.subject,
        body=request.body,
        headers=request.headers,
        attachments=request.attachments
    )

    artifacts = build_artifacts(
        sender=request.sender,
        subject=request.subject,
        body=request.body,
        headers=request.headers,
        attachments=request.attachments
    )

    reputation = enrich_reputation(
        urls=artifacts.urls,
        domains=artifacts.domains,
        ip_addresses=artifacts.ip_addresses
    )

    reputation_summary = summarize_reputation(reputation)

    recommended_action = adjust_recommended_action(
        rule_verdict=verdict,
        reputation_overall=reputation_summary.overall
    )

    return EmailAnalysisResponse(
        verdict=verdict,
        confidence=confidence,
        reasons=reasons,
        indicators=indicators,
        recommended_action=recommended_action,
        llm_notes="LLM analysis is not connected yet. Current result is based on rule-based checks plus threat-intelligence enrichment.",
        model_used="rule_based_v11",
        artifacts=artifacts,
        reputation=reputation,
        reputation_summary=reputation_summary
    )