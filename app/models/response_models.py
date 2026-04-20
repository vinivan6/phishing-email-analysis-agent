from typing import List, Optional
from pydantic import BaseModel, Field


class ExtractedArtifacts(BaseModel):
    urls: List[str] = Field(default_factory=list, description="Extracted URLs from the email")
    domains: List[str] = Field(default_factory=list, description="Extracted domains from sender, URLs, and headers")
    ip_addresses: List[str] = Field(default_factory=list, description="Extracted IP addresses from headers")
    attachments: List[str] = Field(default_factory=list, description="Attachment filenames found in the email")
    phone_numbers: List[str] = Field(default_factory=list, description="Extracted phone numbers from subject/body")
    amounts: List[str] = Field(default_factory=list, description="Extracted monetary amounts from subject/body")


class ReputationEntry(BaseModel):
    value: str
    source: str
    verdict: str
    details: Optional[str] = None


class ReputationResults(BaseModel):
    urls: List[ReputationEntry] = Field(default_factory=list)
    domains: List[ReputationEntry] = Field(default_factory=list)
    ip_addresses: List[ReputationEntry] = Field(default_factory=list)


class ReputationSummary(BaseModel):
    malicious_count: int = 0
    suspicious_count: int = 0
    informational_count: int = 0
    clean_count: int = 0
    no_record_count: int = 0
    unavailable_count: int = 0
    overall: str = "unknown"
    summary_note: str = ""


class EmailAnalysisResponse(BaseModel):
    verdict: str = Field(..., description="Overall phishing verdict")
    confidence: str = Field(..., description="Confidence level of the analysis")
    reasons: List[str] = Field(..., description="Why the email received this verdict")
    indicators: List[str] = Field(..., description="Detected phishing indicators")
    recommended_action: str = Field(..., description="Recommended next action")
    llm_notes: str = Field(..., description="Additional LLM reasoning notes")
    model_used: str = Field(..., description="Model used for analysis")
    artifacts: ExtractedArtifacts = Field(..., description="Extracted artifacts from the email")
    reputation: ReputationResults = Field(..., description="Threat-intelligence enrichment results")
    reputation_summary: ReputationSummary = Field(..., description="Normalized summary of reputation results")