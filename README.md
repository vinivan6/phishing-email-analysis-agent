phishing-email-analysis-agent
# Phishing Email Analysis Agent

A cybersecurity application that evaluates suspicious emails and produces a structured phishing risk assessment.

## Project goals

- Assess email content and metadata for phishing risk
- Detect common phishing indicators such as spoofing, urgency, impersonation, and credential harvesting attempts
- Provide a clear, structured output with verdict, confidence, supporting reasons, and recommended action
- Enable future integration into security workflows through an API-based design

## Planned features

- Accept sender, subject, body, and optional headers
- Detect suspicious phishing indicators
- Return verdict, confidence, reasons, and recommended action
- Add LLM-based analysis
- Add tests and GitHub Actions CI

## Tech stack

- Python
- FastAPI
- Pydantic
- OpenAI API
- Pytest
- GitHub

## Current status

Initial scaffold in progress.