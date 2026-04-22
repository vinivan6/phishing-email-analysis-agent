# Rule-based Phishing Email Analysis Tool with Multi-Source Threat Intel Enrichment and Streamlit UI

A Python and FastAPI-based cybersecurity application that analyzes suspicious emails and produces a structured phishing risk assessment using rule-based detection, threat-intelligence enrichment, semantic classification, and decision logic.

## Features

### Input
- Manual entry of email fields (sender, subject, body, headers)
- `.eml` file upload with automatic parsing

### Artifact Extraction
Automatically extracts the following from email content and headers:
- URLs and embedded links
- Domains
- IP addresses (from headers)
- Attachment names
- Phone numbers
- Monetary amounts

### Phishing Indicator Detection
Rule-based engine checks for:
- Urgency language
- Credential request patterns
- Suspicious or obfuscated URLs
- Lookalike / typosquat domains
- Reply-To header mismatch
- SPF / DKIM authentication failures
- Job scam patterns
- Help desk / IT support scam patterns
- Extortion and blackmail patterns

### Threat Intelligence Enrichment
Each extracted artifact is checked against:
- [VirusTotal](https://www.virustotal.com) — URL, domain, and file hash reputation
- [URLhaus](https://urlhaus.abuse.ch) — malicious URL database
- [AbuseIPDB](https://www.abuseipdb.com) — IP address abuse reports
- [AlienVault OTX](https://otx.alienvault.com) — open threat exchange indicators

### Semantic Classification
Emails are categorised into one of the following types before scoring:
- `newsletter_marketing`
- `credential_phishing`
- `extortion_blackmail`
- `job_scam`
- `helpdesk_support_scam`
- `uncertain`

### Output
Each analysis produces:
- **Verdict** — `clean`, `suspicious`, or `malicious`
- **Confidence** — `low`, `medium`, or `high`
- **Reasons** — human-readable explanation of triggered rules
- **Indicators** — machine-readable indicator tags
- **Artifacts** — all extracted URLs, domains, IPs, etc.
- **Reputation summary** — aggregated threat intel results
- **Recommended action** — `no action`, `review with caution`, `block and escalate`

## Screenshots

### Home Page
![UI Homepage](docs/images/UI_Homepage.png)

### Manual Entry
![UI Manual Entry](docs/images/UI_Homepage_manualEntry.png)

### Example Results
![UI Analysis Result 1](docs/images/UI_Analysis_result1.png)
![UI Analysis Result 2](docs/images/UI_Analysis_result2.png)
![UI Analysis Result 3](docs/images/UI_Analysis_result3.png)

## Architecture

```text
User Input / .eml Upload
        ↓
Email Parsing
        ↓
Artifact Extraction
        ↓
Rule-Based Analysis
        ↓
Threat-Intelligence Enrichment
        ↓
Semantic Classification
        ↓
Decision Engine
        ↓
Final Verdict + Recommended Action
```
**Stack:**
- `FastAPI` — REST API backend (`/analyze` endpoint)
- `Streamlit` — analyst-facing UI
- `Python standard libraries` — email parsing, regex, header analysis
- External APIs — VirusTotal, AbuseIPDB, URLhaus, AlienVault OTX
---

## Setup

### Prerequisites
- Python 3.10+
- API keys for VirusTotal, AbuseIPDB, URLhaus, and AlienVault OTX (all have free tiers)

### 1. Clone the repository

```bash
git clone https://github.com/vinivan6/phishing-email-analysis-agent.git
cd phishing-email-analysis-agent
```

### 2. Create and activate a virtual environment

**Windows (PowerShell):**
```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
```

**macOS / Linux:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure environment variables

Copy the example file and add your API keys:

```bash
cp .env.example .env
```

Edit `.env`:

```env
VT_API_KEY=your_virustotal_key
ABUSEIPDB_API_KEY=your_abuseipdb_key
URLHAUS_AUTH_KEY=your_urlhaus_auth_key
OTX_API_KEY=your_otx_key
```

> Free API keys: [VirusTotal](https://www.virustotal.com/gui/join-us) · [AbuseIPDB](https://www.abuseipdb.com/register) · [URLhaus](https://urlhaus.abuse.ch/api/) · [AlienVault OTX](https://otx.alienvault.com)

### 5. Run the application

**Start the FastAPI backend:**
```bash
uvicorn app.main:app --reload
```
API docs available at: `http://127.0.0.1:8000/docs`

**Start the Streamlit UI (in a separate terminal):**
```bash
streamlit run ui_app.py
```

### 6. Run tests

```bash
pytest
```

## Known Limitations
- `.msg` not supported yet
- LLM explanation not integrated yet
- Threat-intel feeds can produce occasional noisy results
- IP extraction from complex headers may still include noisy but syntactically valid IP-like values