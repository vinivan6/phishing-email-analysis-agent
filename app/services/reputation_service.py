import requests
from urllib.parse import quote

from app.config import settings
from app.models.response_models import ReputationEntry, ReputationResults


VT_DOMAIN_REPORT = "https://www.virustotal.com/api/v3/domains/"
ABUSEIPDB_CHECK = "https://api.abuseipdb.com/api/v2/check"
URLHAUS_URL_CHECK = "https://urlhaus-api.abuse.ch/v1/url/"
OTX_DOMAIN_GENERAL = "https://otx.alienvault.com/api/v1/indicators/domain/{value}/general"
OTX_IPV4_GENERAL = "https://otx.alienvault.com/api/v1/indicators/IPv4/{value}/general"


def get_virustotal_headers() -> dict:
    return {"x-apikey": settings.vt_api_key} if settings.vt_api_key else {}


def get_otx_headers() -> dict:
    return {"X-OTX-API-KEY": settings.otx_api_key} if settings.otx_api_key else {}


def check_urlhaus_url(url: str) -> ReputationEntry:
    if not settings.urlhaus_auth_key:
        return ReputationEntry(
            value=url,
            source="URLhaus",
            verdict="unknown",
            details="Missing URLhaus Auth-Key"
        )

    try:
        response = requests.post(
            URLHAUS_URL_CHECK,
            headers={"Auth-Key": settings.urlhaus_auth_key},
            data={"url": url},
            timeout=10
        )
        data = response.json()
        status = data.get("query_status", "unknown")

        if status == "ok":
            threat = data.get("threat", "unknown")
            blacklists = data.get("blacklists", {})
            spamhaus = blacklists.get("spamhaus_dbl", "unknown")
            surbl = blacklists.get("surbl", "unknown")
            return ReputationEntry(
                value=url,
                source="URLhaus",
                verdict="malicious",
                details=f"threat={threat}, spamhaus_dbl={spamhaus}, surbl={surbl}"
            )

        if status == "no_results":
            return ReputationEntry(
                value=url,
                source="URLhaus",
                verdict="clean",
                details="No URLhaus match for this URL"
            )

        return ReputationEntry(
            value=url,
            source="URLhaus",
            verdict="unknown",
            details=f"URLhaus status: {status}"
        )
    except Exception as exc:
        return ReputationEntry(
            value=url,
            source="URLhaus",
            verdict="error",
            details=str(exc)
        )


def check_abuseipdb_ip(ip: str) -> ReputationEntry:
    if not settings.abuseipdb_api_key:
        return ReputationEntry(
            value=ip,
            source="AbuseIPDB",
            verdict="unknown",
            details="Missing AbuseIPDB API key"
        )

    try:
        response = requests.get(
            ABUSEIPDB_CHECK,
            headers={
                "Key": settings.abuseipdb_api_key,
                "Accept": "application/json"
            },
            params={
                "ipAddress": ip,
                "maxAgeInDays": 90
            },
            timeout=10
        )
        data = response.json().get("data", {})
        score = data.get("abuseConfidenceScore", 0)

        if score >= 75:
            verdict = "malicious"
        elif score >= 25:
            verdict = "suspicious"
        else:
            verdict = "clean"

        return ReputationEntry(
            value=ip,
            source="AbuseIPDB",
            verdict=verdict,
            details=f"Abuse confidence score: {score}"
        )
    except Exception as exc:
        return ReputationEntry(
            value=ip,
            source="AbuseIPDB",
            verdict="error",
            details=str(exc)
        )


def check_virustotal_domain(domain: str) -> ReputationEntry:
    if not settings.vt_api_key:
        return ReputationEntry(
            value=domain,
            source="VirusTotal",
            verdict="unknown",
            details="Missing VirusTotal API key"
        )

    try:
        response = requests.get(
            f"{VT_DOMAIN_REPORT}{quote(domain, safe='')}",
            headers=get_virustotal_headers(),
            timeout=10
        )
        data = response.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        if malicious > 0:
            verdict = "malicious"
        elif suspicious > 0:
            verdict = "suspicious"
        else:
            verdict = "clean"

        return ReputationEntry(
            value=domain,
            source="VirusTotal",
            verdict=verdict,
            details=f"VT malicious={malicious}, suspicious={suspicious}"
        )
    except Exception as exc:
        return ReputationEntry(
            value=domain,
            source="VirusTotal",
            verdict="error",
            details=str(exc)
        )


def check_otx_domain(domain: str) -> ReputationEntry:
    if not settings.otx_api_key:
        return ReputationEntry(
            value=domain,
            source="AlienVault OTX",
            verdict="unknown",
            details="Missing OTX API key"
        )

    try:
        response = requests.get(
            OTX_DOMAIN_GENERAL.format(value=quote(domain, safe="")),
            headers=get_otx_headers(),
            timeout=10
        )
        data = response.json()

        pulse_count = len(data.get("pulse_info", {}).get("pulses", []))
        malware_count = data.get("malware", {}).get("count", 0)

        if pulse_count > 0 or malware_count > 0:
            verdict = "suspicious"
        else:
            verdict = "clean"

        return ReputationEntry(
            value=domain,
            source="AlienVault OTX",
            verdict=verdict,
            details=f"OTX pulses={pulse_count}, malware_count={malware_count}"
        )
    except Exception as exc:
        return ReputationEntry(
            value=domain,
            source="AlienVault OTX",
            verdict="error",
            details=str(exc)
        )


def check_otx_ip(ip: str) -> ReputationEntry:
    if not settings.otx_api_key:
        return ReputationEntry(
            value=ip,
            source="AlienVault OTX",
            verdict="unknown",
            details="Missing OTX API key"
        )

    try:
        response = requests.get(
            OTX_IPV4_GENERAL.format(value=quote(ip, safe="")),
            headers=get_otx_headers(),
            timeout=10
        )
        data = response.json()

        pulse_count = len(data.get("pulse_info", {}).get("pulses", []))
        malware_count = data.get("malware", {}).get("count", 0)

        if pulse_count > 0 or malware_count > 0:
            verdict = "suspicious"
        else:
            verdict = "clean"

        return ReputationEntry(
            value=ip,
            source="AlienVault OTX",
            verdict=verdict,
            details=f"OTX pulses={pulse_count}, malware_count={malware_count}"
        )
    except Exception as exc:
        return ReputationEntry(
            value=ip,
            source="AlienVault OTX",
            verdict="error",
            details=str(exc)
        )


def enrich_reputation(urls: list[str], domains: list[str], ip_addresses: list[str]) -> ReputationResults:
    results = ReputationResults()

    for url in urls:
        results.urls.append(check_urlhaus_url(url))

    for domain in domains:
        results.domains.append(check_virustotal_domain(domain))
        results.domains.append(check_otx_domain(domain))

    for ip in ip_addresses:
        results.ip_addresses.append(check_abuseipdb_ip(ip))
        results.ip_addresses.append(check_otx_ip(ip))

    return results