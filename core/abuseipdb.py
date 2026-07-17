"""
AbuseIPDB API v2 — IP enrichment module.

Supports lookups for IPv4 and IPv6 addresses.
"""
import os
import re
import requests

ABUSEIPDB_BASE = "https://api.abuseipdb.com/api/v2"
ABUSEIPDB_TIMEOUT = 10


def _get_api_key(api_key: str | None = None) -> str:
    key = api_key or os.getenv("ABUSEIPDB_API_KEY", "")
    if not key:
        raise ValueError("ABUSEIPDB_API_KEY is not set. Add it to your .env file.")
    return key


def _is_ip(value: str) -> bool:
    # Basic IPv4 and IPv6 heuristic check
    return bool(re.fullmatch(r"[\d\.:a-fA-F]+", value))


def lookup(ip_address: str, api_key: str | None = None) -> dict:
    """
    Queries the AbuseIPDB v2 API for reputation data on a given IP.

    Returns a normalised result dict.
    Raises:
      - ValueError  if no API key is configured or input is not an IP
      - requests.HTTPError  on 4xx/5xx from API
      - requests.RequestException  on network errors
    """
    value = ip_address.strip()
    if not _is_ip(value):
        raise ValueError(f"Input is not a valid IP address: {value!r}")

    key = _get_api_key(api_key)
    headers = {
        "Accept": "application/json",
        "Key": key
    }
    params = {
        "ipAddress": value,
        "maxAgeInDays": "90"
    }

    url = f"{ABUSEIPDB_BASE}/check"
    response = requests.get(url, headers=headers, params=params, timeout=ABUSEIPDB_TIMEOUT)
    response.raise_for_status()
    
    data = response.json().get("data", {})
    
    return {
        "ipAddress": data.get("ipAddress", value),
        "abuseConfidenceScore": data.get("abuseConfidenceScore", 0),
        "totalReports": data.get("totalReports", 0),
        "numDistinctUsers": data.get("numDistinctUsers", 0),
        "countryCode": data.get("countryCode", ""),
        "isp": data.get("isp", ""),
        "domain": data.get("domain", ""),
        "isPublic": data.get("isPublic", False),
        "isWhitelisted": data.get("isWhitelisted", False),
        "link": f"https://www.abuseipdb.com/check/{value}"
    }
