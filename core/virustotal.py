"""
VirusTotal v3 API — IoC enrichment module.

Supports lookups for:
  - IPv4 addresses  → /api/v3/ip_addresses/{ip}
  - Domains         → /api/v3/domains/{domain}
  - URLs            → /api/v3/urls/{base64(url)}  (no-padding, URL-safe b64)

Returns a normalised dict so callers don't need to handle raw VT JSON.
"""
import base64
import os
import re

import requests

VT_BASE = "https://www.virustotal.com/api/v3"
VT_TIMEOUT = 15


def _get_api_key(api_key: str | None = None) -> str:
    key = api_key or os.getenv("VT_API_KEY", "")
    if not key:
        raise ValueError("VT_API_KEY is not set. Add it to your .env file.")
    return key


def _is_ip(value: str) -> bool:
    return bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", value))


def _is_domain(value: str) -> bool:
    """Heuristic: no protocol prefix and at least one dot."""
    return (
        "://" not in value
        and "." in value
        and not _is_ip(value)
    )


def _url_to_vt_id(url: str) -> str:
    """VirusTotal URL ID = base64url(url) with no '=' padding."""
    return base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()


def _parse_response(data: dict, ioc_value: str, ioc_type: str) -> dict:
    """Extract the key fields from a VT v3 response attributes block."""
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})

    malicious   = stats.get("malicious", 0)
    suspicious  = stats.get("suspicious", 0)
    harmless    = stats.get("harmless", 0)
    undetected  = stats.get("undetected", 0)
    total       = malicious + suspicious + harmless + undetected

    # Verdict
    if malicious >= 3:
        verdict = "malicious"
    elif suspicious >= 2 or malicious >= 1:
        verdict = "suspicious"
    else:
        verdict = "clean"

    # Extra context per type
    extra = {}
    if ioc_type == "ip":
        extra["country"]  = attrs.get("country", "")
        extra["asn"]      = attrs.get("asn", "")
        extra["as_owner"] = attrs.get("as_owner", "")
    elif ioc_type == "domain":
        extra["registrar"]   = attrs.get("registrar", "")
        extra["creation_date"] = attrs.get("creation_date", "")
        cats = attrs.get("categories", {})
        extra["categories"]  = list(cats.values()) if cats else []
    elif ioc_type == "url":
        extra["final_url"] = attrs.get("last_final_url", ioc_value)
        extra["title"]     = attrs.get("title", "")

    return {
        "ioc_value":  ioc_value,
        "ioc_type":   ioc_type,
        "verdict":    verdict,
        "malicious":  malicious,
        "suspicious": suspicious,
        "harmless":   harmless,
        "undetected": undetected,
        "total_engines": total,
        "vt_link":    f"https://www.virustotal.com/gui/{ioc_type}/{ioc_value}",
        **extra,
    }


def lookup(ioc_value: str, api_key: str | None = None) -> dict:
    """
    Auto-detects the IoC type (IP / domain / URL) and queries VirusTotal.

    Returns a normalised result dict with verdict, engine counts, and extras.
    Raises:
      - ValueError  if no API key is configured
      - requests.HTTPError  on 4xx/5xx from VT API
      - requests.RequestException  on network errors
    """
    key = _get_api_key(api_key)
    headers = {"x-apikey": key}
    value = ioc_value.strip()

    if _is_ip(value):
        ioc_type = "ip"
        url = f"{VT_BASE}/ip_addresses/{value}"
    elif value.startswith("http://") or value.startswith("https://"):
        ioc_type = "url"
        url = f"{VT_BASE}/urls/{_url_to_vt_id(value)}"
    elif _is_domain(value):
        ioc_type = "domain"
        url = f"{VT_BASE}/domains/{value}"
    else:
        raise ValueError(f"Cannot determine IoC type for: {value!r}")

    response = requests.get(url, headers=headers, timeout=VT_TIMEOUT)
    response.raise_for_status()
    return _parse_response(response.json(), value, ioc_type)
