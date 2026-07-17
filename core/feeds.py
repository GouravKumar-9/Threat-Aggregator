import os
import requests

# ---------------------------------------------------------------------------
# Feodo Tracker (Abuse.ch) — Malicious C2 IPs
# ---------------------------------------------------------------------------
def fetch_feodo_tracker():
    """Fetches malicious IPs from Abuse.ch Feodo Tracker."""
    url = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
    print(f"[*] Fetching data from {url}...")
    
    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        
        iocs = []
        for line in response.text.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                iocs.append({
                    "ioc_value": line,
                    "ioc_type": "IP",
                    "source": "Feodo Tracker (Abuse.ch)"
                })
        print(f"[+] Feodo Tracker: fetched {len(iocs)} indicators.")
        return iocs
        
    except requests.exceptions.RequestException as e:
        print(f"[-] Error fetching Feodo Tracker: {e}")
        return []


# ---------------------------------------------------------------------------
# URLhaus (Abuse.ch) — Malicious URLs
# ---------------------------------------------------------------------------
def fetch_urlhaus():
    """
    Fetches malicious URLs from URLhaus (Abuse.ch).
    Uses the CSV export which contains online/offline status and tags.
    Only 'online' or 'unknown' status URLs are included.
    """
    url = "https://urlhaus.abuse.ch/downloads/csv_online/"
    print(f"[*] Fetching data from URLhaus ({url})...")
    
    try:
        response = requests.get(url, timeout=20)
        response.raise_for_status()
        
        iocs = []
        for line in response.text.splitlines():
            line = line.strip()
            # Skip comments and empty lines
            if not line or line.startswith("#"):
                continue
            
            parts = line.split('","')
            if len(parts) < 6:
                continue
            
            # CSV columns: id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link
            try:
                url_value = parts[2].strip('"')
                # Basic validation: must look like a URL
                if url_value.startswith("http://") or url_value.startswith("https://"):
                    iocs.append({
                        "ioc_value": url_value,
                        "ioc_type": "URL",
                        "source": "URLhaus (Abuse.ch)"
                    })
            except IndexError:
                continue
        
        print(f"[+] URLhaus: fetched {len(iocs)} indicators.")
        return iocs
        
    except requests.exceptions.RequestException as e:
        print(f"[-] Error fetching URLhaus: {e}")
        return []


# ---------------------------------------------------------------------------
# AlienVault OTX — Community Threat Pulses
# ---------------------------------------------------------------------------
def fetch_alienvault_otx(api_key: str | None = None):
    """
    Fetches recent IoC indicators from AlienVault OTX subscribed pulses.
    Requires a free API key: https://otx.alienvault.com

    Set the OTX_API_KEY environment variable or pass api_key directly.
    Supports indicator types: IPv4, domain, URL.
    """
    key = api_key or os.getenv("OTX_API_KEY", "")
    
    if not key or key == "your_otx_api_key_here":
        print("[!] OTX_API_KEY not set — skipping AlienVault OTX feed.")
        print("    Sign up free at https://otx.alienvault.com to enable this feed.")
        return []
    
    base_url = "https://otx.alienvault.com/api/v1"
    headers = {"X-OTX-API-KEY": key}
    
    # Map OTX indicator types to our schema
    type_map = {
        "IPv4": "IP",
        "IPv6": "IP",
        "domain": "Domain",
        "hostname": "Domain",
        "URL": "URL",
    }
    
    print(f"[*] Fetching data from AlienVault OTX...")
    iocs = []
    page = 1
    max_pages = 5  # Limit to first 5 pages (~250 pulses) to avoid long waits
    
    try:
        while page <= max_pages:
            resp = requests.get(
                f"{base_url}/pulses/subscribed",
                headers=headers,
                params={"limit": 50, "page": page},
                timeout=20
            )
            resp.raise_for_status()
            data = resp.json()
            pulses = data.get("results", [])
            
            if not pulses:
                break
            
            for pulse in pulses:
                pulse_name = pulse.get("name", "AlienVault OTX")
                for indicator in pulse.get("indicators", []):
                    ind_type = indicator.get("type", "")
                    ind_value = indicator.get("indicator", "").strip()
                    
                    our_type = type_map.get(ind_type)
                    if our_type and ind_value:
                        iocs.append({
                            "ioc_value": ind_value,
                            "ioc_type": our_type,
                            "source": f"AlienVault OTX — {pulse_name[:50]}"
                        })
            
            # Check if there are more pages
            if not data.get("next"):
                break
            page += 1
        
        print(f"[+] AlienVault OTX: fetched {len(iocs)} indicators.")
        return iocs
        
    except requests.exceptions.HTTPError as e:
        if e.response is not None and e.response.status_code == 401:
            print("[-] AlienVault OTX: Invalid API key (401 Unauthorized).")
        else:
            print(f"[-] AlienVault OTX HTTP error: {e}")
        return []
    except requests.exceptions.RequestException as e:
        print(f"[-] Error fetching AlienVault OTX: {e}")
        return []