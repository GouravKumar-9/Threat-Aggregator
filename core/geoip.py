import requests
import json

def fetch_geoip_batch(ips: list) -> dict:
    """
    Fetches GeoIP data (lat, lon) for a list of IPs using ip-api.com's batch endpoint.
    Returns a dictionary mapping IP to {"lat": lat, "lon": lon}.
    """
    if not ips:
        return {}

    # ip-api batch endpoint supports up to 100 IPs per request
    url = "http://ip-api.com/batch"
    
    # We only care about lat and lon
    payload = [{"query": ip, "fields": "query,lat,lon,status"} for ip in ips]
    
    results = {}
    try:
        response = requests.post(url, json=payload, timeout=10)
        if response.status_code == 200:
            data = response.json()
            for item in data:
                if item.get("status") == "success":
                    results[item["query"]] = {
                        "lat": item.get("lat"),
                        "lon": item.get("lon")
                    }
    except Exception as e:
        print(f"Failed to fetch GeoIP batch: {e}")
        
    return results
