import json
import uuid
from datetime import datetime, timezone

def normalize_to_stix(ioc_value: str, ioc_type: str, source: str) -> str:
    """
    Normalizes a basic IoC into a STIX 2.1 JSON representation.
    Returns the JSON string of the STIX object.
    """
    now = datetime.now(timezone.utc).isoformat() + "Z"
    
    # STIX 2.1 pattern mapping based on our ioc_type
    if ioc_type == "IP":
        pattern = f"[ipv4-addr:value = '{ioc_value}']"
    elif ioc_type == "Domain":
        pattern = f"[domain-name:value = '{ioc_value}']"
    elif ioc_type == "URL":
        pattern = f"[url:value = '{ioc_value}']"
    else:
        pattern = f"[file:hashes.'SHA-256' = '{ioc_value}']" # Fallback/generic

    stix_indicator = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--{uuid.uuid4()}",
        "created": now,
        "modified": now,
        "name": f"Malicious {ioc_type} from {source}",
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": now,
        "labels": ["malicious-activity"]
    }
    return json.dumps(stix_indicator)
