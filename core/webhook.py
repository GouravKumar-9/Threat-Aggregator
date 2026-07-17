import requests
import os

def send_alert(ioc_value: str, ioc_type: str, source: str):
    """Sends a real-time alert to a Discord/Slack webhook."""
    webhook_url = os.getenv("WEBHOOK_URL")
    if not webhook_url:
        print("WEBHOOK_URL not configured in .env. Skipping alert.")
        return
        
    payload = {
        "text": f"🚨 **REAL-TIME THREAT DETECTED** 🚨\n"
                f"**Indicator**: `{ioc_value}` ({ioc_type})\n"
                f"**Source Feed Match**: {source}\n"
                f"**Action Required**: Check SIEM and Firewall logs immediately."
    }
    
    try:
        requests.post(webhook_url, json=payload, timeout=5)
        print(f"Alert successfully dispatched for {ioc_value}")
    except Exception as e:
        print(f"Failed to send webhook alert: {e}")
