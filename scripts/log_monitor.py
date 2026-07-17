import os
import re
import sys
import time

# Add parent directory to path to allow importing from core
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.database import search_ioc
from core.webhook import send_alert
from dotenv import load_dotenv

load_dotenv()

def monitor_log(file_path):
    print(f"[*] Started Threat Aggregator Live Log Monitor")
    print(f"[*] Tailing {file_path} for suspicious IPs in real-time...")
    
    with open(file_path, 'r') as f:
        # Fast-forward to the end of the file
        f.seek(0, os.SEEK_END)
        
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
                
            # Basic IPv4 extraction
            match = re.search(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', line)
            if match:
                ip = match.group(0)
                # Check against Threat Aggregator database
                db_match = search_ioc(ip)
                if db_match:
                    ioc_value, ioc_type, source, timestamp = db_match
                    print(f"\n[!] MATCH FOUND: {ip} is flagged as malicious!")
                    print(f"    Source: {source} (Added: {timestamp})")
                    # Fire webhook
                    send_alert(ioc_value, ioc_type, source)
                    # Notify UI via SSE
                    try:
                        import requests
                        requests.post("http://localhost:8080/api/internal/notify", json={
                            "message": f"Log match: Botnet IP detected in auth.log!",
                            "ioc": ip,
                            "source": source,
                            "type": "danger"
                        })
                    except Exception:
                        pass

if __name__ == "__main__":
    # For testing, we use a local dummy_auth.log
    log_file = os.path.join(os.path.dirname(__file__), 'dummy_auth.log')
    if not os.path.exists(log_file):
        with open(log_file, 'a') as f:
            f.write("Log Monitor Initialized\n")
            
    monitor_log(log_file)
