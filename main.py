import argparse
import os
from dotenv import load_dotenv

from core.database import init_db, insert_iocs, search_ioc
from core.feeds import fetch_feodo_tracker, fetch_urlhaus, fetch_alienvault_otx

# Load environment variables (.env file) if present
load_dotenv()

def update_feeds():
    print("[*] Starting threat feed update...")
    
    # Fetch from all configured feeds
    feodo_data  = fetch_feodo_tracker()
    urlhaus_data = fetch_urlhaus()
    otx_data    = fetch_alienvault_otx()   # reads OTX_API_KEY from env automatically

    all_iocs = feodo_data + urlhaus_data + otx_data

    # Insert into database (duplicates are skipped automatically)
    new_records = insert_iocs(all_iocs)
    print(f"\n[+] Update complete!")
    print(f"    Total fetched : {len(all_iocs):,}")
    print(f"    New unique IoCs added: {new_records:,}")

def search_database(query):
    print(f"[*] Searching for '{query}'...")
    result = search_ioc(query)

    if result:
        print("\n[!] ALERT: IoC Found in Database!")
        print("-" * 40)
        print(f"Indicator: {result[0]}")
        print(f"Type:      {result[1]}")
        print(f"Source:    {result[2]}")
        print(f"Added On:  {result[3]} (UTC)")
        print("-" * 40)
    else:
        print(f"[+] '{query}' was not found in any threat feed. (Clean)")

if __name__ == "__main__":
    # Initialize database on first run
    init_db()

    parser = argparse.ArgumentParser(
        description="Threat Aggregator — Threat Intelligence Aggregator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python main.py --update\n"
            "  python main.py --search 185.220.101.45\n\n"
            "Web dashboard:\n"
            "  uvicorn api:app --reload\n"
            "  Then open http://localhost:8000/dashboard"
        )
    )
    parser.add_argument("--update", action="store_true",
                        help="Download and update IoCs from all configured feeds")
    parser.add_argument("--search", type=str,
                        help="Search the database for a specific IP, URL, or Domain")

    args = parser.parse_args()

    if args.update:
        update_feeds()
    elif args.search:
        search_database(args.search)
    else:
        parser.print_help()