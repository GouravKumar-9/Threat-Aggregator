# Threat Aggregator

Threat Aggregator is a lightweight, self-hosted Threat Intelligence Dashboard that automatically aggregates Indicators of Compromise (IoCs) from various open-source intelligence (OSINT) feeds and provides real-time enrichment via VirusTotal and AbuseIPDB.

## Features

- **Automated OSINT Feeds**: Periodically pulls data from:
  - Feodo Tracker (Abuse.ch)
  - URLhaus (Abuse.ch)
  - AlienVault OTX
- **Real-Time Enrichment**:
  - **VirusTotal**: Automatically queries VT for IPs, Domains, and URLs to fetch malware/suspicion counts.
  - **AbuseIPDB**: Automatically queries AbuseIPDB for IP addresses to get Abuse Confidence Scores, ISP, and geographic data.
- **Unified Search UI**: Easily query any IP, domain, or URL to see its status across your internal database, VirusTotal, and AbuseIPDB in one clean interface.
- **FastAPI Backend**: Built for high performance and concurrency using Python's FastAPI.
- **SQLite Database**: Lightweight, zero-config local storage for collected IoCs.

## Setup Instructions

1. **Install Dependencies**
   Ensure you have Python 3.10+ installed, then install the required packages:
   ```bash
   pip install -r requirements.txt
   ```

2. **Configure API Keys**
   Copy the example environment file:
   ```bash
   cp .env.example .env
   ```
   Open the `.env` file and add your API keys:
   - **VirusTotal**: Get a free key at [VirusTotal](https://www.virustotal.com/gui/join-us)
   - **AbuseIPDB**: Get a free key at [AbuseIPDB](https://www.abuseipdb.com/)

3. **Run the Application**
   Start the FastAPI server using Uvicorn:
   ```bash
   uvicorn main:app --reload --host 0.0.0.0 --port 8080
   ```
   *(Note: It is configured to run on port 8080 by default to avoid conflicts).*

4. **Access the Dashboard**
   Open your browser and navigate to:
   [http://localhost:8080/dashboard](http://localhost:8080/dashboard)

## Usage

- **Sync Feeds**: Click "Sync Feeds Now" on the dashboard to manually trigger a data pull from all configured OSINT feeds.
- **IoC Lookup**: Paste any IP, URL, or domain into the search bar. The system will instantly check your local database while simultaneously reaching out to VirusTotal and AbuseIPDB (for IPs) to give you a consolidated threat report.
