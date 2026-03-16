# Phish_Detector: SOC Triage Automation

An automated tool for Security Operations Center (SOC) analysts to quickly triage suspicious Outlook `.msg` files. This script handles the heavy lifting of extracting URLs, bypassing enterprise security wrappers, and gathering threat intelligence from VirusTotal.

## 🛡️ Why This Exists
Standard URL scanners often fail when links are "wrapped" by security gateways like Sophos or Mimecast. I built this tool to recursively "peel" those layers and find the actual malicious destination hidden inside.

## 🚀 Key Features
* **Multi-Layer URL Decoding:** Recursively extracts hidden destination URLs from Sophos 'Safe Links' and Mimecast 'TTP' wrappers.
* **Deep Reputation Analysis:** Cross-references both the full **Request URL** and the **Root Domain** against 70+ security vendors via the VirusTotal v3 API.
* **SSL/Inspection Friendly:** Built-in handling for SSL inspection and self-signed certificates common in corporate/academic labs.
* **Incident Logging:** Automatically logs malicious findings to `threat_log.txt` using defanged URLs for safe documentation.

## 🛠️ Technical Stack
* **Language:** Python 3.13+
* **Core Libraries:** `extract-msg`, `requests`, `python-dotenv`
* **Intelligence:** VirusTotal v3 REST API

## ⚙️ Installation & Setup

1. **Clone the Repo:**
   ```bash
   git clone [https://github.com/jbarajas-sec/Phish_Detector.git](https://github.com/jbarajas-sec/Phish_Detector.git)
   cd Phish_Detector
