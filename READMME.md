\# Phish\_Detector: Automated Email Triage \& URL Analysis



A Python-based Security Operations Center (SOC) utility designed to automate the initial triage of suspicious Outlook `.msg` artifacts. This tool extracts hidden indicators of compromise (IoCs), bypasses enterprise security wrappers, and cross-references findings with the VirusTotal v3 API.



\## 🛡️ Key Features

\* \*\*Recursive URL De-wrapping:\*\* Automatically peels back multiple layers of security gateways (Sophos 'Safe Links' and Mimecast 'Targeted Threat Protection') to find the original destination URL.

\* \*\*Dual-Layer Intelligence:\*\* Checks reputation for both the specific \*\*URL\*\* and the \*\*Root Domain\*\* to identify threats even when unique tracking IDs are used.

\* \*\*Enterprise Ready:\*\* Configured to handle SSL inspection environments and bypass certificate verification errors common in corporate/academic networks.

\* \*\*Persistent Logging:\*\* Generates a `threat\_log.txt` ledger for incident documentation and audit trails.



\## 🛠️ Technical Stack

\* \*\*Language:\*\* Python 3.13+

\* \*\*Libraries:\*\* `extract-msg`, `requests`, `python-dotenv`, `urllib3`

\* \*\*API:\*\* VirusTotal v3 (REST)



\## 🚀 Installation \& Setup

1\. \*\*Clone the repository:\*\*

&#x20;  ```bash

&#x20;  git clone \[https://github.com/YOUR\_USERNAME/Phish\_Detector.git](https://github.com/YOUR\_USERNAME/Phish\_Detector.git)

&#x20;  cd Phish\_Detector

