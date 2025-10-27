# MalNoteGenerator
MalNote is a Python-based tool that automates malware analysis and threat intelligence gathering. It’s designed for cybersecurity analysts, DFIR professionals, and researchers who need fast, reliable insights into suspicious files.
# 🧾 MalNote – Intelligent Malware Note Generator

> **MalNote** — A smart Python tool for malware analysis, threat intelligence correlation, and automated DFIR note generation powered by ClamAV, VirusTotal, and Gemini AI.

---

## 📖 Overview
**MalNote** is a Python-based tool that automates malware analysis and threat intelligence gathering.  
It’s designed for cybersecurity analysts, DFIR professionals, and researchers who need fast, reliable insights into suspicious files.

The tool calculates a **SHA-256 hash**, performs a **local ClamAV scan**, and queries multiple sources — **AlienVault OTX**, **ThreatFox**, **MalwareBazaar**, and **VirusTotal** — to detect known threats.  
It then generates a clear **Markdown report** summarizing findings, detections, and external intelligence data.

With optional **Google Gemini AI integration**, MalNote can summarize results and suggest next DFIR actions — turning raw technical data into actionable insights.  
Lightweight, open-source, and easy to use, MalNote simplifies malware triage and improves the quality of your forensic documentation.

---

## ⚙️ Features
- 🧮 Compute file hashes (SHA-256)
- 🦠 Scan files locally with **ClamAV**
- 🌍 Query multiple threat intelligence sources  
- 📝 Auto-generate Markdown malware reports  
- 🤖 Optional Gemini AI analysis for DFIR recommendations  

---

## 🧰 Requirements
- Python 3.8 or later  
- `requests`, `hashlib`, `pyclamd`, `subprocess`, `json`, `os`  

Install dependencies:
```bash
pip install -r requirements.txt

🚀 Usage

Clone the repository:
git clone https://github.com/<your-username>/MalNote.git
cd MalNote


Run the script:
python Final_Code_MlawarenoteGenerator.py


Enter:

File path

API keys (OTX, ThreatFox, VirusTotal, Gemini)

View the generated Markdown report (malware_note_<hash>.md)

🔑 Environment Variables
Variable	Description
OTX_API_KEY	AlienVault OTX API key
THREATFOX_API_KEY	ThreatFox API key
VIRUSTOTAL_API_KEY	VirusTotal API key
GEMINI_API_KEY	Gemini API key (optional)

🛡️ Disclaimer

This tool is for educational and research purposes only.
Do not use it to distribute or analyze live malware without proper authorization.
The author is not responsible for any misuse or damage caused by this software.
