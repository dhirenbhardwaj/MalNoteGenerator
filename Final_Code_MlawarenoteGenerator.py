import os
import hashlib
import json
import requests
import yara
import pyclamd
import subprocess
# --------------------------------------------------------------------
# 1️⃣ HASH CALCULATION
# --------------------------------------------------------------------
def compute_file_hash(file_path, algorithm):
    """Compute the hash of a file using the specified algorithm."""
    hash_func = hashlib.new(algorithm)
    with open(file_path, 'rb') as file:
        while chunk := file.read(8192):
            hash_func.update(chunk)
    return hash_func.hexdigest()

# --------------------------------------------------------------------
# 2️⃣ CLAMAV SINGLE FILE SCAN
# --------------------------------------------------------------------
import subprocess
import shutil
import os

def scan_single_file(file_path, clamscan_exe=None, timeout=120):
    """
    Scan a single file using clamscan (fallback local scanner).
    - file_path: full path to the file to scan (string)
    - clamscan_exe: optional full path to clamscan.exe (if None, shutil.which is used)
    Returns a dict when infected, or None if clean / error.
    """
    # Normalize the path (handles forward/back slashes)
    file_path = os.path.abspath(file_path)

    if not os.path.isfile(file_path):
        print(f"[!] Error: file not found: {file_path}")
        return None

    # Find clamscan on PATH if not explicitly provided
    if clamscan_exe:
        clamscan_path = clamscan_exe
    else:
        clamscan_path = shutil.which("clamscan") or shutil.which("clamscan.exe")

    if not clamscan_path:
        print("[!] clamscan not found on PATH. Provide full path to clamscan.exe or add to PATH.")
        return None

    print(f"[→] Using clamscan at: {clamscan_path}")
    print(f"[→] Scanning: {file_path}")

    try:
        completed = subprocess.run(
            [clamscan_path, "--infected", "--no-summary", file_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout
        )
    except subprocess.TimeoutExpired:
        print("[!] clamscan timed out")
        return None
    except Exception as e:
        print(f"[!] Error running clamscan: {e}")
        return None

    stdout = completed.stdout or ""
    stderr = completed.stderr or ""

    # clamscan returns exit code 0 when no infected files, 1 when infected, >1 for errors
    if completed.returncode == 0:
        print("[✔] No threats found.")
        return None
    elif completed.returncode == 1:
        # parse lines like: C:\path\to\file: Eicar-Test-Signature FOUND
        for line in stdout.splitlines():
            if line.strip().endswith(" FOUND"):
                # split at the last ':' to be safe with paths that contain ':'
                parts = line.rsplit(":", maxsplit=1)
                if len(parts) == 2:
                    virus_part = parts[1].strip()      # "Eicar-Test-Signature FOUND"
                    virus_name = virus_part.rsplit(" ", 1)[0]  # remove "FOUND"
                    print(f"[⚠] MATCH FOUND! {virus_name}")
                    return {"status": "FOUND", "virus_name": virus_name}
        # If we couldn't parse but returncode == 1, show outputs for debugging
        print(f"[!] clamscan reported infection but couldn't parse output.\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}")
        return {"status": "FOUND", "virus_name": "UNKNOWN"}
    else:
        print(f"[!] clamscan failed (code {completed.returncode}). STDERR:\n{stderr}\nSTDOUT:\n{stdout}")
        return None


# --------------------------------------------------------------------
# 3️⃣ OTX LOOKUP
# --------------------------------------------------------------------
def lookup_otx(file_hash, api_key):
    """Query AlienVault OTX for a file hash."""
    url = f"https://otx.alienvault.com/api/v1/indicators/file/{file_hash}/general"
    headers = {"X-OTX-API-KEY": api_key}

    try:
        r = requests.get(url, headers=headers, timeout=20)
        if r.status_code == 200:
            data = r.json()
            pulses = data.get("pulse_info", {}).get("pulses", [])
            if len(pulses) > 0:
                return {
                    "source": "OTX",
                    "pulse_count": len(pulses),
                    "pulse_names": [p.get("name") for p in pulses],
                    "references": [p.get("references", []) for p in pulses],
                }
            else:
                print("[OTX] No pulses found for this hash.")
        elif r.status_code == 404:
            print("[OTX] No entry found (404).")
        else:
            print(f"[OTX] Error {r.status_code}: {r.text}")
    except Exception as e:
        print(f"[OTX] Exception: {e}")
    return None

# --------------------------------------------------------------------
# 4️⃣ THREATFOX LOOKUP
# --------------------------------------------------------------------
def lookup_threatfox(file_hash, api_key):
    """Query ThreatFox for a file hash."""
    url = "https://threatfox-api.abuse.ch/api/v1/"
    headers = {"Auth-Key": api_key, "User-Agent": "Malware-Triage-Client/1.0"}
    payload = {"query": "search_hash", "hash": file_hash}

    try:
        r = requests.post(url, json=payload, headers=headers, timeout=30)
        if r.status_code == 200:
            data = r.json()
            if data.get("query_status") == "ok" and data.get("data"):
                return {
                    "source": "ThreatFox",
                    "ioc_count": len(data["data"]),
                    "sample": data["data"][0],
                }
            else:
                print("[ThreatFox] No results found for this hash.")
        else:
            print(f"[ThreatFox] Error {r.status_code}: {r.text}")
    except Exception as e:
        print(f"[ThreatFox] Exception: {e}")
    return None

# --------------------------------------------------------------------
# 5️⃣ MALWAREBAZAAR LOOKUP
# --------------------------------------------------------------------
def lookup_malwarebazaar(file_hash):
    """Query MalwareBazaar for hash info (no API key required)."""
    url = "https://mb-api.abuse.ch/api/v1/"
    data = {"query": "get_info", "hash": file_hash}

    try:
        r = requests.post(url, data=data, timeout=20)
        if r.status_code == 200:
            result = r.json()
            if result.get("query_status") == "ok":
                entry = result["data"][0]
                return {
                    "source": "MalwareBazaar",
                    "file_type": entry.get("file_type"),
                    "signature": entry.get("signature"),
                    "tags": entry.get("tags", []),
                }
            else:
                print("[MalwareBazaar] No match found.")
        else:
            print(f"[MalwareBazaar] Error {r.status_code}: {r.text}")
    except Exception as e:
        print(f"[MalwareBazaar] Exception: {e}")
    return None

# --------------------------------------------------------------------
# 6️⃣ VIRUSTOTAL LOOKUP
# --------------------------------------------------------------------
def lookup_virustotal(file_hash, api_key):
    if not api_key:
        return None
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}
    try:
        r = requests.get(url, headers=headers, timeout=30)
        if r.status_code == 200:
            data = r.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            return {
                "source": "VirusTotal",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "link": f"https://www.virustotal.com/gui/file/{file_hash}"
            }
    except Exception as e:
        print("[VirusTotal] Error:", e)
    return None

# --------------------------------------------------------------------
# 7️⃣ MULTI-SOURCE LOOKUP
# --------------------------------------------------------------------
def multi_lookup(file_hash, otx_key, threatfox_key, vt_key):
    print(f"\n[+] Searching for hash: {file_hash}\n")

    otx_result = lookup_otx(file_hash, otx_key)
    if otx_result:
        print("[✔] Found result on OTX.\n")
        return otx_result

    print("[→] Trying ThreatFox...")
    tf_result = lookup_threatfox(file_hash, threatfox_key)
    if tf_result:
        print("[✔] Found result on ThreatFox.\n")
        return tf_result

    print("[→] Trying MalwareBazaar...")
    mb_result = lookup_malwarebazaar(file_hash)
    if mb_result:
        print("[✔] Found result on MalwareBazaar.\n")
        return mb_result

    print("[→] Trying VirusTotal...")
    vt_result = lookup_virustotal(file_hash, vt_key)
    if vt_result:
        print("[✔] Found result on VirusTotal.\n")
        return vt_result

    print("[✖] No results found on any platform.")
    return {"source": None, "message": "No results from OTX, ThreatFox, MalwareBazaar, or VirusTotal."}

# --------------------------------------------------------------------
# 8️⃣ CREATE MALWARE NOTE
# --------------------------------------------------------------------
def create_malware_note(file_path, algorithm, file_hash, clamav_result, intel_results):
    """Generate a malware note (Markdown)."""
    note = []
    note.append("# 🧾 Malware Analysis Note\n")
    note.append(f"**File Path:** {file_path}")
    note.append(f"**Hash Algorithm:** {algorithm}")
    note.append(f"**Hash Value:** `{file_hash}`\n")

    note.append("## 🧠 ClamAV Scan Result")
    if clamav_result:
        note.append(f"- **Status:** {clamav_result.get('status', 'Unknown')}")
        note.append(f"- **Detection:** {clamav_result.get('virus_name', 'None')}\n")
    else:
        note.append("- No threats found.\n")

    note.append("## 🌐 Threat Intelligence Summary\n")
    if intel_results:
        note.append(f"**Source:** {intel_results.get('source', 'N/A')}")
        for k, v in intel_results.items():
            if k != "source":
                note.append(f"- **{k.capitalize()}**: {v}")
    else:
        note.append("No intelligence hits from OTX, ThreatFox, MalwareBazaar, or VirusTotal.")

    file_name = f"malware_note_{file_hash[:10]}.md"
    with open(file_name, "w", encoding="utf-8") as f:
        f.write("\n".join(note))
    print(f"\n[+] Malware note created: {file_name}")
    return file_name

# --------------------------------------------------------------------
# 9️⃣ GEMINI AI ANALYSIS
# --------------------------------------------------------------------
def analyze_with_gemini(gemini_api_key, note_text):
    """Send the malware note to Gemini API for AI-based analysis."""
    if not gemini_api_key:
        print("[!] Gemini API key not provided — skipping AI analysis.")
        return None

    url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent"
    headers = {"Content-Type": "application/json"}
    params = {"key": gemini_api_key}

    payload = {
        "contents": [
            {
                "parts": [
                    {
                        "text": (
                            "You are a malware analyst. Given the following malware note, "
                            "summarize findings and suggest next DFIR actions.\n\n"
                            f"{note_text}"
                        )
                    }
                ]
            }
        ]
    }

    try:
        r = requests.post(url, headers=headers, params=params, json=payload, timeout=60)
        if r.status_code == 200:
            data = r.json()
            output = data["candidates"][0]["content"]["parts"][0]["text"]
            print("\n=== 🧠 Gemini AI Analysis ===\n")
            print(output)
            return output
        else:
            print(f"[Gemini] Error {r.status_code}: {r.text}")
    except Exception as e:
        print(f"[Gemini] Exception: {e}")
    return None

# --------------------------------------------------------------------
# 🔟 MAIN PROGRAM
# --------------------------------------------------------------------
if __name__ == "__main__":
    print("=== Malware Note Generator ===\n")

    file_path = input("Enter file path: ").strip()
    algorithm = "sha256"

    try:
        file_hash = compute_file_hash(file_path, algorithm)
        print(f"[+] Computed {algorithm}: {file_hash}")
    except Exception as e:
        print(f"[!] Error computing hash: {e}")
        exit()

    # 1. ClamAV
    clamav_result = scan_single_file(file_path)

    # 2. Threat intel lookups
    otx_key = os.getenv("OTX_API_KEY") or input("Enter OTX API Key: ").strip()
    tf_key = os.getenv("THREATFOX_API_KEY") or input("Enter ThreatFox API Key: ").strip()
    vt_key = os.getenv("VIRUSTOTAL_API_KEY") or input("Enter VirusTotal API Key: ").strip()
    gem_key = os.getenv("GEMINI_API_KEY") or input("Enter Gemini API Key: ").strip()

    intel_result = multi_lookup(file_hash, otx_key, tf_key, vt_key)

    # 3. Create malware note
    note_file = create_malware_note(file_path, algorithm, file_hash, clamav_result, intel_result)

    # 4. Upload note to Gemini
    with open(note_file, "r", encoding="utf-8") as f:
        note_text = f.read()
    analyze_with_gemini(gem_key, note_text)
