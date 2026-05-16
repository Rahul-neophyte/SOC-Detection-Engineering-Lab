import requests
import json
from datetime import datetime

# ============================================
# SOC AI ANALYZER v2.1 — FIXED
# Rahul Teja Kathi
# Ollama + Mistral 7B (Local — Free)
# ============================================

OLLAMA_URL   = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "phi3:mini"
SPLUNK_HOST  = "192.168.56.101"
SPLUNK_PORT  = "8089"
SPLUNK_TOKEN = "eyJraWQiOiJzcGx1bmsuc2VjcmV0IiwiYWxnIjoiSFM1MTIiLCJ2ZXIiOiJ2MiIsInR0eXAiOiJzdGF0aWMifQ.eyJpc3MiOiJyYWh1bCBmcm9tIFVidW50dSIsInN1YiI6InJhaHVsIiwiYXVkIjoiTUlTVFJBTCBUT0tFTiIsImlkcCI6IlNwbHVuayIsImp0aSI6ImI2ZjhmZGQwN2NhZDc4MGMwMjI5ODEwODNlYWZlYTU4OGQzMTdhZWI0NGJmOGFhMzJhZjc0MDBkOTNkY2M0OGIiLCJpYXQiOjE3Nzg5MjI0NDgsImV4cCI6MTc4MTUxNDQ0OCwibmJyIjoxNzc4OTIyNDQ4fQ.2RvBYsLkUJtD3R-WUpbycN-jvZm_za8H1WPvU03P8HCuFsej1eUwbIbZMLjOgzGBy23W7ZI3uwByoCJyt04lfQ"
SPLUNK_BASE  = f"https://{SPLUNK_HOST}:{SPLUNK_PORT}"

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SPLUNK_HEADERS = {
    "Authorization": f"Bearer {SPLUNK_TOKEN}",
    "Content-Type": "application/x-www-form-urlencoded"
}

# ============================================
# FUNCTION: Query Mistral — Fixed JSON forcing
# ============================================
def query_mistral(alert_name, alert_data):
    print(f"    Querying Mistral AI...")

    # Simplified prompt that forces clean JSON
    prompt = f"""[INST]
You are a SOC analyst. Analyze this alert and return ONLY a JSON object.
Start your response with {{ and end with }}.
Do not include any text outside the JSON.

Alert: {alert_name}
Data: {json.dumps(alert_data)}

Return this exact JSON structure:
{{
"severity": "CRITICAL",
"confidence": "HIGH",
"attack_summary": "what happened in plain english",
"mitre_technique": "T1110.001 Password Guessing",
"mitre_tactic": "Credential Access",
"attack_stage": "Initial Access",
"immediate_actions": ["block source IP", "reset account", "check for success after failures"],
"false_positive_likelihood": "LOW",
"false_positive_reason": "why this might be false positive",
"incident_report_paragraph": "professional paragraph for report",
"analyst_note": "additional context"
}}
[/INST]"""

    try:
        response = requests.post(
            OLLAMA_URL,
            json={
                "model": OLLAMA_MODEL,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.1,
                    "top_p": 0.9,
                    "num_predict": 400
                }
            },
            timeout=240
        )

        raw = response.json().get("response", "").strip()

        # Multiple JSON extraction attempts
        # Attempt 1: Direct parse
        try:
            return json.loads(raw)
        except:
            pass

        # Attempt 2: Find first { to last }
        try:
            start = raw.find("{")
            end = raw.rfind("}") + 1
            if start != -1 and end > start:
                return json.loads(raw[start:end])
        except:
            pass

        # Attempt 3: Clean common issues
        try:
            cleaned = raw.replace("\n", " ").replace("\\n", " ")
            start = cleaned.find("{")
            end = cleaned.rfind("}") + 1
            if start != -1 and end > start:
                return json.loads(cleaned[start:end])
        except:
            pass

        # Fallback: Build manual response from raw text
        print(f"    AI responded but JSON malformed — building manual response")
        return build_manual_response(alert_name, raw)

    except Exception as e:
        print(f"    Mistral error: {e}")
        return {"error": str(e)}


# ============================================
# FUNCTION: Build manual response if JSON fails
# ============================================
def build_manual_response(alert_name, raw_text):
    severity_map = {
        "brute": "HIGH",
        "privilege": "CRITICAL",
        "lateral": "HIGH",
        "exfil": "CRITICAL"
    }

    name_lower = alert_name.lower()
    severity = "HIGH"
    for key, val in severity_map.items():
        if key in name_lower:
            severity = val
            break

    return {
        "severity": severity,
        "confidence": "MEDIUM",
        "attack_summary": f"Mistral analyzed {alert_name}. Raw response captured for review.",
        "mitre_technique": "See raw response",
        "mitre_tactic": "See raw response",
        "attack_stage": "Under Investigation",
        "immediate_actions": [
            "Review raw AI response in saved JSON file",
            "Manually investigate the alert",
            "Escalate if confirmed malicious"
        ],
        "false_positive_likelihood": "MEDIUM",
        "false_positive_reason": "Manual review required",
        "incident_report_paragraph": f"Alert {alert_name} was analyzed by Mistral AI. Manual review of the raw response is recommended.",
        "analyst_note": f"Raw AI output: {raw_text[:300]}",
        "raw_ai_response": raw_text[:500]
    }


# ============================================
# FUNCTION: Run Splunk search
# ============================================
def run_splunk_search(spl_query, time_range="-7d"):
    import time
    print(f"    Querying Splunk...")

    try:
        create_url = f"{SPLUNK_BASE}/services/search/jobs"
        search_data = {
            "search": f"search {spl_query}",
            "earliest_time": time_range,
            "latest_time": "now",
            "output_mode": "json"
        }

        response = requests.post(
            create_url,
            headers=SPLUNK_HEADERS,
            data=search_data,
            verify=False,
            timeout=30
        )

        if response.status_code == 401:
            print(f"    Splunk token expired — update SPLUNK_TOKEN in script")
            return []

        if response.status_code != 201:
            print(f"    Splunk error {response.status_code} — using lab data")
            return []

        job_sid = response.json()["sid"]

        for attempt in range(20):
            time.sleep(2)
            status_url = f"{SPLUNK_BASE}/services/search/jobs/{job_sid}"
            status_r = requests.get(
                status_url,
                headers={"Authorization": f"Bearer {SPLUNK_TOKEN}"},
                params={"output_mode": "json"},
                verify=False,
                timeout=30
            )
            state = status_r.json()["entry"][0]["content"]["dispatchState"]
            if state == "DONE":
                break
            elif state == "FAILED":
                return []

        results_url = f"{SPLUNK_BASE}/services/search/jobs/{job_sid}/results"
        results_r = requests.get(
            results_url,
            headers={"Authorization": f"Bearer {SPLUNK_TOKEN}"},
            params={"output_mode": "json", "count": 5},
            verify=False,
            timeout=30
        )

        results = results_r.json().get("results", [])
        print(f"    Got {len(results)} results from Splunk")
        return results

    except Exception as e:
        print(f"    Splunk error: {e} — using lab data")
        return []


# ============================================
# FUNCTION: Print analysis
# ============================================
def print_analysis(alert_name, analysis):
    print("\n" + "="*65)
    print(f"  AI ANALYSIS: {alert_name}")
    print("="*65)

    if "error" in analysis and len(analysis) == 1:
        print(f"  ERROR: {analysis['error']}")
        return

    sev = analysis.get("severity", "UNKNOWN")
    print(f"\n  SEVERITY:        [{sev}]")
    print(f"  CONFIDENCE:      {analysis.get('confidence', 'N/A')}")
    print(f"  ATTACK STAGE:    {analysis.get('attack_stage', 'N/A')}")
    print(f"  MITRE TECHNIQUE: {analysis.get('mitre_technique', 'N/A')}")
    print(f"  MITRE TACTIC:    {analysis.get('mitre_tactic', 'N/A')}")
    print(f"\n  WHAT HAPPENED:")
    print(f"  {analysis.get('attack_summary', 'N/A')}")
    print(f"\n  FALSE POSITIVE:  {analysis.get('false_positive_likelihood', 'N/A')}")
    print(f"  REASON:          {analysis.get('false_positive_reason', 'N/A')}")
    print(f"\n  IMMEDIATE ACTIONS:")
    actions = analysis.get("immediate_actions", [])
    for i, action in enumerate(actions, 1):
        print(f"  {i}. {action}")
    print(f"\n  INCIDENT REPORT PARAGRAPH:")
    print(f"  {analysis.get('incident_report_paragraph', 'N/A')}")
    print(f"\n  ANALYST NOTE:")
    print(f"  {analysis.get('analyst_note', 'N/A')}")
    print("="*65)


# ============================================
# FUNCTION: Save analysis
# ============================================
def save_analysis(alert_name, alert_data, ai_analysis):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_name = alert_name.replace(" ", "_")
    filename = f"AI_Analysis_{safe_name}_{timestamp}.json"

    output = {
        "report_metadata": {
            "alert_name": alert_name,
            "analyst": "Rahul Teja Kathi",
            "tool": "SOC AI Analyzer v2.1",
            "timestamp": datetime.now().isoformat(),
            "ai_model": "Mistral 7B Local (Ollama)",
            "cost": "FREE"
        },
        "alert_data": alert_data,
        "ai_analysis": ai_analysis
    }

    with open(filename, "w") as f:
        json.dump(output, f, indent=2)

    print(f"    Saved: {filename}")
    return filename


# ============================================
# MAIN
# ============================================
def main():
    print("\n" + "="*65)
    print("  SOC AI ANALYZER v2.1 — FREE EDITION")
    print("  Rahul Teja Kathi")
    print("  Ollama + Mistral 7B (Local AI)")
    print("="*65)

    saved_files = []

    # ALERT 1 — BRUTE FORCE
    print("\n[1/4] BRUTE FORCE (T1110.001)")
    print("-"*40)
    splunk_1 = run_splunk_search(
        'index=winlogs EventCode=4625 | stats count as failures by src_ip | where failures > 3',
        "-7d"
    )
    alert_1 = {
        "alert_id": "DE-001",
        "EventCode": "4625",
        "Account_Name": "targetuser",
        "src_ip": "192.168.56.103",
        "dest_ip": "192.168.56.104",
        "failure_count": 15,
        "time_window": "5 minutes",
        "protocol": "SMB 445",
        "tool": "CrackMapExec",
        "splunk_results": splunk_1,
        "timestamp": "2026-05-05 22:33 IST"
    }
    analysis_1 = query_mistral("DE-001 Brute Force", alert_1)
    print_analysis("DE-001 Brute Force", analysis_1)
    f1 = save_analysis("DE001_BruteForce", alert_1, analysis_1)
    saved_files.append(f1)

    # ALERT 2 — PRIVILEGE ESCALATION
    print("\n[2/4] PRIVILEGE ESCALATION (T1053.005)")
    print("-"*40)
    splunk_2 = run_splunk_search(
        'index=winlogs EventCode=4672 Account_Name=SYSTEM | stats count by host',
        "-7d"
    )
    alert_2 = {
        "alert_id": "DE-002",
        "EventCode": "4672",
        "Account_Name": "SYSTEM",
        "process": "schtasks.exe",
        "parent": "cmd.exe",
        "command": "schtasks /run /tn PrivEscDemo",
        "result": "nt authority\\system",
        "splunk_results": splunk_2,
        "timestamp": "2026-05-04 22:43 IST"
    }
    analysis_2 = query_mistral("DE-002 Privilege Escalation", alert_2)
    print_analysis("DE-002 Privilege Escalation", analysis_2)
    f2 = save_analysis("DE002_PrivEsc", alert_2, analysis_2)
    saved_files.append(f2)

    # ALERT 3 — LATERAL MOVEMENT
    print("\n[3/4] LATERAL MOVEMENT (T1021.002)")
    print("-"*40)
    splunk_3 = run_splunk_search(
        'index=winlogs EventCode=4624 Logon_Type=3 | stats count by Account_Name, src_ip | where count > 1',
        "-7d"
    )
    alert_3 = {
        "alert_id": "DE-003",
        "EventCode": "4624",
        "Logon_Type": "3",
        "Account_Name": "targetuser",
        "src_ip": "192.168.56.103",
        "dest_ip": "192.168.56.104",
        "shares": ["ADMIN$", "C$", "IPC$"],
        "tool": "CrackMapExec",
        "splunk_results": splunk_3,
        "timestamp": "2026-05-05 22:45 IST"
    }
    analysis_3 = query_mistral("DE-003 Lateral Movement", alert_3)
    print_analysis("DE-003 Lateral Movement", analysis_3)
    f3 = save_analysis("DE003_LateralMovement", alert_3, analysis_3)
    saved_files.append(f3)

    # ALERT 4 — DATA EXFILTRATION
    print("\n[4/4] DATA EXFILTRATION (T1041)")
    print("-"*40)
    splunk_4 = run_splunk_search(
        'index=winlogs sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3 | where DestinationPort!=80 AND DestinationPort!=443',
        "-7d"
    )
    alert_4 = {
        "alert_id": "DE-004",
        "process": "powershell.exe",
        "src_ip": "192.168.56.104",
        "dest_ip": "192.168.56.103",
        "dest_port": "4444",
        "files_stolen": ["sensitive_data.txt", "credentials.txt"],
        "confirmed": True,
        "splunk_results": splunk_4,
        "timestamp": "2026-05-08 22:50 IST"
    }
    analysis_4 = query_mistral("DE-004 Data Exfiltration", alert_4)
    print_analysis("DE-004 Data Exfiltration", analysis_4)
    f4 = save_analysis("DE004_DataExfiltration", alert_4, analysis_4)
    saved_files.append(f4)

    print("\n" + "="*65)
    print("  COMPLETE")
    print("="*65)
    print(f"  Model:    Mistral 7B Local")
    print(f"  Analyst:  Rahul Teja Kathi")
    print(f"  Cost:     ZERO")
    print(f"\n  Saved files:")
    for f in saved_files:
        print(f"    {f}")
    print("="*65 + "\n")


if __name__ == "__main__":
    main()