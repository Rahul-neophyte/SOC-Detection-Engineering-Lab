import requests
import json
from datetime import datetime

OLLAMA_URL   = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "phi3:mini"

# Simplified chain data — less tokens = faster response
chain_summary = """
Attack on SOC Lab by Rahul Teja Kathi:
- Stage 1: Brute force SMB with CrackMapExec, got credentials for targetuser
- Stage 2: Privilege escalation via scheduled task, achieved SYSTEM access  
- Stage 3: Lateral movement via SMB, enumerated ADMIN$ C$ IPC$ shares
- Stage 4: Data exfiltration via Netcat port 4444, stole employee PII and passwords
Attacker IP: 192.168.56.103, Victim IP: 192.168.56.104
"""

prompt = f"""You are a CISO analyst. Analyze this attack and return ONLY JSON.
Start with {{ end with }}. No other text.

Attack: {chain_summary}

JSON format:
{{
"executive_summary": "2 sentence CISO summary",
"business_impact": "what was stolen and why it matters",
"mitre_chain": "T1110 to T1053 to T1021 to T1041",
"root_cause": "main security gap that enabled this",
"top_3_recommendations": ["rec1", "rec2", "rec3"],
"threat_actor_profile": "type of attacker"
}}"""

print("\n" + "="*65)
print("  ATTACK CHAIN ANALYZER — CISO BRIEFING")
print("  Rahul Teja Kathi | Phi3 Mini Local AI")
print("="*65)
print("\nAnalyzing full attack chain...")
print("Please wait 20-40 seconds...\n")

try:
    response = requests.post(
        OLLAMA_URL,
        json={
            "model": OLLAMA_MODEL,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.1,
                "num_predict": 500
            }
        },
        timeout=300
    )

    raw = response.json().get("response", "").strip()
    print(f"Raw response received ({len(raw)} chars)")

    # Extract JSON
    analysis = None
    try:
        analysis = json.loads(raw)
    except:
        start = raw.find("{")
        end = raw.rfind("}") + 1
        if start != -1 and end > start:
            try:
                analysis = json.loads(raw[start:end])
            except:
                analysis = None

    if analysis:
        print("\n" + "="*65)
        print("  CISO BRIEFING — CONFIDENTIAL")
        print("="*65)
        print(f"\nEXECUTIVE SUMMARY:")
        print(f"  {analysis.get('executive_summary', 'N/A')}")
        print(f"\nBUSINESS IMPACT:")
        print(f"  {analysis.get('business_impact', 'N/A')}")
        print(f"\nMITRE CHAIN:")
        print(f"  {analysis.get('mitre_chain', 'N/A')}")
        print(f"\nROOT CAUSE:")
        print(f"  {analysis.get('root_cause', 'N/A')}")
        print(f"\nTHREAT ACTOR:")
        print(f"  {analysis.get('threat_actor_profile', 'N/A')}")
        print(f"\nTOP 3 RECOMMENDATIONS:")
        recs = analysis.get('top_3_recommendations', [])
        for i, rec in enumerate(recs, 1):
            print(f"  {i}. {rec}")
        print("="*65)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"CISO_Report_{timestamp}.json"
        with open(filename, "w") as f:
            json.dump({
                "metadata": {
                    "analyst": "Rahul Teja Kathi",
                    "model": "Phi3 Mini Local",
                    "timestamp": datetime.now().isoformat(),
                    "cost": "FREE"
                },
                "attack_summary": chain_summary,
                "ciso_analysis": analysis
            }, f, indent=2)
        print(f"\n  Saved: {filename}")

    else:
        print("\nAI responded but JSON could not be parsed.")
        print("Raw response:")
        print(raw[:800])
        print("\nSaving raw response...")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"CISO_Raw_Response_{timestamp}.txt"
        with open(filename, "w") as f:
            f.write(f"Analyst: Rahul Teja Kathi\n")
            f.write(f"Timestamp: {datetime.now().isoformat()}\n")
            f.write(f"Model: Phi3 Mini Local\n\n")
            f.write(f"Attack Data:\n{chain_summary}\n\n")
            f.write(f"AI Response:\n{raw}")
        print(f"  Saved raw: {filename}")

except requests.exceptions.Timeout:
    print("Timeout — try running again. First run after download is slow.")
except Exception as e:
    print(f"Error: {e}")