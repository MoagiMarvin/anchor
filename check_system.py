import os
from dotenv import load_dotenv
from database import get_db

load_dotenv()
db = get_db()

print("\n" + "="*50)
print("       ANCHOR SYSTEM INTEGRITY CHECK")
print("="*50)

# 1. Check Watcher (Threats)
print("\n[WATCHER] Checking Recent Threats...")
try:
    threats = db.table("anchor_threats").select("threat_type, risk_score, created_at").order("created_at", desc=True).limit(3).execute()
    if threats.data:
        for t in threats.data:
            print(f"  - {t['created_at'][:19]} | {t['threat_type']} | Risk: {t['risk_score']}")
    else:
        print("  No threats found in database.")
except Exception as e:
    print(f"  Error checking threats: {e}")

# 2. Check POPIA
print("\n[POPIA] Checking Breach Reports...")
try:
    reports = db.table("anchor_popia_reports").select("breach_type, created_at, report_draft").order("created_at", desc=True).limit(1).execute()
    if reports.data:
        r = reports.data[0]
        print(f"  - Generated: {r['created_at'][:19]}")
        print(f"  - Breach Type: {r['breach_type']}")
        print("\n--- REPORT DRAFT PREVIEW ---")
        print(r['report_draft'][:500] + "...")
        print("----------------------------")
    else:
        print("  No POPIA reports generated yet.")
except Exception as e:
    print(f"  Error checking POPIA: {e}")

# 3. Check Honeypot
print("\n[HONEYPOT] Checking Attacker Containment...")
try:
    logs = db.table("anchor_honeypot_logs").select("action, endpoint, created_at").order("created_at", desc=True).limit(3).execute()
    if logs.data:
        for l in logs.data:
            print(f"  - {l['created_at'][:19]} | {l['action']} -> {l['endpoint']}")
    else:
        print("  No honeypot activity detected yet.")
except Exception as e:
    print(f"  Error checking honeypot: {e}")

print("\n" + "="*50)
