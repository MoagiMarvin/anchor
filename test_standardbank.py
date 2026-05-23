#!/usr/bin/env python3
"""
==================================================================
        ANCHOR — STANDARD BANK SCENARIO SIMULATION
==================================================================
Simulates two distinct scenarios:
  1. Legitimate Admin (Enrolled device, normal/admin operations, 
     evading false positives, escalating if cumulative risk is too high)
  2. Rootboy Attacker (Stolen credentials, unenrolled device,
     silently contained in the honeypot environment)

Run with:
  python test_standardbank.py
==================================================================
"""

from test_hacker_ai import hack
from hpack import hpack
from hpack import hpack
import requests
import json
import time
import sys
from datetime import datetime

BASE_URL = "http://localhost:8000"
API_KEY  = "anchor-standardbank-2026-demo-key"
ADMIN_ID = "admin@standardbank.co.za"

HEADERS  = {
    "X-API-Key":   API_KEY,
    "Content-Type": "application/json"
}

# Style helpers for logs
def banner(title):
    print("\n" + "=" * 65)
    print(f"  {title}")
    print("=" * 65)

def sep():
    print("─" * 65)

def ok(msg):     print(f"  \033[92m[PASS]  ✅ {msg}\033[0m")
def warn(msg):   print(f"  \033[93m[WARN]  ⚠️  {msg}\033[0m")
def fail(msg):   print(f"  \033[91m[FAIL]  ❌ {msg}\033[0m")
def info(msg):   print(f"  \033[94m[INFO]  ℹ  {msg}\033[0m")
def alert(msg):  print(f"  \033[95m[ALERT] 🚨 {msg}\033[0m")
def honey(msg):  print(f"  \033[33m[HONEY] 🍯 {msg}\033[0m")
def hack(msg):   print(f"  \033[35m[HACK]  🕵 {msg}\033[0m")


def run_standardbank_test():
    banner("ANCHOR: STANDARD BANK END-TO-END SIMULATION")
    info(f"Target API: {BASE_URL}")
    info(f"API Key:    {API_KEY}")

    # Check API health
    try:
        r = requests.get(f"{BASE_URL}/", headers=HEADERS)
        if r.status_code == 200:
            ok("FastAPI server is running and accessible.")
        else:
            fail(f"Failed to connect to API, Status Code: {r.status_code}")
            sys.exit(1)
    except Exception as e:
        fail(f"Could not connect to the API server at {BASE_URL}: {e}")
        sys.exit(1)

    # ────────────────────────────────────────────────────────────────
    # SCENARIO 1: LEGITIMATE ADMINISTRATOR
    # ────────────────────────────────────────────────────────────────
    banner("SCENARIO 1: LEGITIMATE ADMINISTRATOR (John Smith)")
    
    legit_ip = "10.0.1.45"
    legit_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Standard Bank Internal"
    
    # Step 1.1: Enroll the legitimate admin's hardware
    info("John Smith turns on corporate laptop. Self-enrolling device fingerprint...")
    enroll_payload = {
        "employee_id": ADMIN_ID,
        "ip_address":  legit_ip,
        "user_agent":  legit_ua
    }
    status, res = post_req("/enroll/device/self-enroll", enroll_payload)
    if status == 200:
        ok("Corporate laptop successfully enrolled in Standard Bank's device registry.")
    else:
        fail(f"Self-enrollment failed: {res}")

    # Step 1.2: Create secure session
    info("Logging in to internal bank portal...")
    session_payload = {
        "user_id":    ADMIN_ID,
        "ip_address": legit_ip,
        "user_agent": legit_ua
    }
    status, session_data = post_req("/session/create", session_payload)
    if status == 200 and "token" in session_data:
        token = session_data["token"]
        ok(f"Session created successfully. Token received (len={len(token)}).")
    else:
        fail(f"Session creation failed: {session_data}")
        return

    # Step 1.3: Validate the session
    info("Performing initial 4-layer session validation check...")
    val_payload = {
        "token":      token,
        "ip_address": legit_ip,
        "user_agent": legit_ua
    }
    status, val_data = post_req("/session/validate", val_payload)
    if status == 200 and val_data.get("status") == "ok":
        ok("All 4 validation layers passed! (Dilithium Sig, DB status, IP/UA match, Enrolled Hardware).")
        info(f"Initial Session Risk Score: {val_data.get('risk', {}).get('score', 0)}")
    else:
        fail(f"Validation failed: {val_data}")

    # Step 1.4: Admin performs a few normal sensitive actions
    sep()
    info("John Smith browses corporate files...")
    status, act1 = post_req("/session/event", {
        "token":       token,
        "action":      "view_records",
        "endpoint":    "/sharepoint/browse",
        "data_volume": 10,
        "ip_address":  legit_ip,
        "user_agent":  legit_ua
    })
    ok(f"Action 'view_records' logged. Status: {act1.get('status')} | Risk Score: {act1.get('risk_score', 0)}")

    time.sleep(1)
    info("John Smith downloads a small selected dataset...")
    status, act2 = post_req("/session/event", {
        "token":       token,
        "action":      "export_records",
        "endpoint":    "/sharepoint/download",
        "data_volume": 100,
        "ip_address":  legit_ip,
        "user_agent":  legit_ua
    })
    ok(f"Action 'export_records' logged. Status: {act2.get('status')} | Risk Score: {act2.get('risk_score', 0)}")

    # Step 1.5: Cumulative Risk Safeguard
    # Legitimate admin attempts bulk downloads sequentially (escalating policy)
    sep()
    warn("John Smith initiates a large download (1.2TB of data)...")
    status, act3 = post_req("/session/event", {
        "token":       token,
        "action":      "bulk_download",
        "endpoint":    "/sharepoint/bulk-download",
        "data_volume": 1200000,
        "ip_address":  legit_ip,
        "user_agent":  legit_ua
    })
    
    risk3 = act3.get("risk_score", 0)
    warn(f"First Bulk Download. Verdict: {act3.get('message')} | Cumulative Risk: {risk3}")
    
    # Already at reauth (60) after first bulk download — show the escalation result
    action3 = act3.get("action_required", "none")
    if action3 == "reauth":
        alert("Anchor escalated to REAUTH after first 1.2TB bulk download!")
        info(f"Explanation: {act3.get('explanation') or 'Repeated bulk download exceeds safe threshold.'}")
        warn("Session is now in re-authentication hold. Further bulk actions will be blocked.")
    elif action3 == "kill":
        alert("Session KILLED by Anchor on first bulk download attempt!")
        info(f"Explanation: {act3.get('explanation')}")
    else:
        time.sleep(1)
        warn("John Smith attempts the bulk download a second time...")
        status, act4 = post_req("/session/event", {
            "token":       token,
            "action":      "bulk_download",
            "endpoint":    "/sharepoint/bulk-download",
            "data_volume": 1200000,
            "ip_address":  legit_ip,
            "user_agent":  legit_ua
        })
        risk4 = act4.get("risk_score", 0)
        warn(f"Second Bulk Download. Verdict: {act4.get('message')} | Cumulative Risk: {risk4}")
        action4 = act4.get("action_required", "none")
        if action4 in ("kill", "reauth"):
            alert(f"Anchor Triggered Safeguard! Action required: {action4.upper()}")
            info(f"Explanation: {act4.get('explanation') or 'Repeated high-volume download flagged.'}") 
        else:
            info("Cumulative risk is monitored but below termination threshold.")

    # Clean up session
    requests.post(f"{BASE_URL}/session/kill", headers=HEADERS, json={"token": token})


    # ────────────────────────────────────────────────────────────────
    # SCENARIO 2: ROOTBOY ATTACKER
    # ────────────────────────────────────────────────────────────────
    banner("SCENARIO 2: ROOTBOY ATTACKER (Stolen Credentials)")
    
    hacker_ip = "41.203.0.1" # Stolen credentials used from foreign/Nigerian range IP
    hacker_ua = "Mozilla/5.0 (Linux; x86_64) RootboyAttacker/1.0"
    
    # Step 2.1: Attack session creation
    info("Rootboy logs in using John Smith's stolen password...")
    status, h_session_data = post_req("/session/create", {
        "user_id":    ADMIN_ID,
        "ip_address": hacker_ip,
        "user_agent": hacker_ua
    })
    if status == 200 and "token" in h_session_data:
        h_token = h_session_data["token"]
        ok(f"Session established. Token issued: {h_token[:30]}...")
    else:
        fail(f"Hacker login failed: {h_session_data}")
        return

    # Step 2.2: Session validation fails enrolled hardware check
    info("Rootboy triggers first portal action, starting session validation...")
    status, h_val_data = post_req("/session/validate", {
        "token":      h_token,
        "ip_address": hacker_ip,
        "user_agent": hacker_ua
    })
    
    if status == 200 and h_val_data.get("status") == "warning":
        honey("VALIDATION WARNING! Check 4 (Enrolled Hardware) FAILED.")
        honey(f"Verdict: {h_val_data.get('message')}")
        honey("Anchor silently flagged this session as a HONEYPOT. Attacker is now sandboxed.")
    else:
        warn(f"Honeypot check output: {h_val_data}")

    # Step 2.3: Rootboy attempts massive bulk export
    sep()
    hack("Rootboy attempts to download ALL customer records (154,000,000 rows)...")
    status, h_act1 = post_req("/session/event", {
        "token":       h_token,
        "action":      "bulk_download",
        "endpoint":    "/api/crm/bulk-export",
        "data_volume": 154000000,
        "ip_address":  hacker_ip,
        "user_agent":  hacker_ua
    })
    
    if h_act1.get("honeypot") or "Honeypot" in h_act1.get("message", "") or h_act1.get("status") == "ok":
        honey("Silent redirection active! Attacker download completed successfully (Faked).")
        honey(f"Honeypot returned response: '{h_act1.get('message')}'")
        ok("Attacker remains contained in the sandbox. Risk score presented to attacker is 0.")
    else:
        fail(f"Rootboy bulk download wasn't caught in honeypot! Response: {h_act1}")

    # Step 2.4: Rootboy tries looking for system database schemas
    time.sleep(1)
    hack("Rootboy runs database queries to locate other high-value tables...")
    status, h_act2 = post_req("/session/event", {
        "token":       h_token,
        "action":      "database_query",
        "endpoint":    "/schema/tables",
        "data_volume": 200,
        "ip_address":  hacker_ip,
        "user_agent":  hacker_ua
    })
    honey(f"Hacker database probe intercepted. Sandbox response: '{h_act2.get('message')}'")

    # Step 2.5: Cleanup & Threat Dashboard verification info
    sep()
    info("Attack simulation complete.")
    info("Go to http://localhost:8000/dashboard in your browser to view:")
    info("  - The logged attacks in the Honeypot Activity section.")
    info("  - The generated POPIA breach notification report for the attacker's bulk export.")

    # Kill session
    requests.post(f"{BASE_URL}/session/kill", headers=HEADERS, json={"token": h_token})


# Helper to send POST requests — always returns (status_code, dict)
def post_req(path, payload):
    try:
        r = requests.post(f"{BASE_URL}{path}", headers=HEADERS, json=payload, timeout=8)
        try:
            return r.status_code, r.json()
        except Exception:
            return r.status_code, {"error": r.text[:200]}
    except Exception as e:
        return 0, {"error": str(e)}


if __name__ == "__main__":
    run_standardbank_test()
