"""
Anchor Test Script — Session Event Flow
Run this from WSL inside your anchor venv:
  python3 test_events.py

It will:
  1. Create a real session (Dilithium signed)
  2. Fire a sequence of events simulating a suspicious user
  3. Print the risk score and AI verdict after each event
  4. Show you when reauth or kill is triggered
"""

from requests import status_codes
import requests
import json
import time

BASE_URL = "http://127.0.0.1:8000"
API_KEY  = "anchor-ul-2026-demo-key"

HEADERS = {
    "X-API-Key": API_KEY,
    "Content-Type": "application/json"
}

# ── Simulated attacker profile ───────────────────────────
USER_ID    = "student_001"
IP_ADDRESS = "197.1.1.1"
USER_AGENT = "Mozilla/5.0"

# Event sequence — simulates reconnaissance → exfiltration
# Adjust these to test different attack patterns
EVENTS = [
    {"action": "view_dashboard",    "endpoint": "/dashboard",           "data_volume": 0},
    {"action": "view_records",      "endpoint": "/students",            "data_volume": 5},
    {"action": "database_query",    "endpoint": "/api/students/search", "data_volume": 20},
    {"action": "admin_access",      "endpoint": "/admin/users",         "data_volume": 0},
    {"action": "schema_access",     "endpoint": "/schema",              "data_volume": 0},
    {"action": "export_records",    "endpoint": "/api/students/export", "data_volume": 200},
    {"action": "export_records",    "endpoint": "/api/students/export", "data_volume": 500},
    {"action": "bulk_download",     "endpoint": "/export",              "data_volume": 1000},
]


def print_divider():
    print("\n" + "─" * 60)


def step(msg):
    print(f"\n▶  {msg}")


def create_session():
    step("Creating Dilithium session...")
    r = requests.post(f"{BASE_URL}/session/create", headers=HEADERS, json={
        "user_id":    USER_ID,
        "ip_address": IP_ADDRESS,
        "user_agent": USER_AGENT
    })
    data = r.json()
    if data.get("status") != "ok":
        print(f"❌ Session creation failed: {data}")
        exit(1)

    token = data["token"]
    print(f"✅ Session created for: {USER_ID}")
    print(f"   Token prefix: {token[:30]}...")
    return token


def fire_event(token, event, index):
    print_divider()
    print(f"EVENT {index + 1}/{len(EVENTS)}")
    print(f"  Action:      {event['action']}")
    print(f"  Endpoint:    {event['endpoint']}")
    print(f"  Data volume: {event['data_volume']} records")

    r = requests.post(f"{BASE_URL}/session/event", headers=HEADERS, json={
        "token":       token,
        "action":      event["action"],
        "endpoint":    event["endpoint"],
        "data_volume": event["data_volume"],
        "ip_address":  IP_ADDRESS,
        "user_agent":  USER_AGENT
    })

    data = r.json()

    status  = data.get("status", "unknown")
    message = data.get("message", "")
    risk    = data.get("risk", {})

    score   = risk.get("score", 0)   if risk else 0
    level   = risk.get("level", "-") if risk else "-"

    # Risk bar
    filled = int(score / 5)
    bar    = "█" * filled + "░" * (20 - filled)

    print(f"\n  Status:      {_status_icon(status)} {status.upper()}")
    print(f"  Risk score:  [{bar}] {score}/100 ({level})")

    if risk and risk.get("reasons"):
        for reason in risk["reasons"]:
            if reason:
                print(f"  ⚠  {reason[:120]}")

    if message:
        print(f"  Action:      {message}")

    return status


def _status_icon(status):
    return {"ok": "✅", "warning": "⚠️ ", "threat": "🚨"}.get(status, "❓")


def run():
    print("═" * 60)
    print("  ANCHOR — Session Behavioural Monitoring Test")
    print("  University of Limpopo Demo")
    print("═" * 60)

    token = create_session()
    time.sleep(0.5)

    for i, event in enumerate(EVENTS):
        status = fire_event(token, event, i)
        time.sleep(0.3)

        if status == "threat":
            print_divider()
            print("🚨 SESSION TERMINATED — test complete")
            print("   The session was killed before the full exfiltration completed.")
            break
    else:
        print_divider()
        print("✅ All events fired — check your Supabase dashboard for full logs")

    print("\n")


if __name__ == "__main__":
    run()
