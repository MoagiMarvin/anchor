import requests
import json
import time

BASE_URL = "http://127.0.0.1:8000"
API_KEY  = "anchor-ul-2026-demo-key"

HEADERS = {
    "X-API-Key": API_KEY,
    "Content-Type": "application/json"
}

USER_ID    = "student_001"
IP_ADDRESS = "197.1.1.1"
USER_AGENT = "Mozilla/5.0"

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
    print("\n" + "-" * 60)

def step(msg):
    print(f"\n> {msg}")

def create_session():
    step("Creating Dilithium session...")
    r = requests.post(f"{BASE_URL}/session/create", headers=HEADERS, json={
        "user_id":    USER_ID,
        "ip_address": IP_ADDRESS,
        "user_agent": USER_AGENT
    })
    data = r.json()
    if data.get("status") != "ok":
        print(f"FAILED: {data}")
        exit(1)
    return data["token"]

def fire_event(token, event, index):
    print_divider()
    print(f"EVENT {index + 1}/{len(EVENTS)}: {event['action']}")
    r = requests.post(f"{BASE_URL}/session/event", headers=HEADERS, json={
        "token":       token,
        "action":      event["action"],
        "endpoint":    event["endpoint"],
        "data_volume": event["data_volume"],
        "ip_address":  IP_ADDRESS,
        "user_agent":  USER_AGENT
    })
    data = r.json()
    print(f"Response: {json.dumps(data, indent=2)}")
    return data.get("status")

def run():
    print("=" * 60)
    print("  ANCHOR - Session Behavioural Monitoring Test")
    print("=" * 60)
    token = create_session()
    for i, event in enumerate(EVENTS):
        status = fire_event(token, event, i)
        if status == "threat":
            print("\n! SESSION TERMINATED")
            break

if __name__ == "__main__":
    run()
