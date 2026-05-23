#!/usr/bin/env python3
"""
Anchor — Standard Bank Attack Simulation
Tests the full session protection stack and verifies dashboard updates.
"""

import requests
import time
import json

BASE      = "http://localhost:8000"
API_KEY   = "anchor-standardbank-2026-demo-key"   # Standard Bank key
HEADERS   = {
    "X-API-Key":    API_KEY,
    "Content-Type": "application/json"
}

# ─────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────

def p(label, data, color=""):
    CYAN   = "\033[96m"
    GREEN  = "\033[92m"
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    colors = {"ok": GREEN, "threat": RED, "warn": YELLOW, "info": CYAN}
    c = colors.get(color, CYAN)
    print(f"\n{BOLD}{c}{'─'*55}{RESET}")
    print(f"{BOLD}{c}  {label}{RESET}")
    print(f"{c}{'─'*55}{RESET}")
    print(json.dumps(data, indent=2))

def post(path, body):
    try:
        r = requests.post(f"{BASE}{path}", json=body, headers=HEADERS, timeout=10)
        return r.json()
    except Exception as e:
        return {"error": str(e)}

def get(path):
    try:
        r = requests.get(f"{BASE}{path}", headers=HEADERS, timeout=10)
        return r.json()
    except Exception as e:
        return {"error": str(e)}

# ─────────────────────────────────────────
# TEST 1 — Normal customer session
# Expected: session created, token returned
# ─────────────────────────────────────────

print("\n\033[1m\033[96m" + "="*55)
print("  ANCHOR — STANDARD BANK ATTACK SIMULATION")
print("  SS26Hack 2026 — Identity & Session Protection")
print("="*55 + "\033[0m")

print("\n\033[1m[TEST 1] Normal customer session\033[0m")
r1 = post("/session/create", {
    "user_id":    "sb_customer_001",
    "ip_address": "196.25.1.10",
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120"
})
p("Session created", r1, "ok")
LEGIT_TOKEN = r1.get("token")

# ─────────────────────────────────────────
# TEST 2 — Normal activity on legit session
# Expected: ok, low risk
# ─────────────────────────────────────────

print("\n\033[1m[TEST 2] Normal customer activity\033[0m")
time.sleep(1)

for action in ["view_account", "view_transactions", "view_balance"]:
    r = post("/session/event", {
        "token":       LEGIT_TOKEN,
        "action":      action,
        "endpoint":    f"/banking/{action}",
        "data_volume": 1,
        "ip_address":  "196.25.1.10",
        "user_agent":  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120"
    })
    status = r.get("status", "?")
    risk   = r.get("risk_score", 0)
    color  = "ok" if status == "ok" else "threat"
    print(f"  {'✅' if status == 'ok' else '🚨'} {action:<25} status={status}  risk={risk}")

# ─────────────────────────────────────────
# TEST 3 — Session hijack simulation
# Attacker steals token, uses from different IP/UA
# Expected: risk spikes, flag fires
# ─────────────────────────────────────────

print("\n\033[1m[TEST 3] Session hijack — attacker steals token\033[0m")
time.sleep(1)

r3 = post("/session/event", {
    "token":       LEGIT_TOKEN,
    "action":      "view_account",
    "endpoint":    "/banking/view_account",
    "data_volume": 1,
    "ip_address":  "41.190.3.77",        # completely different IP
    "user_agent":  "curl/7.81.0 Linux"   # completely different UA
})
p("Hijack attempt", r3, "warn" if r3.get("risk_score", 0) < 80 else "threat")

# ─────────────────────────────────────────
# TEST 4 — Attacker session: bulk data exfil
# New session, then immediately tries to dump everything
# Expected: anomaly agent flags it, session killed
# ─────────────────────────────────────────

print("\n\033[1m[TEST 4] Attacker session — bulk data exfiltration\033[0m")
time.sleep(1)

r4 = post("/session/create", {
    "user_id":    "sb_attacker_099",
    "ip_address": "41.190.3.77",
    "user_agent": "python-requests/2.28"
})
ATTACK_TOKEN = r4.get("token")
p("Attacker session created", r4, "info")

time.sleep(1)

attack_actions = [
    ("bulk_download",   "/api/accounts/export",   50000),
    ("database_query",  "/api/internal/db",        99999),
    ("export_records",  "/api/customers/all",      75000),
    ("admin_access",    "/admin/config",            1000),
    ("delete_records",  "/api/accounts/delete",    10000),
]

for action, endpoint, volume in attack_actions:
    r = post("/session/event", {
        "token":       ATTACK_TOKEN,
        "action":      action,
        "endpoint":    endpoint,
        "data_volume": volume,
        "ip_address":  "41.190.3.77",
        "user_agent":  "python-requests/2.28"
    })
    status = r.get("status", "?")
    risk   = r.get("risk_score", 0)
    req    = r.get("action_required", "none")
    icon   = "🚨" if status == "threat" else "⚠️ " if status == "warning" else "✅"
    print(f"  {icon} {action:<20} status={status:<8} risk={risk:<4} action={req}")
    if status == "threat" or req == "kill":
        print(f"     └─ Session killed. Attack pattern: {r.get('attack_pattern', 'anomaly')}")
        ATTACK_TOKEN = None
        break
    time.sleep(0.5)

# ─────────────────────────────────────────
# TEST 5 — Rate limit (brute force)
# Rapid fire requests
# Expected: 429 after threshold
# ─────────────────────────────────────────

print("\n\033[1m[TEST 5] Rate limit — brute force simulation\033[0m")
time.sleep(1)

brute_token = post("/session/create", {
    "user_id":    "sb_brute_001",
    "ip_address": "41.190.3.77",
    "user_agent": "AttackBot/1.0"
}).get("token")

hit_limit = False
for i in range(1, 20):
    r = post("/session/event", {
        "token":      brute_token,
        "action":     "view_account",
        "endpoint":   "/banking/view_account",
        "ip_address": "41.190.3.77"
    }) if brute_token else {"status": "threat"}

    # Also hammer the API directly for rate limit
    raw = requests.post(
        f"{BASE}/session/create",
        json={"user_id": f"bot_{i}", "ip_address": "41.190.3.77", "user_agent": "bot"},
        headers=HEADERS
    )
    if raw.status_code == 429:
        print(f"  🛑 Rate limit hit on attempt {i} — 429 returned ✅")
        hit_limit = True
        break
    else:
        print(f"  attempt {i:<3} → {raw.status_code}")

if not hit_limit:
    print("  ⚠️  Rate limit not triggered — threshold may be too high")

# ─────────────────────────────────────────
# TEST 6 — Dashboard verification
# Pull stats and verify counts moved
# ─────────────────────────────────────────

print("\n\033[1m[TEST 6] Dashboard verification — did everything register?\033[0m")
time.sleep(1)

stats    = get("/dashboard/stats")
threats  = get("/threats")
sessions = get("/sessions")
honeypot = get("/honeypot/sessions")
analyses = get("/analyses")

p("Dashboard stats", stats, "info")

print(f"\n  Threats logged:      {threats.get('count', 0)}")
print(f"  Sessions total:      {sessions.get('count', 0)}")
print(f"  Honeypot sessions:   {honeypot.get('count', 0)}")
print(f"  AI analyses run:     {analyses.get('count', 0)}")

# ─────────────────────────────────────────
# SUMMARY
# ─────────────────────────────────────────

print("\n\033[1m\033[96m" + "="*55)
print("  TEST RUN COMPLETE")
print("="*55 + "\033[0m")
print("""
  Check your dashboard at http://localhost:8000/dashboard
  and verify:
    ✅ Threats feed shows the attack events
    ✅ Sessions shows the attacker + legit sessions
    ✅ AI verdicts show the bulk download pattern
    ✅ Stat cards updated

  If honeypot count is 0, the session/event
  spiderweb trap should have fired on /admin/config.
""")
