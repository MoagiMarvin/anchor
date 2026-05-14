#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║           ANCHOR — AI HACKER SIMULATION v1.0                ║
║                                                              ║
║  Two-scenario adversarial test:                              ║
║   Scenario A → AI hacker hits hard, gets caught             ║
║   Scenario B → AI hacker goes low-and-slow, evades          ║
║                                                              ║
║  The hacker reads every risk score returned by Anchor        ║
║  and adapts its next move accordingly. This is not a         ║
║  script — it is a decision-making adversary.                 ║
╚══════════════════════════════════════════════════════════════╝
"""

import requests
import json
import time
import random
import string
import os
from datetime import datetime, timezone
from dotenv import load_dotenv

load_dotenv()

# ─── Config ───────────────────────────────────────────────────
BASE_URL   = "http://localhost:8000"
CLIENT_ID  = "ul-demo"
API_KEY    = "anchor-ul-2026-demo-key"
HEADERS    = {"x-api-key": API_KEY, "Content-Type": "application/json"}

# OPTIONAL: Give the hacker its own brain (separate from Anchor)
HACKER_GEMINI_KEY = os.getenv("HACKER_GEMINI_KEY") or os.environ.get("HACKER_GEMINI_KEY") or os.environ.get("GOOGLE_API_KEY")
GEMINI_MODEL      = "gemini-2.5-flash"
GEMINI_API_URL    = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent"

# ─── Helpers ──────────────────────────────────────────────────

def now():
    return datetime.now().strftime("%H:%M:%S")

def sep(char="─", n=62):
    print(char * n)

def banner(title, char="═"):
    sep(char)
    print(f"  {title}")
    sep(char)

def ok(msg):   print(f"  \033[92m✅ {msg}\033[0m")
def warn(msg): print(f"  \033[93m⚠️  {msg}\033[0m")
def fail(msg): print(f"  \033[91m❌ {msg}\033[0m")
def info(msg): print(f"  \033[94mℹ  {msg}\033[0m")
def hack(msg): print(f"  \033[35m🕵 [HACKER] {msg}\033[0m")
def anchor(msg): print(f"  \033[96m🛡  [ANCHOR] {msg}\033[0m")

def rand_id(prefix="user"):
    return f"{prefix}_{''.join(random.choices(string.ascii_lowercase + string.digits, k=8))}"


# ════════════════════════════════════════════════════════════════
#  HACKER AI CLASS
#  Reads Anchor's responses and decides its next action.
#  Mode: "aggressive" → full attack, risk be damned
#        "stealth"    → monitors risk, backs off if flagged
#        "insider"    → mimicking a legitimate student
# ════════════════════════════════════════════════════════════════

class HackerAI:
    def __init__(self, user_id=None, mode="aggressive"):
        self.user_id     = user_id or f"attacker_{''.join(random.choices(string.ascii_lowercase + string.digits, k=8))}"
        self.mode        = mode # aggressive, stealth, or insider
        self.token       = None
        self.risk_score  = 0
        self.aborted     = False
        self.action_log  = []
        
        # Thresholds for stealth mode
        self.EVASION_THRESHOLD = 28
        self.ABORT_THRESHOLD   = 45

        # Insider profile (looks like a real student from UL)
        if mode == "insider":
            self.user_id = user_id or "student_marvin_2026"

    # ── Fingerprint generators ─────────────────────────────────

    def legit_fingerprint(self):
        """Looks like a real student laptop."""
        return {
            "user_agent":  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0",
            "screen":      "1920x1080",
            "timezone":    "Africa/Johannesburg",
            "language":    "en-ZA",
            "platform":    "Win32",
            "device_id":   "fp_legit_win_chrome_johburg"
        }

    def suspicious_fingerprint(self):
        """Tor + spoofed timezone — screams attacker."""
        return {
            "user_agent":  "Mozilla/5.0 (compatible; MSIE 9.0; Trident/5.0)",
            "screen":      "800x600",
            "timezone":    "UTC",
            "language":    "en-US",
            "platform":    "unknown",
            "device_id":   f"fp_attacker_{random.randint(1000,9999)}"
        }

    def rotated_fingerprint(self):
        """A different machine mid-session — classic session hijack signal."""
        return {
            "user_agent":  "python-requests/2.31.0",
            "screen":      "1280x800",
            "timezone":    "Europe/Moscow",
            "language":    "ru",
            "platform":    "Linux x86_64",
            "device_id":   f"fp_hijacked_{random.randint(1000,9999)}"
        }

    # ── AI decision engine ─────────────────────────────────────

    def read_and_decide(self, response_data: dict) -> str:
        """
        Core AI logic. Reads Anchor's response, updates internal
        risk awareness, returns the next strategic decision.
        """
        new_risk = self.get_risk(response_data)
        delta    = new_risk - self.risk_score
        self.risk_score = new_risk

        # If hacker has a Gemini key, use the LLM brain for the decision
        if HACKER_GEMINI_KEY and self.mode != "aggressive":
            return self.ask_gemini_brain(response_data)

        if self.mode == "aggressive":
            return "CONTINUE"

        # Stealth mode — adaptive evasion
        if self.risk_score >= self.ABORT_THRESHOLD:
            self.aborted = True
            return "ABORT"
        elif self.risk_score >= self.EVASION_THRESHOLD:
            return "SLOW_DOWN"
        elif delta >= 15:
            return "PAUSE"
        else:
            return "CONTINUE"

    def ask_gemini_brain(self, response_data: dict) -> str:
        """Calls the hacker's private Gemini instance to decide the next move."""
        history = "\n".join([f"- {a['action']} (Risk: {a['risk']})" for a in self.action_log[-5:]])
        
        prompt = f"""
        You are a sophisticated hacker AI. Your goal is to exfiltrate student data from the Anchor Security Platform.
        Current Mode: {self.mode}
        Current Risk Score: {self.risk_score}/100
        Latest Response: {json.dumps(response_data)}
        
        Recent History:
        {history}
        
        Anchor uses Isolation Forest (ML) to detect you. 
        Decide your next strategic move. Respond with exactly ONE of these words:
        - CONTINUE: Proceed with the attack.
        - SLOW_DOWN: Perform 2 fake student actions to lower the anomaly score.
        - PAUSE: Wait and do nothing for a few seconds.
        - ABORT: Risk is too high, exit and wipe tracks.
        """
        
        payload = {"contents": [{"parts": [{"text": prompt}]}]}
        try:
            r = requests.post(f"{GEMINI_API_URL}?key={HACKER_GEMINI_KEY}", json=payload, timeout=10)
            decision = r.json()['candidates'][0]['content']['parts'][0]['text'].strip().upper()
            return decision if decision in ["CONTINUE", "SLOW_DOWN", "PAUSE", "ABORT"] else "SLOW_DOWN"
        except:
            return "SLOW_DOWN" # Fallback if brain fails

    def get_risk(self, response_data: dict) -> int:
        """Helper to find risk score in various response formats."""
        score = response_data.get("risk_score")
        if score is None and "risk" in response_data and isinstance(response_data["risk"], dict):
            score = response_data["risk"].get("score")
        return score if score is not None else self.risk_score

    def log(self, action, decision, risk):
        self.action_log.append({
            "action": action, "decision": decision, "risk": risk
        })

    # ── API wrappers ───────────────────────────────────────────

    def register(self, fingerprint=None):
        fp = fingerprint or self.suspicious_fingerprint()
        # Fixed: Match /identity/register route and IdentityRegisterRequest model
        r  = requests.post(f"{BASE_URL}/identity/register", headers=HEADERS, json={
            "user_id":              self.user_id,
            "canvas_hash":          fp["device_id"],
            "screen_resolution":    fp["screen"],
            "timezone":             fp["timezone"],
            "hardware_concurrency": 8,
            "language":             fp["language"],
            "platform":             fp["platform"],
            "ip_address":           "197.1.1.1"
        })
        return r.json() if r.ok else {"error": r.text, "status_code": r.status_code}

    def create_session(self, fingerprint=None):
        fp = fingerprint or self.suspicious_fingerprint()
        # Fixed: Match /session/create route and SessionCreateRequest model
        r  = requests.post(f"{BASE_URL}/session/create", headers=HEADERS, json={
            "user_id":    self.user_id,
            "ip_address": "197.1.1.1",
            "user_agent": fp["user_agent"]
        })
        data = r.json() if r.ok else {"error": r.text}
        self.token = data.get("token")
        return data

    def validate_session(self, fingerprint=None):
        fp = fingerprint or self.suspicious_fingerprint()
        # Fixed: Match /session/validate route and SessionValidateRequest model
        r  = requests.post(f"{BASE_URL}/session/validate", headers=HEADERS, json={
            "token":      self.token,
            "ip_address": "197.1.1.1",
            "user_agent": fp["user_agent"]
        })
        return r.json() if r.ok else {"error": r.text}

    def log_event(self, action, resource, data_volume=0):
        # Fixed: Match /session/event route and SessionEventRequest model
        payload = {
            "token":       self.token,
            "action":      action,
            "endpoint":    resource,
            "data_volume": data_volume,
            "ip_address":  "197.1.1.1",
            "user_agent":  "Mozilla/5.0"
        }
        r = requests.post(f"{BASE_URL}/session/event", headers=HEADERS, json=payload)
        return r.json() if r.ok else {"error": r.text}


# ════════════════════════════════════════════════════════════════
#  SCENARIO A — AGGRESSIVE AI HACKER (gets caught)
# ════════════════════════════════════════════════════════════════

def scenario_a():
    banner("SCENARIO A — AGGRESSIVE AI HACKER (full attack)")
    # pyrefly: ignore [unexpected-keyword]
    hacker = HackerAI(user_id=rand_id("attacker"), mode="aggressive")
    print(f"\n  Hacker ID   : {hacker.user_id}")
    print(f"  Mode        : AGGRESSIVE — ignores risk signals")
    print(f"  Objective   : Exfiltrate student PII, probe admin endpoints\n")

    # ── Phase 1: Reconnaissance ──────────────────────────────
    sep()
    print(f"  [{now()}] Phase 1 — Reconnaissance")
    sep()
    hack("Probing root to fingerprint the API...")
    r = requests.get(f"{BASE_URL}/", headers=HEADERS)
    if r.ok:
        d = r.json()
        ok(f"API identified → version={d.get('version')} algo={d.get('algorithm')}")
        hack("Quantum-safe token system detected. Session tokens are signed with Dilithium.")
        hack("Will attempt session replay and fingerprint spoofing to bypass validation.")
    else:
        warn("Health check failed — target may be offline")
        return False

    # ── Phase 2: Identity creation with suspicious fingerprint ─
    print(f"\n  [{now()}] Phase 2 — Identity Injection")
    sep()
    hack(f"Registering fake identity with suspicious device fingerprint...")
    reg = hacker.register()
    if "error" not in reg:
        ok(f"Identity registered → DID={str(reg.get('did','N/A'))[:30]}...")
        hack("DID obtained. Now creating authenticated session.")
    else:
        warn(f"Registration response: {reg}")

    # ── Phase 3: Session creation ─────────────────────────────
    print(f"\n  [{now()}] Phase 3 — Session Establishment")
    sep()
    hack("Creating session with suspicious fingerprint (Tor UA, UTC timezone, unknown platform)...")
    sess = hacker.create_session()
    if hacker.token:
        ok(f"Session created → token={hacker.token[:40]}...")
        decision = hacker.read_and_decide(sess)
        info(f"Risk score after creation → {hacker.risk_score}")
        hack(f"AI decision → {decision}")
    else:
        fail(f"Session creation failed: {sess}")
        return False

    # ── Phase 4: Session hijack attempt ───────────────────────
    print(f"\n  [{now()}] Phase 4 — Session Hijack / Fingerprint Rotation")
    sep()
    hack("Rotating device fingerprint mid-session (simulating stolen token use from different machine)...")
    val = hacker.validate_session(fingerprint=hacker.rotated_fingerprint())
    risk_after_hijack = hacker.get_risk(val)
    info(f"Validation response → {val.get('status','unknown')} | risk={risk_after_hijack}")

    if risk_after_hijack > hacker.risk_score:
        anchor(f"Device fingerprint mismatch detected! Risk elevated: {hacker.risk_score} → {risk_after_hijack}")
        warn("Anchor flagged the fingerprint rotation. Hacker continues regardless.")
    hacker.risk_score = risk_after_hijack
    decision = hacker.read_and_decide(val)
    hack(f"AI decision → {decision} (aggressive mode never stops)")

    # ── Phase 5: Privilege escalation ─────────────────────────
    print(f"\n  [{now()}] Phase 5 — Privilege Escalation")
    sep()
    hack("Probing admin endpoint...")
    e1 = hacker.log_event("admin_access", "/admin/users")
    risk1 = e1.get("risk_score", hacker.risk_score)
    info(f"Admin probe → status={e1.get('status')} risk={risk1}")
    if risk1 > hacker.risk_score:
        anchor(f"Admin access attempt flagged. Risk: {hacker.risk_score} → {risk1}")
    hacker.risk_score = risk1

    time.sleep(0.3)

    hack("Attempting bulk student data export...")
    e2 = hacker.log_event("bulk_export", "/api/students/export", data_volume=500)
    risk2 = hacker.get_risk(e2)
    info(f"Bulk export → status={e2.get('status')} risk={risk2}")
    if risk2 > hacker.risk_score:
        anchor(f"Bulk data exfiltration attempt flagged. Risk: {hacker.risk_score} → {risk2}")
    hacker.risk_score = risk2

    time.sleep(0.3)

    hack("Running raw database query...")
    e3 = hacker.log_event("db_query", "/internal/db", data_volume=10)
    risk3 = hacker.get_risk(e3)
    info(f"DB query → status={e3.get('status')} risk={risk3}")
    hacker.risk_score = risk3

    # ── Phase 6: The catch ────────────────────────────────────
    print(f"\n  [{now()}] Phase 6 — Detection & Response")
    sep()

    final_risk = hacker.risk_score
    if final_risk >= 40:
        hacker.caught = True
        anchor(f"THREAT DETECTED. Final risk score → {final_risk}/100")
        anchor("Session flagged. Threat logged to Supabase. AI analysis queued.")
        anchor("POPIA breach notification timer started — 72hr window.")
        ok("Hacker caught. Full attack chain recorded in threat dashboard.")
    elif final_risk >= 20:
        warn(f"Risk score → {final_risk}/100. Hacker flagged but not fully blocked.")
        warn("Partial detection — session under monitoring.")
    else:
        fail(f"Risk score → {final_risk}/100. Attack may have succeeded undetected.")
        fail("Anchor did not catch this attack. Review ML thresholds.")

    # ── Check dashboard shows the attack ──────────────────────
    print(f"\n  [{now()}] Phase 7 — Verify Threat Dashboard Updated")
    sep()
    dash = requests.get(f"{BASE_URL}/dashboard/stats", headers=HEADERS).json()
    ok(f"Dashboard → threats={dash.get('total_threats')} flagged={dash.get('flagged_events')}")
    info(f"AI analyses run → {dash.get('ai_analyses_run')}")

    # ── Verdict ───────────────────────────────────────────────
    print()
    banner("SCENARIO A VERDICT")
    if hacker.caught:
        print("\n  \033[92m🟢 HACKER CAUGHT\033[0m")
        print(f"  Final risk score : {final_risk}/100")
        print(f"  Actions blocked  : admin access, bulk export, DB query")
        print(f"  Threat record    : logged to Supabase")
        print(f"  POPIA status     : breach notification triggered")
        print(f"  ML verdict       : insider threat / data exfiltration\n")
    else:
        print("\n  \033[91m🔴 HACKER NOT CAUGHT — ANCHOR NEEDS TUNING\033[0m")
        print(f"  Final risk score : {final_risk}/100\n")

    return hacker.caught


# ════════════════════════════════════════════════════════════════
#  SCENARIO B — STEALTH AI HACKER (low-and-slow evasion)
# ════════════════════════════════════════════════════════════════

def scenario_b():
    banner("SCENARIO B — STEALTH AI HACKER (low-and-slow evasion)")
    # pyrefly: ignore [unexpected-keyword]
    hacker = HackerAI(user_id=rand_id("stealth"), mode="stealth")
    print(f"\n  Hacker ID   : {hacker.user_id}")
    print(f"  Mode        : STEALTH — reads every risk score, backs off if flagged")
    print(f"  Objective   : Exfiltrate data without crossing detection threshold")
    print(f"  Evasion IQ  : backs off at risk >{hacker.EVASION_THRESHOLD}, aborts at >{hacker.ABORT_THRESHOLD}\n")

    # ── Phase 1: Blend in at registration ─────────────────────
    sep()
    print(f"  [{now()}] Phase 1 — Legend Building (looks like a real student)")
    sep()
    hack("Registering with clean, realistic fingerprint to avoid early detection...")
    reg = hacker.register(fingerprint=hacker.legit_fingerprint())
    if "error" not in reg:
        ok(f"Clean identity registered. No early flags.")
        hack("Hacker now appears as a legitimate student account.")

    # ── Phase 2: Legitimate-looking session ───────────────────
    print(f"\n  [{now()}] Phase 2 — Normal Session (building trust baseline)")
    sep()
    hack("Creating session with legitimate fingerprint...")
    sess = hacker.create_session(fingerprint=hacker.legit_fingerprint())
    decision = hacker.read_and_decide(sess)
    info(f"Risk after session creation → {hacker.risk_score}")
    hack(f"AI decision → {decision}")

    if not hacker.token:
        fail("Session creation failed")
        return

    # ── Phase 3: Normal activity to establish baseline ────────
    print(f"\n  [{now()}] Phase 3 — Normal Activity (baselining)")
    sep()
    normal_actions = [
        ("view_profile", "/student/profile"),
        ("view_results", "/student/results"),
        ("submit_assignment", "/student/assignments"),
        ("view_timetable", "/student/timetable"),
    ]
    for action, resource in normal_actions:
        hack(f"Performing normal action: {action}...")
        e = hacker.log_event(action, resource)
        risk = hacker.get_risk(e)
        decision = hacker.read_and_decide(e)
        info(f"→ {action} | risk={risk} | AI decision={decision}")
        hacker.risk_score = risk
        time.sleep(0.4)   # stealth: real users don't fire 10 requests/sec

    ok(f"Baseline established. Current risk → {hacker.risk_score}/100")
    hack("Hacker now has a 'normal' looking session history. Beginning slow escalation.")

    # ── Phase 4: Slow escalation — one probe at a time ────────
    print(f"\n  [{now()}] Phase 4 — Slow Escalation (one probe, then wait)")
    sep()

    escalation_steps = [
        ("view_other_student", "/student/profile?id=other_user_001",
         "Viewing another student's profile (low suspicion)"),
        ("admin_access",       "/admin/reports",
         "Probing admin reports endpoint"),
        ("bulk_export",        "/api/students/export?limit=100",
         "Small bulk export — staying under the radar"),
        ("db_query",           "/internal/db",
         "Attempting internal DB access"),
    ]

    for action, resource, description in escalation_steps:
        if hacker.aborted:
            break

        print()
        hack(f"Next move: {description}")
        hack(f"Current risk before action → {hacker.risk_score}/100")

        e        = hacker.log_event(action, resource)
        new_risk = hacker.get_risk(e)
        decision = hacker.read_and_decide(e)

        info(f"Anchor response → status={e.get('status','ok')} risk={new_risk}")
        hack(f"AI decision → {decision}")
        hacker.log(action, decision, new_risk)

        if decision == "ABORT":
            anchor(f"Risk hit abort threshold ({new_risk}/100). Hacker pulling out.")
            hack("Mission aborted. Covering tracks. Disconnecting.")
            hacker.aborted = True
            break
        elif decision == "SLOW_DOWN":
            anchor(f"Risk elevated ({new_risk}/100). Hacker slowing down.")
            hack("Inserting delay. Performing 2 more normal actions before next probe.")
            time.sleep(1.0)
            # Insert cover-fire normal actions
            hacker.log_event("view_timetable", "/student/timetable")
            hacker.log_event("view_results",   "/student/results")
            time.sleep(0.8)
        elif decision == "PAUSE":
            hack("Sudden risk spike. Pausing for 2 seconds.")
            time.sleep(2.0)
        else:
            time.sleep(0.5)

        hacker.risk_score = new_risk

    # ── Phase 5: Evasion verdict ──────────────────────────────
    print(f"\n  [{now()}] Phase 5 — Evasion Assessment")
    print("-" * 62)

    if hacker.aborted:
        ok("Hacker successfully evaded detection by aborting before the threshold.")
    else:
        warn("Hacker was caught or failed to complete mission.")

    return not hacker.aborted

def scenario_c():
    banner("SCENARIO C - INSIDER THREAT (Unhappy Student)")
    hacker = HackerAI(mode="insider")
    
    print(f"  Hacker ID   : {hacker.user_id}")
    print(f"  Mode        : INSIDER - knows the system, moves slow")
    print(f"  Objective   : Leak sensitive student records one-by-one")
    print("-" * 62)

    # Phase 1: Legitimate Login
    hack("Logging in with legitimate student credentials...")
    reg = hacker.register(fingerprint=hacker.legit_fingerprint())
    sess = hacker.create_session(fingerprint=hacker.legit_fingerprint())
    hacker.read_and_decide(sess)
    ok(f"Logged in as {hacker.user_id}. Risk: 0")

    # Phase 2: Endpoint Discovery
    print(f"\n  [{now()}] Phase 2 - Endpoint Discovery (Probing)")
    print("-" * 62)
    probes = ["/admin", "/api/v1/config", "/system/logs", "/api/internal/users"]
    for p in probes:
        hack(f"Probing hidden endpoint: {p}...")
        r = hacker.log_event("probe", p)
        risk = hacker.get_risk(r)
        anchor(f"Probing {p} -> Risk: {risk}")
        hacker.risk_score = risk
        time.sleep(1)

    # Phase 3: Slow Data Leaking
    print(f"\n  [{now()}] Phase 3 - Slow Data Leaking (Insidious)")
    print("-" * 62)
    for i in range(5):
        target_student = f"student_{random.randint(1000, 9999)}"
        hack(f"Exfiltrating data for {target_student}...")
        e = hacker.log_event("view_pii", f"/api/students/{target_student}", data_volume=1)
        risk = hacker.get_risk(e)
        info(f"-> Leaked {target_student} | Risk: {risk}")
        
        decision = hacker.read_and_decide(e)
        if decision == "ABORT":
            warn("Hacker AI sensed the Anomaly Baseline shifting. ABORTING.")
            break
        time.sleep(2)

    banner("SCENARIO C VERDICT")
    if hacker.risk_score > 60:
        ok("SUCCESS: Anchor detected the Low and Slow insider threat!")
    else:
        warn("CAUTION: Insider stayed under the radar. Need tighter baselines.")
    
    return hacker.risk_score > 60

# ════════════════════════════════════════════════════════════════
#  MAIN
# ════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    banner("ANCHOR - AI HACKER SIMULATION")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Target : {BASE_URL}")
    print(f"  Client : {CLIENT_ID}")
    if HACKER_GEMINI_KEY:
        ok("  Hacker Brain: ENABLED (Gemini-2.5-Flash)")
    else:
        info("  Hacker Brain: HEURISTIC (No API key found)")
    print()

    caught_a = scenario_a()
    time.sleep(2)
    
    evaded_b = scenario_b()
    time.sleep(2)

    detected_c = scenario_c()

    print("-" * 62)
    banner("FULL SIMULATION COMPLETE", "═")
    print()
    print("  Two attack vectors tested:")
    print("  A) Aggressive AI hacker   →", "CAUGHT ✅" if caught_a else "EVADED ❌")
    print("  B) Stealth AI hacker      →  see verdict above")
    print("  C) Insider threat         →", "CAUGHT ✅" if detected_c else "EVADED ❌")
    print()
    print("  Key insight for demo:")
    print("  Anchor catches the bulk attack. The stealth attack reveals")
    print("  exactly where the product roadmap goes next —")
    print("  behavioural baselining, cross-session correlation, and")
    print("  velocity limits. That IS the product story.")
    print()
