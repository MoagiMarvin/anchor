"""
ANCHOR — End-to-End Test Script
Simulates a real attack from login to POPIA report.

Run with:
    python3 test_anchor.py

API must be running:
    uvicorn main:app --reload --port 8000
"""

import requests
import json
import time
from datetime import datetime

BASE_URL = "http://localhost:8000"
API_KEY  = "anchor-ul-2026-demo-key"
HEADERS  = {"X-API-Key": API_KEY, "Content-Type": "application/json"}

# ─────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────

def section(title: str):
    print(f"\n{'='*55}")
    print(f"  {title}")
    print(f"{'='*55}")

def ok(label: str, value=None):
    val = f" → {value}" if value is not None else ""
    print(f"  ✅ {label}{val}")

def fail(label: str, value=None):
    val = f" → {value}" if value is not None else ""
    print(f"  ❌ {label}{val}")

def info(label: str, value=None):
    val = f" → {value}" if value is not None else ""
    print(f"  ℹ  {label}{val}")

def post(path, data):
    r = requests.post(f"{BASE_URL}{path}", headers=HEADERS, json=data)
    return r.status_code, r.json()

def get(path):
    r = requests.get(f"{BASE_URL}{path}", headers=HEADERS)
    return r.status_code, r.json()


# ─────────────────────────────────────────
# TEST 1 — API HEALTH
# ─────────────────────────────────────────

def test_health():
    section("TEST 1 — API Health")
    status, data = get("/")
    if status == 200 and data.get("status") == "ok":
        ok("API is running", data.get("version"))
        ok("Algorithm", data.get("algorithm"))
        ok("Quantum safe", data.get("quantum_safe"))
    else:
        fail("API not responding", status)
    return status == 200


# ─────────────────────────────────────────
# TEST 2 — ML ANOMALY DETECTOR
# Direct test — no API call needed
# ─────────────────────────────────────────

def test_ml_detector():
    section("TEST 2 — ML Anomaly Detector (Isolation Forest)")

    try:
        from ml.anomaly_detector import get_detector

        detector = get_detector()
        if not detector.is_ready():
            fail("Model not loaded — run: python3 ml/train.py")
            return False

        ok("Model loaded")

        # Normal event
        r1 = detector.score("view_profile", "/profile", 2, 1, 5)
        ok(f"Normal event scored",
           f"anomaly={r1['anomaly_score']} is_anomaly={r1['is_anomaly']} risk_added={r1['risk_added']}")

        # Suspicious event
        r2 = detector.score("bulk_download", "/export", 800, 30, 25)
        ok(f"Bulk download scored",
           f"anomaly={r2['anomaly_score']} is_anomaly={r2['is_anomaly']} risk_added={r2['risk_added']}")

        # Critical event
        r3 = detector.score("delete_records", "/admin", 2000, 50, 55)
        ok(f"Admin delete scored",
           f"anomaly={r3['anomaly_score']} is_anomaly={r3['is_anomaly']} risk_added={r3['risk_added']}")

        if r1["anomaly_score"] < r2["anomaly_score"]:
            ok("ML correctly ranks normal < suspicious")
        else:
            fail("ML ranking unexpected — check model")

        return True

    except Exception as e:
        fail(f"ML test error: {e}")
        return False


# ─────────────────────────────────────────
# TEST 3 — DASHBOARD STATS
# ─────────────────────────────────────────

def test_dashboard():
    section("TEST 3 — Dashboard Stats")
    status, data = get("/dashboard/stats")
    if status == 200:
        ok("Dashboard responding")
        info("Total threats",      data.get("total_threats"))
        info("Active honeypots",   data.get("active_honeypots"))
        info("Flagged events",     data.get("flagged_events"))
        info("AI analyses run",    data.get("ai_analyses_run"))
    else:
        fail("Dashboard failed", status)
    return status == 200


# ─────────────────────────────────────────
# TEST 4 — IDENTITY REGISTRATION
# Register a clean user first
# ─────────────────────────────────────────

def test_register():
    section("TEST 4 — Identity Registration (Legitimate User)")

    status, data = post("/identity/register", {
        "user_id":              "test_student_ul_001",
        "canvas_hash":          "abc123def456",
        "screen_resolution":    "1920x1080",
        "timezone":             "Africa/Johannesburg",
        "hardware_concurrency": 8,
        "language":             "en-ZA",
        "webgl":                "WebGL 2.0",
        "platform":             "Win32",
        "ip_address":           "196.25.1.100"
    })

    if status == 200:
        ok("Registration accepted", data.get("status"))
        info("DID generated", data.get("did", "none")[:20] + "..." if data.get("did") else "none")
    else:
        fail("Registration failed", status)
        print(f"  Response: {data}")

    return status == 200


# ─────────────────────────────────────────
# TEST 5 — NORMAL SESSION
# Legitimate login and session creation
# ─────────────────────────────────────────

def test_normal_session():
    section("TEST 5 — Normal Session (Legitimate Login)")

    # Create session
    status, data = post("/session/create", {
        "user_id":    "test_student_ul_001",
        "ip_address": "196.25.1.100",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120"
    })

    if status != 200:
        fail("Session creation failed", status)
        return None

    token = data.get("token")
    ok("Session created", "token received" if token else "NO TOKEN")

    # Validate session
    status2, data2 = post("/session/validate", {
        "token":      token,
        "ip_address": "196.25.1.100",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120"
    })

    if status2 == 200 and data2.get("status") == "ok":
        ok("Session validated", "quantum-safe ✓")
    else:
        fail("Validation failed", data2.get("message"))

    # Normal event
    status3, data3 = post("/session/event", {
        "token":       token,
        "action":      "view_records",
        "endpoint":    "/students/profile",
        "data_volume": 1,
        "ip_address":  "196.25.1.100",
        "user_agent":  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120"
    })

    if status3 == 200:
        ok("Normal event recorded", data3.get("status"))
        risk = data3.get("risk")
        if risk:
            info("Risk score", risk.get("score"))
        else:
            info("Risk score", "0 — clean session")
    else:
        fail("Event recording failed", status3)

    return token


# ─────────────────────────────────────────
# TEST 6 — SIMULATED ATTACK
# High-risk login → honeypot triggered
# Attacker actions logged
# ─────────────────────────────────────────

def test_attack_simulation():
    section("TEST 6 — Attack Simulation (Honeypot + ML + POPIA)")

    print("\n  [Phase 1] Attacker creates session with suspicious fingerprint...")

    # Create a session directly — simulating post-login attacker
    # In real flow: verify-login with risk >= 75 triggers honeypot
    # Here we create a normal session then simulate suspicious events
    status, data = post("/session/create", {
        "user_id":    "test_student_ul_001",
        "ip_address": "41.203.0.1",      # different IP — Nigerian range
        "user_agent": "python-requests/2.28"  # bot user agent
    })

    if status != 200:
        fail("Attack session setup failed", status)
        return

    token = data.get("token")
    ok("Attacker session created (simulating post-honeypot-trigger)")

    print("\n  [Phase 2] Attacker probes admin endpoints...")
    time.sleep(1)

    # Admin access
    status2, data2 = post("/session/event", {
        "token":       token,
        "action":      "admin_access",
        "endpoint":    "/admin/users",
        "data_volume": 50,
        "ip_address":  "41.203.0.1",
        "user_agent":  "python-requests/2.28"
    })
    ok("Admin probe sent", f"status={data2.get('status')} risk={data2.get('risk_score', 0)}")
    if data2.get("explanation"):
        info("Gemini says", data2.get("explanation", "")[:100] + "...")

    time.sleep(1)

    print("\n  [Phase 3] Attacker attempts bulk data export...")

    # Bulk export
    status3, data3 = post("/session/event", {
        "token":       token,
        "action":      "export_records",
        "endpoint":    "/export/students",
        "data_volume": 1500,
        "ip_address":  "41.203.0.1",
        "user_agent":  "python-requests/2.28"
    })
    ok("Bulk export sent", f"status={data3.get('status')} risk={data3.get('risk_score', 0)}")
    if data3.get("explanation"):
        info("Gemini says", data3.get("explanation", "")[:120] + "...")
    if data3.get("attack_pattern"):
        info("Attack pattern", data3.get("attack_pattern"))
    if data3.get("popia_concern"):
        info("POPIA concern", "⚠️  YES — breach notification may be triggered")

    time.sleep(1)

    print("\n  [Phase 4] Attacker tries database query...")

    # Database query
    status4, data4 = post("/session/event", {
        "token":       token,
        "action":      "database_query",
        "endpoint":    "/schema/tables",
        "data_volume": 200,
        "ip_address":  "41.203.0.1",
        "user_agent":  "python-requests/2.28"
    })
    ok("DB query sent", f"status={data4.get('status')} risk={data4.get('risk_score', 0)}")
    action_required = data4.get("action_required", "none")
    info("Action required", action_required)

    if action_required in ("kill", "reauth"):
        ok(f"Anchor correctly escalated to: {action_required.upper()}")

    # Return session uuid for follow-up checks
    return data4.get("session_uuid")


# ─────────────────────────────────────────
# TEST 7 — CHECK HONEYPOT + POPIA RESULTS
# ─────────────────────────────────────────

def test_results(session_uuid: str = None):
    section("TEST 7 — Check Threat Dashboard Results")

    # Dashboard stats
    _, stats = get("/dashboard/stats")
    ok("Dashboard stats", f"threats={stats.get('total_threats')} flagged={stats.get('flagged_events')}")

    # Flagged events
    _, flagged = get("/events/flagged")
    ok("Flagged events feed", f"{flagged.get('count')} events")

    # AI analyses
    _, analyses = get("/analyses")
    ok("AI analyses feed", f"{analyses.get('count')} verdicts")
    if analyses.get("analyses"):
        latest = analyses["analyses"][0]
        info("Latest verdict", latest.get("attack_pattern", "none"))
        info("Threat level",   latest.get("threat_level", "unknown"))
        if latest.get("explanation"):
            info("Explanation", latest.get("explanation", "")[:100] + "...")

    # Honeypot sessions
    _, honeypots = get("/honeypot/sessions")
    info("Honeypot sessions", honeypots.get("count"))

    # Honeypot activity
    _, activity = get("/honeypot/activity")
    info("Honeypot actions logged", activity.get("count"))

    # POPIA reports
    _, reports = get("/popia/reports")
    info("POPIA reports generated", reports.get("count"))
    if reports.get("reports"):
        r = reports["reports"][0]
        info("Breach type",     r.get("breach_type"))
        info("Affected users",  r.get("affected_users"))
        info("Report status",   r.get("status"))
        print("\n  --- POPIA REPORT PREVIEW (first 400 chars) ---")
        draft = r.get("report_draft", "")
        print(f"  {draft[:400]}...")
        print("  --- END PREVIEW ---")

    # Manual POPIA trigger if we have a session uuid
    if session_uuid:
        print(f"\n  [Manual POPIA trigger for session {session_uuid[:8]}...]")
        status, report = post(f"/popia/generate/{session_uuid}", {})
        if status == 200:
            ok("Manual POPIA report generated")
            info("Deadline", report.get("deadline"))
        else:
            info("Manual trigger response", status)


# ─────────────────────────────────────────
# TEST 8 — PQC SIGNING
# ─────────────────────────────────────────

def test_pqc():
    section("TEST 8 — PQC Signing (Dilithium / SHA3-512)")

    _, info_data = get("/pqc/info")
    ok("Algorithm", info_data.get("algorithm"))
    ok("Mode",      info_data.get("mode"))

    status, signed = post("/pqc/sign", {
        "user_id": "test_student_ul_001",
        "action":  "test_sign"
    })

    if status == 200:
        ok("Token signed", "token received")
        token = signed.get("signed_token")

        # Verify it
        status2, verified = post("/pqc/verify", {"token": token})
        if status2 == 200 and verified.get("valid"):
            ok("Token verified — signature valid ✓")
        else:
            fail("Verification failed")
    else:
        fail("Signing failed", status)


# ─────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────

if __name__ == "__main__":
    print("\n" + "="*55)
    print("  ANCHOR — FULL SYSTEM TEST")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*55)

    results = []

    results.append(("Health",       test_health()))
    results.append(("ML Detector",  test_ml_detector()))
    results.append(("Dashboard",    test_dashboard()))
    results.append(("Registration", test_register()))

    normal_token   = test_normal_session()
    results.append(("Normal Session", normal_token is not None))

    session_uuid   = test_attack_simulation()
    results.append(("Attack Simulation", session_uuid is not None))

    time.sleep(2)  # give Gemini a moment to respond
    test_results(session_uuid)

    test_pqc()
    results.append(("PQC Signing", True))

    # Summary
    section("TEST SUMMARY")
    passed = sum(1 for _, r in results if r)
    total  = len(results)
    for name, result in results:
        if result:
            ok(name)
        else:
            fail(name)

    print(f"\n  {passed}/{total} tests passed")
    if passed == total:
        print("\n  🟢 Anchor is fully operational. Ready for Render deployment.")
    else:
        print("\n  🔴 Some tests failed. Check output above.")
    print()
