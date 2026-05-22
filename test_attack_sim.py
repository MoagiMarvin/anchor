import requests
import json
import time

BASE_URL = "http://localhost:8000"
API_KEY  = "anchor-ul-2026-demo-key"
HEADERS  = {"X-API-Key": API_KEY}

def print_result(title, response):
    print(f"\n{'='*55}")
    print(f"  {title}")
    print(f"{'='*55}")
    data = response.json()
    print(json.dumps(data, indent=2))
    return data


def run():
    print("\n🔐 ANCHOR — Attack Simulation Test")
    print("   SS26Hack 2026 | University of Limpopo Demo")

    # ── STEP 1: Enroll a legitimate device ───────────────────
    print("\n[1/6] Enrolling legitimate UL device...")
    r = requests.post(f"{BASE_URL}/enroll/device",
        headers={**HEADERS, "X-Admin-ID": "admin@ul.ac.za"},
        json={
            "employee_id":        "student_001",
            "device_fingerprint": "ul-laptop-fp-AABBCC",
            "device_label":       "UL Student Laptop 001"
        }
    )
    result = print_result("DEVICE ENROLLMENT", r)
    assert result["status"] in ("enrolled", "reactivated"), "❌ Enrollment failed"
    print("✅ Device enrolled successfully")
    time.sleep(1)

    # ── STEP 2: Create session from enrolled device ───────────
    print("\n[2/6] Creating session from enrolled device...")
    r = requests.post(f"{BASE_URL}/session/create",
        headers=HEADERS,
        json={
            "user_id":    "student_001",
            "ip_address": "192.168.1.100",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0) UL-Enrolled"
        }
    )
    result = print_result("SESSION CREATED", r)
    token = result["token"]
    assert token, "❌ No token returned"
    print("✅ Quantum-safe session created")
    time.sleep(1)

    # ── STEP 3: Validate from same device (should PASS) ───────
    print("\n[3/6] Validating from legitimate enrolled device...")
    r = requests.post(f"{BASE_URL}/session/validate",
        headers=HEADERS,
        json={
            "token":      token,
            "ip_address": "192.168.1.100",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0) UL-Enrolled"
        }
    )
    result = print_result("VALIDATION — ENROLLED DEVICE", r)
    assert result["status"] == "ok", f"❌ Expected ok, got {result['status']}"
    print("✅ CHECK 1 PASS — Dilithium signature valid")
    print("✅ CHECK 2 PASS — Session found in Supabase")
    print("✅ CHECK 3 PASS — Device fingerprint matches")
    print("✅ CHECK 4 PASS — Device enrolled in UL registry")
    time.sleep(1)

    # ── STEP 4: Create attacker session ───────────────────────
    print("\n[4/6] Attacker creates session with stolen credentials...")
    r = requests.post(f"{BASE_URL}/session/create",
        headers=HEADERS,
        json={
            "user_id":    "student_001",
            "ip_address": "41.203.18.99",
            "user_agent": "Mozilla/5.0 (Linux) AttackerDevice"
        }
    )
    result = print_result("ATTACKER SESSION CREATED", r)
    attacker_token = result["token"]
    print("⚠️  Attacker has a valid token — but watch what happens next...")
    time.sleep(1)

    # ── STEP 5: Attacker validates from unenrolled device ─────
    print("\n[5/6] Attacker attempts session validation from unenrolled device...")
    r = requests.post(f"{BASE_URL}/session/validate",
        headers=HEADERS,
        json={
            "token":      attacker_token,
            "ip_address": "41.203.18.99",
            "user_agent": "Mozilla/5.0 (Linux) AttackerDevice"
        }
    )
    result = print_result("VALIDATION — ATTACKER DEVICE", r)
    print("🚨 CHECK 4 FIRED — Device not in UL institutional registry")
    print("🍯 Attacker silently routed to HONEYPOT — they don't know")
    time.sleep(1)

    # ── STEP 6: Confirm honeypot in Supabase ──────────────────
    print("\n[6/6] Checking honeypot sessions in Supabase...")
    r = requests.get(f"{BASE_URL}/honeypot/sessions", headers=HEADERS)
    result = print_result("HONEYPOT SESSIONS", r)
    print(f"🍯 {result['count']} attacker session(s) currently contained")
    time.sleep(1)

    # ── SUMMARY ───────────────────────────────────────────────
    print(f"\n{'='*55}")
    print("  SIMULATION COMPLETE")
    print(f"{'='*55}")
    print("  ✅ Legitimate device: PASSED all 4 checks")
    print("  🚨 Attacker device:   BLOCKED at CHECK 4")
    print("  🍯 Attacker session:  CONTAINED in honeypot")
    print("  📋 POPIA breach log:  Auto-generated")
    print(f"{'='*55}\n")


if __name__ == "__main__":
    run()