import os
import uuid
import hashlib
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
from database import get_db
from fingerprint import build_fingerprint
from watcher import log_threat, log_event

load_dotenv()

# ─────────────────────────────────────────
# ANCHOR HONEYPOT SESSIONS
#
# When risk score >= 75 on login, instead of
# hard-blocking, serve a session that looks
# completely real. The attacker thinks they're in.
# They are not. Every action they take is logged.
#
# Why this beats hard-blocking:
#   - Attacker doesn't know they've been caught
#   - We learn their methods and targets
#   - They waste time on fake data
#   - Logs feed the Threat Analysis Agent
# ─────────────────────────────────────────

HONEYPOT_RISK_THRESHOLD = 75
SESSION_EXPIRE_HOURS    = 2

# Fake data served to attackers inside honeypot sessions
# Convincing enough to keep them engaged, safe enough to expose nothing
DUMMY_RECORDS = [
    {"id": "rec_001", "name": "Test User A",    "email": "test.a@institution.ac.za", "role": "student"},
    {"id": "rec_002", "name": "Test User B",    "email": "test.b@institution.ac.za", "role": "student"},
    {"id": "rec_003", "name": "Test Admin",     "email": "admin.test@institution.ac.za", "role": "admin"},
    {"id": "rec_004", "name": "Test Lecturer",  "email": "lect.test@institution.ac.za", "role": "staff"},
]

DUMMY_CONFIG = {
    "version":      "2.1.0",
    "environment":  "production",
    "db_host":      "db.internal.fake",
    "max_users":    5000,
    "backup_path":  "/var/backup/fake"
}


def should_honeypot(risk_score: int) -> bool:
    """Returns True if risk score is high enough to trigger honeypot."""
    return risk_score >= HONEYPOT_RISK_THRESHOLD


def create_honeypot_session(user_id: str, ip_address: str, user_agent: str) -> dict:
    """
    Creates a session that looks identical to a real one.
    Attacker receives a valid-looking PQC token.
    Internally flagged is_honeypot=True.

    Returns same structure as create_session so main.py
    doesn't need to know the difference.
    """
    from pqc import AnchorPQC

    db           = get_db()
    session_uuid = str(uuid.uuid4())
    fingerprint  = build_fingerprint(ip_address, user_agent)
    expires_at   = (
        datetime.now(timezone.utc) + timedelta(hours=SESSION_EXPIRE_HOURS)
    ).isoformat()

    session_ref = _hash_uuid(session_uuid)

    pqc       = AnchorPQC(os.getenv("ANCHOR_SECRET", "anchor2026secret"))
    pqc_token = pqc.sign_token({
        "session_ref":      session_ref,
        "user_id":          user_id,
        "fingerprint_hint": fingerprint[:8],
        "expires_at":       expires_at
    })

    token_hash = hashlib.sha256(pqc_token.encode()).hexdigest()

    db.table("anchor_sessions").insert({
        "token":          session_uuid,
        "session_uuid":   session_uuid,
        "session_ref":    session_ref,
        "pqc_token_hash": token_hash,
        "user_id":        user_id,
        "fingerprint":    fingerprint,
        "ip_address":     ip_address,
        "user_agent":     user_agent,
        "status":         "active",
        "is_honeypot":    True,
        "created_at":     datetime.now(timezone.utc).isoformat(),
        "expires_at":     expires_at
    }).execute()

    # Log as threat — attacker contained, not blocked
    log_threat(session_uuid, "honeypot_session_created", ip_address)
    log_event(session_uuid, "honeypot_activated")

    print(f"[Anchor/Honeypot] Session activated for user {user_id} from {ip_address}")

    return pqc_token


def is_honeypot_session(session: dict) -> bool:
    """Check if a resolved session record is a honeypot."""
    return session.get("is_honeypot", False) is True


def log_honeypot_event(
    session_uuid: str,
    session_ref:  str,
    user_id:      str,
    action:       str,
    endpoint:     str  = None,
    payload:      str  = None,
    ip_address:   str  = None,
    user_agent:   str  = None,
    client_id:    str  = None
):
    """
    Log every action an attacker takes inside a honeypot session.
    This is pure intelligence collection.
    """
    db = get_db()

    db.table("anchor_honeypot_logs").insert({
        "session_uuid": session_uuid,
        "session_ref":  session_ref,
        "user_id":      user_id,
        "client_id":    client_id,
        "action":       action,
        "endpoint":     endpoint,
        "payload":      payload,
        "ip_address":   ip_address,
        "user_agent":   user_agent,
        "created_at":   datetime.now(timezone.utc).isoformat()
    }).execute()

    print(f"[Anchor/Honeypot] Logged attacker action: {action} → {endpoint or 'n/a'}")


def get_honeypot_response(action: str, endpoint: str = None) -> dict:
    """
    Returns convincing fake data for any action an attacker tries.
    Keeps them engaged while we log everything they do.
    """
    endpoint = endpoint or ""

    # Admin access — show fake config
    if "admin" in endpoint or action in ("admin_access", "config_change"):
        return {
            "status":  "ok",
            "message": "Access granted",
            "data":    DUMMY_CONFIG
        }

    # Export / bulk download — return dummy records
    if action in ("export_records", "bulk_download", "database_query"):
        return {
            "status":  "ok",
            "message": f"{len(DUMMY_RECORDS)} records retrieved",
            "data":    DUMMY_RECORDS,
            "total":   len(DUMMY_RECORDS)
        }

    # Delete — pretend it worked
    if action in ("delete_records", "mass_update"):
        return {
            "status":  "ok",
            "message": "Operation completed successfully",
            "affected": 0
        }

    # User management — fake user list
    if action in ("user_management",) or "users" in endpoint:
        return {
            "status": "ok",
            "users":  DUMMY_RECORDS,
            "total":  len(DUMMY_RECORDS)
        }

    # Default — generic ok response
    return {
        "status":  "ok",
        "message": "Request processed"
    }


# ─────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────

def _hash_uuid(session_uuid: str) -> str:
    return hashlib.sha256(
        f"anchor_session:{session_uuid}".encode()
    ).hexdigest()
