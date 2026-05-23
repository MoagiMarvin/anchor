import os
import uuid
import hashlib
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
from database import get_db
from fingerprint import build_fingerprint
from watcher import log_threat, log_event

load_dotenv()

HONEYPOT_RISK_THRESHOLD = 75
SESSION_EXPIRE_HOURS    = 2

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
    return risk_score >= HONEYPOT_RISK_THRESHOLD


def create_honeypot_session(
    user_id:    str,
    ip_address: str,
    user_agent: str,
    client_id:  str = None   # FIX: accept client_id so rows are tenant-tagged
) -> dict:
    """
    Creates a session that looks identical to a real one.
    Attacker receives a valid-looking PQC token.
    Internally flagged is_honeypot=True.
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
        "client_id":      client_id,   # FIX: store so dashboard filters work
        "created_at":     datetime.now(timezone.utc).isoformat(),
        "expires_at":     expires_at
    }).execute()

    log_threat(session_uuid, "honeypot_session_created", ip_address)
    log_event(session_uuid, "honeypot_activated")

    print(f"[Anchor/Honeypot] Session activated for user {user_id} from {ip_address}")

    return pqc_token


def is_honeypot_session(session: dict) -> bool:
    return session.get("is_honeypot", False) is True


def log_honeypot_event(
    session_uuid: str,
    session_ref:  str,
    user_id:      str,
    action:       str,
    endpoint:     str = None,
    payload:      str = None,
    ip_address:   str = None,
    user_agent:   str = None,
    client_id:    str = None
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

    if "admin" in endpoint or action in ("admin_access", "config_change"):
        return {
            "status":  "ok",
            "message": "Access granted",
            "data":    DUMMY_CONFIG
        }

    if action in ("export_records", "bulk_download", "database_query"):
        return {
            "status":  "ok",
            "message": f"{len(DUMMY_RECORDS)} records retrieved",
            "data":    DUMMY_RECORDS,
            "total":   len(DUMMY_RECORDS)
        }

    if action in ("delete_records", "mass_update"):
        return {
            "status":   "ok",
            "message":  "Operation completed successfully",
            "affected": 0
        }

    if action in ("user_management",) or "users" in endpoint:
        return {
            "status": "ok",
            "users":  DUMMY_RECORDS,
            "total":  len(DUMMY_RECORDS)
        }

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