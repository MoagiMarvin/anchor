import os
import uuid
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
from fingerprint import build_fingerprint, fingerprints_match
from watcher import log_threat, log_event
from database import get_db
from scoring import calculate_risk_score

load_dotenv()

SESSION_EXPIRE_HOURS = 2

def create_session(user_id: str, ip_address: str, user_agent: str) -> str:
    db = get_db()
    token = str(uuid.uuid4())
    fingerprint = build_fingerprint(ip_address, user_agent)
    expires_at = (datetime.now(timezone.utc) + timedelta(hours=SESSION_EXPIRE_HOURS)).isoformat()

    db.table("anchor_sessions").insert({
        "token": token,
        "user_id": user_id,
        "fingerprint": fingerprint,
        "ip_address": ip_address,
        "user_agent": user_agent,
        "status": "active",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "expires_at": expires_at
    }).execute()

    log_event(token, "session_created")
    return token

def validate_session(token: str, ip_address: str, user_agent: str) -> dict:
    db = get_db()

    result = db.table("anchor_sessions")\
        .select("*")\
        .eq("token", token)\
        .eq("status", "active")\
        .execute()

    if not result.data:
        return {
            "status": "threat",
            "message": "Session not found or already terminated",
            "risk": {"score": 100, "level": "critical", "reasons": ["Session not found"]}
        }

    session = result.data[0]

    expires_at = datetime.fromisoformat(session["expires_at"])
    if datetime.now(timezone.utc) > expires_at:
        kill_session(token)
        return {
            "status": "threat",
            "message": "Session expired",
            "risk": {"score": 50, "level": "medium", "reasons": ["Session expired"]}
        }

    fp_match = fingerprints_match(session["fingerprint"], ip_address, user_agent)
    ip_changed = session.get("ip_address") != ip_address
    ua_changed = session.get("user_agent") != user_agent

    risk = calculate_risk_score(fp_match, ip_changed, ua_changed, 0)

    if not fp_match:
        kill_session(token)
        log_threat(token, "fingerprint_mismatch", ip_address)
        return {
            "status": "threat",
            "message": "Session hijack detected — session terminated",
            "risk": risk
        }

    log_event(token, "session_validated")
    return {
        "status": "ok",
        "message": "Session is legitimate",
        "risk": risk
    }

def kill_session(token: str) -> dict:
    db = get_db()
    db.table("anchor_sessions")\
        .update({"status": "killed"})\
        .eq("token", token)\
        .execute()

    log_event(token, "session_killed")
    return {"status": "ok", "message": "Session terminated"}