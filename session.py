import os
import uuid
import hashlib
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
from fingerprint import build_fingerprint, fingerprints_match
from watcher import log_threat, log_event
from database import get_db
from scoring import calculate_risk_score

load_dotenv()

SESSION_EXPIRE_HOURS = 2

def create_session(user_id: str, ip_address: str, user_agent: str) -> str:
    from pqc import AnchorPQC
    db = get_db()
    session_uuid = str(uuid.uuid4())
    fingerprint = build_fingerprint(ip_address, user_agent)
    expires_at = (datetime.now(timezone.utc) + timedelta(hours=SESSION_EXPIRE_HOURS)).isoformat()

    pqc = AnchorPQC(os.getenv("ANCHOR_SECRET", "anchor2026secret"))
    pqc_token = pqc.sign_token({
        "session_uuid": session_uuid,
        "user_id": user_id,
        "fingerprint": fingerprint[:16],
        "expires_at": expires_at
    })

    token_hash = hashlib.sha256(pqc_token.encode()).hexdigest()

    db.table("anchor_sessions").insert({
        "token": session_uuid,
        "session_uuid": session_uuid,
        "pqc_token_hash": token_hash,
        "user_id": user_id,
        "fingerprint": fingerprint,
        "ip_address": ip_address,
        "user_agent": user_agent,
        "status": "active",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "expires_at": expires_at
    }).execute()

    log_event(session_uuid, "session_created_pqc")
    return pqc_token

def validate_session(token: str, ip_address: str, user_agent: str) -> dict:
    from pqc import AnchorPQC
    db = get_db()
    pqc = AnchorPQC(os.getenv("ANCHOR_SECRET", "anchor2026secret"))

    verification = pqc.verify_token(token)
    if not verification.get("valid"):
        return {
            "status": "threat",
            "message": "Invalid token signature — token forged or tampered",
            "risk": {"score": 100, "level": "critical", "reasons": ["PQC signature invalid"]}
        }

    payload = verification["payload"]
    session_uuid = payload.get("session_uuid")

    result = db.table("anchor_sessions")\
        .select("*")\
        .eq("session_uuid", session_uuid)\
        .eq("status", "active")\
        .execute()

    if not result.data:
        return {
            "status": "threat",
            "message": "Session not found or already terminated",
            "risk": {"score": 100, "level": "critical", "reasons": ["Session not in database"]}
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
        log_threat(session_uuid, "fingerprint_mismatch_pqc", ip_address)
        return {
            "status": "threat",
            "message": "Session hijack detected — session terminated",
            "risk": risk
        }

    log_event(session_uuid, "session_validated_pqc")
    return {
        "status": "ok",
        "message": "Session verified — quantum safe",
        "risk": risk
    }

def kill_session(token: str) -> dict:
    from pqc import AnchorPQC
    db = get_db()

    try:
        pqc = AnchorPQC(os.getenv("ANCHOR_SECRET", "anchor2026secret"))
        verification = pqc.verify_token(token)
        if verification.get("valid"):
            session_uuid = verification["payload"].get("session_uuid")
            db.table("anchor_sessions")\
                .update({"status": "killed"})\
                .eq("session_uuid", session_uuid)\
                .execute()
            log_event(session_uuid, "session_killed")
            return {"status": "ok", "message": "Session terminated"}
    except Exception:
        pass

    db.table("anchor_sessions")\
        .update({"status": "killed"})\
        .eq("token", token)\
        .execute()
    return {"status": "ok", "message": "Session terminated"}