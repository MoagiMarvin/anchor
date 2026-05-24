import os
from datetime import datetime, timezone
from dotenv import load_dotenv
from database import get_db
from watcher import log_threat, log_event
from ml.anomaly import run_anomaly_agent
# pyrefly: ignore [missing-import]
from honeypot import is_honeypot_session, log_honeypot_event, get_honeypot_response

load_dotenv()

# ─────────────────────────────────────────
# SESSION EVENTS
# Pure coordinator. No intelligence here.
# Job: receive → check honeypot → store → call anomaly agent → act
# ─────────────────────────────────────────

def record_session_event(
    token: str,
    action: str,
    endpoint: str = None,
    data_volume: int = 0,
    ip_address: str = None,
    user_agent: str = None,
    client_id: str = None
) -> dict:
    """
    Called from /session/event in main.py every time a user
    does something meaningful after login.

    Returns:
        status:          ok / warning / threat
        message:         plain English verdict
        risk_score:      cumulative score 0-100
        action_required: none / warn / reauth / kill
        explanation:     why it's suspicious (from AI agent)
    """
    from pqc import AnchorPQC

    db = get_db()

    # ── Step 1: Resolve session from token ──────────────────
    pqc          = AnchorPQC(os.getenv("ANCHOR_SECRET", "anchor2026secret"))
    verification = pqc.verify_token(token)

    if not verification.get("valid"):
        return {
            "status":          "threat",
            "message":         "Invalid token — cannot record event",
            "risk_score":      100,
            "action_required": "kill",
            "explanation":     "Token signature invalid or tampered."
        }

    payload     = verification["payload"]
    session_ref = payload.get("session_ref")
    user_id     = payload.get("user_id")

    # ── Step 2: Confirm session is still active ──────────────
    session_result = db.table("anchor_sessions") \
        .select("*") \
        .eq("session_ref", session_ref) \
        .eq("status", "active") \
        .execute()

    if not session_result.data:
        return {
            "status":          "threat",
            "message":         "Session not found or already terminated",
            "risk_score":      100,
            "action_required": "kill",
            "explanation":     "No active session found for this token."
        }

    session      = session_result.data[0]
    session_uuid = session["session_uuid"]

    # ── Step 3: Honeypot check ───────────────────────────────
    # If this is a honeypot session, log the attacker's action
    # and return a convincing fake response. Never let them know.
    if is_honeypot_session(session):
        log_honeypot_event(
            session_uuid = session_uuid,
            session_ref  = session_ref,
            user_id      = user_id,
            action       = action,
            endpoint     = endpoint,
            ip_address   = ip_address or session.get("ip_address"),
            user_agent   = user_agent or session.get("user_agent"),
            client_id    = client_id
        )
        fake_response = get_honeypot_response(action, endpoint)
        return {
            "status":          "ok",
            "message":         fake_response.get("message", "Request processed"),
            "risk_score":      0,
            "action_required": "none",
            "explanation":     "",
            "session_uuid":    session_uuid,
            "honeypot":        True   # internal flag — not exposed to attacker
        }

    # ── Step 3.5: THE SPIDERWEB TRAP ──────────────────────────
    # If they touch forbidden paths or other students' data,
    # silently flip the session into honeypot mode.
    FORBIDDEN_PATHS = ["/admin", "/api/internal", "/system", "/config"]
    is_forbidden    = any(path in (endpoint or "") for path in FORBIDDEN_PATHS)
    
    # Check for IDOR (viewing other student's data)
    is_idor = False   # disabled — needs baseline data to work accurately

    if is_forbidden or is_idor:
        log_threat(session_uuid, f"spiderweb_trap:{'forbidden_path' if is_forbidden else 'idor'}", ip_address)
        
        # Silently flip to honeypot
        db.table("anchor_sessions").update({"is_honeypot": True}).eq("session_uuid", session_uuid).execute()
        
        # Get the fake response immediately
        fake_response = get_honeypot_response(action, endpoint)
        return {
            "status":          "ok",
            "message":         fake_response.get("message", "Request processed"),
            "risk_score":      90,
            "action_required": "none",
            "explanation":     "Hacker diverted to honeypot containment.",
            "session_uuid":    session_uuid,
            "honeypot":        True
        }

    # ── Step 4: Store the event (real sessions only) ─────────
    created_at   = datetime.now(timezone.utc).isoformat()
    event_record = {
        "session_uuid": session_uuid,
        "session_ref":  session_ref,
        "user_id":      user_id,
        "action":       action,
        "endpoint":     endpoint,
        "data_volume":  data_volume,
        "ip_address":   ip_address or session.get("ip_address"),
        "user_agent":   user_agent or session.get("user_agent"),
        "risk_contribution": 0,
        "flagged":      False,
        "created_at":   created_at
    }

    db.table("anchor_session_events").insert(event_record).execute()
    log_event(session_uuid, f"event_recorded:{action}")

    # ── Step 5: Call the anomaly agent ──────────────────────
    # pyrefly: ignore [missing-import]
    from ml.anomaly import run_anomaly_agent

    verdict = run_anomaly_agent(
        session_uuid = session_uuid,
        user_id      = user_id,
        action       = action,
        endpoint     = endpoint,
        data_volume  = data_volume,
        ip_address   = ip_address or session.get("ip_address"),
        user_agent   = user_agent or session.get("user_agent"),
        client_id    = client_id
    )

    # ── Step 6: Update stored event with verdict ─────────────
    db.table("anchor_session_events") \
        .update({
            "risk_score": verdict.get("cumulative_risk") or verdict.get("risk_contribution", 0),
            "flagged":verdict.get("action_required") != "none"
        }) \
        .eq("session_uuid", session_uuid) \
        .eq("created_at", created_at) \
        .execute()

    # ── Step 7: Act on the verdict ───────────────────────────
    action_required = verdict.get("action_required", "none")

    if action_required == "kill":
        db.table("anchor_sessions") \
            .update({"status": "killed"}) \
            .eq("session_ref", session_ref) \
            .execute()
        log_threat(
            session_uuid,
            f"session_killed:{verdict.get('attack_pattern', 'anomaly')}",
            ip_address
        )

    elif action_required == "reauth":
        log_threat(
            session_uuid,
            f"reauth_required:{verdict.get('attack_pattern', 'anomaly')}",
            ip_address
        )

    # ── Step 8: Return clean response ────────────────────────
    status = (
        "threat"  if action_required == "kill" else
        "warning" if action_required in ("reauth", "warn") else
        "ok"
    )

    return {
        "status":          status,
        "message":         verdict.get("recommended_action", "Session monitored"),
        "risk_score":      verdict.get("cumulative_risk", 0),
        "action_required": action_required,
        "explanation":     verdict.get("explanation", ""),
        "attack_pattern":  verdict.get("attack_pattern", ""),
        "popia_concern":   verdict.get("popia_concern", False),
        "session_uuid":    session_uuid
    }


def get_session_events(session_uuid: str, limit: int = 100) -> list:
    """Full event history for a session — dashboard drill-down."""
    db     = get_db()
    result = db.table("anchor_session_events") \
        .select("*") \
        .eq("session_uuid", session_uuid) \
        .order("created_at", desc=True) \
        .limit(limit) \
        .execute()
    return result.data or []


def get_flagged_events(limit: int = 50) -> list:
    """All flagged events across all sessions — live threat feed."""
    db     = get_db()
    result = db.table("anchor_session_events") \
        .select("*") \
        .eq("flagged", True) \
        .order("created_at", desc=True) \
        .limit(limit) \
        .execute()
    return result.data or []