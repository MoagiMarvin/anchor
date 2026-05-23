import os
from datetime import datetime, timezone
from database import get_db


def log_event(session_uuid: str, event_type: str, data_volume: int = 0):
    """
    Best-effort audit log — writes to anchor_watcher_logs, not
    anchor_session_events. Keeps the session events table clean
    so cumulative risk calculations aren't polluted with empty rows.
    Never raises, so callers are never blocked.
    """
    try:
        db = get_db()
        db.table("anchor_watcher_logs").insert({
            "session_uuid": session_uuid,
            "event_type":   event_type,
            "data_volume":  data_volume,
            "created_at":   datetime.now(timezone.utc).isoformat()
        }).execute()
    except Exception:
        pass  # audit logging is non-critical


def log_threat(
    session_uuid: str,
    threat_type:  str,
    ip_address:   str,
    client_id:    str = None   # FIX: tag every threat row with the client
):
    """Best-effort threat log — never raises."""
    try:
        db = get_db()
        db.table("anchor_threats").insert({
            "session_uuid": session_uuid,
            "event_type":   threat_type,
            "threat_type":  threat_type,
            "ip_address":   ip_address,
            "client_id":    client_id,
            "risk_score":   100,
            "status":       "flagged",
            "detected_at":  datetime.now(timezone.utc).isoformat(),
            "created_at":   datetime.now(timezone.utc).isoformat()
        }).execute()
    except Exception:
        pass


def get_stats():
    db      = get_db()
    threats = db.table("anchor_threats").select("count", count="exact").execute()
    events  = db.table("anchor_session_events").select("count", count="exact").execute()
    flagged = db.table("anchor_session_events").select("count", count="exact").eq("flagged", True).execute()

    return {
        "total_threats":  threats.count or 0,
        "total_events":   events.count  or 0,
        "flagged_events": flagged.count or 0,
        "ai_analyses_run": threats.count or 0
    }