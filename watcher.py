import os
from datetime import datetime, timezone
from database import get_db

def log_event(session_uuid, event_type, data_volume=0):
    db = get_db()
    db.table("anchor_session_events").insert({
        "session_uuid": session_uuid,
        "action": event_type,
        "data_volume": data_volume,
        "created_at": datetime.now(timezone.utc).isoformat()
    }).execute()

def log_threat(session_uuid, threat_type, ip_address):
    db = get_db()
    # Corrected column: 'event_type' instead of 'threat_type'
    db.table("anchor_threats").insert({
        "session_uuid": session_uuid,
        "event_type": threat_type,
        "ip_address": ip_address,
        "risk_score": 100,
        "status": "flagged",
        "created_at": datetime.now(timezone.utc).isoformat()
    }).execute()

def get_stats():
    db = get_db()
    threats = db.table("anchor_threats").select("count", count="exact").execute()
    events = db.table("anchor_session_events").select("count", count="exact").execute()
    flagged = db.table("anchor_session_events").select("count", count="exact").eq("flagged", True).execute()
    
    return {
        "total_threats": threats.count if threats.count is not None else 0,
        "total_events": events.count if events.count is not None else 0,
        "flagged_events": flagged.count if flagged.count is not None else 0,
        "ai_analyses_run": threats.count if threats.count is not None else 0 # Mock stat
    }
