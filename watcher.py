import os
from datetime import datetime
from database import get_db

def log_threat(token: str, reason: str, ip_address: str):
    db = get_db()
    db.table("anchor_threats").insert({
        "token": token,
        "reason": reason,
        "ip_address": ip_address,
        "detected_at": datetime.utcnow().isoformat()
    }).execute()
    print(f"[ANCHOR WATCHER] THREAT DETECTED — {reason} — IP: {ip_address}")

def log_event(token: str, event: str):
    db = get_db()
    db.table("anchor_events").insert({
        "token": token,
        "event": event,
        "timestamp": datetime.utcnow().isoformat()
    }).execute()
