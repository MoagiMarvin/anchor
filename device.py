import hashlib
from database import get_db
from watcher import log_threat, log_event
from scoring import calculate_risk_score
from datetime import datetime, timezone

def build_device_fingerprint(
    canvas_hash: str,
    screen_resolution: str,
    timezone: str,
    hardware_concurrency: int,
    language: str
) -> str:
    """
    Builds a strong device fingerprint from real browser data.
    This is unbypassable without access to the actual device.
    """
    raw = f"{canvas_hash}:{screen_resolution}:{timezone}:{hardware_concurrency}:{language}"
    return hashlib.sha256(raw.encode()).hexdigest()

def verify_device(
    token: str,
    canvas_hash: str,
    screen_resolution: str,
    timezone_str: str,
    hardware_concurrency: int,
    language: str
) -> dict:
    """
    Verifies that the device making the request
    matches the device that created the session.
    This is the real fingerprinting — not just IP and UA.
    """
    db = get_db()

    # Get the session
    result = db.table("anchor_sessions")\
        .select("*")\
        .eq("token", token)\
        .eq("status", "active")\
        .execute()

    if not result.data:
        return {
            "status": "threat",
            "message": "Session not found or terminated",
            "risk": {"score": 100, "level": "critical", "reasons": ["Session not found"]}
        }

    session = result.data[0]

    # Build incoming device fingerprint
    incoming_fingerprint = build_device_fingerprint(
        canvas_hash,
        screen_resolution,
        timezone_str,
        hardware_concurrency,
        language
    )

    # First time device data is submitted — store it
    if not session.get("canvas_hash"):
        db.table("anchor_sessions").update({
            "canvas_hash": canvas_hash,
            "screen_resolution": screen_resolution,
            "timezone": timezone_str,
            "hardware_concurrency": hardware_concurrency,
            "language": language,
            "device_fingerprint": incoming_fingerprint
        }).eq("token", token).execute()

        log_event(token, "device_registered")
        return {
            "status": "ok",
            "message": "Device registered and verified",
            "risk": {"score": 0, "level": "safe", "reasons": []}
        }

    # Compare device fingerprints
    stored_fingerprint = build_device_fingerprint(
        session["canvas_hash"],
        session["screen_resolution"],
        session["timezone"],
        session["hardware_concurrency"],
        session["language"]
    )

    reasons = []
    score = 0

    if incoming_fingerprint != stored_fingerprint:
        score += 70
        reasons.append("Device fingerprint mismatch")

    if session.get("screen_resolution") != screen_resolution:
        score += 15
        reasons.append("Screen resolution changed")

    if session.get("timezone") != timezone_str:
        score += 15
        reasons.append("Timezone changed — possible VPN or location spoofing")

    if session.get("language") != language:
        score += 10
        reasons.append("Browser language changed")

    score = min(score, 100)

    if score == 0:
        level = "safe"
    elif score < 30:
        level = "low"
    elif score < 60:
        level = "medium"
    elif score < 80:
        level = "high"
    else:
        level = "critical"

    risk = {"score": score, "level": level, "reasons": reasons}

    if score >= 70:
        # Kill session and log threat
        db.table("anchor_sessions")\
            .update({"status": "killed"})\
            .eq("token", token)\
            .execute()
        log_threat(token, "device_fingerprint_mismatch", "unknown")
        return {
            "status": "threat",
            "message": "Device mismatch detected — session terminated",
            "risk": risk
        }

    log_event(token, "device_verified")
    return {
        "status": "ok",
        "message": "Device verified",
        "risk": risk
    }
