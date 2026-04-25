"""
Anchor Identity Module
Handles device registration and login verification.

This is the core of Anchor's identity protection:
- Register a trusted device when a user signs up
- Verify that device on every login
- Block or challenge if device doesn't match

Integrates with any website or app via anchor.js
"""

import hashlib
import uuid
from datetime import datetime, timezone
from database import get_db
from watcher import log_threat, log_event

# ─────────────────────────────────────────
# DEVICE FINGERPRINT BUILDER
# Combines all device signals into one hash
# ─────────────────────────────────────────
def build_device_fingerprint(
    canvas_hash: str,
    screen_resolution: str,
    timezone_str: str,
    hardware_concurrency: int,
    language: str,
    webgl: str = "",
    platform: str = ""
) -> str:
    raw = f"{canvas_hash}:{screen_resolution}:{timezone_str}:{hardware_concurrency}:{language}:{webgl}:{platform}"
    return hashlib.sha256(raw.encode()).hexdigest()

# ─────────────────────────────────────────
# DECENTRALIZED IDENTITY (DID)
# Each device gets a unique DID
# This is the Web3 Trust concept from CSIR
# The DID is tied to the device — not a server
# ─────────────────────────────────────────
def generate_did(user_id: str, client_id: str, device_fingerprint: str) -> str:
    """
    Generates a Decentralized Identifier (DID) for this device.
    Format: did:anchor:user_id:device_hash
    
    This follows the W3C DID standard concept.
    The identity is derived from the device itself —
    not assigned by a central authority.
    """
    combined = f"{user_id}:{client_id}:{device_fingerprint}"
    device_hash = hashlib.sha256(combined.encode()).hexdigest()[:16]
    return f"did:anchor:{device_hash}"

# ─────────────────────────────────────────
# REGISTER — Called at signup
# Stores the user's trusted device identity
# ─────────────────────────────────────────
def register_identity(
    user_id: str,
    client_id: str,
    canvas_hash: str,
    screen_resolution: str,
    timezone_str: str,
    hardware_concurrency: int,
    language: str,
    webgl: str = "",
    platform: str = "",
    ip_address: str = ""
) -> dict:
    """
    Registers a user's device identity at signup.
    
    Call this when:
    - A new user creates an account on your website
    - anchor.js has collected device data from the browser
    
    This becomes the trusted device baseline.
    Every future login is compared against this.
    """
    db = get_db()

    # Build the device fingerprint
    device_fingerprint = build_device_fingerprint(
        canvas_hash, screen_resolution, timezone_str,
        hardware_concurrency, language, webgl, platform
    )

    # Generate DID for this device
    did = generate_did(user_id, client_id, device_fingerprint)

    # Check if identity already exists for this user+client
    existing = db.table("anchor_identities")\
        .select("*")\
        .eq("user_id", user_id)\
        .eq("client_id", client_id)\
        .execute()

    if existing.data:
        # Update existing identity
        db.table("anchor_identities").update({
            "canvas_hash": canvas_hash,
            "screen_resolution": screen_resolution,
            "timezone": timezone_str,
            "hardware_concurrency": hardware_concurrency,
            "language": language,
            "webgl": webgl,
            "platform": platform,
            "device_fingerprint": device_fingerprint,
            "did": did,
            "registered_at": datetime.now(timezone.utc).isoformat()
        }).eq("user_id", user_id).eq("client_id", client_id).execute()

        log_event(f"{user_id}:{client_id}", "identity_updated")
        return {
            "status": "ok",
            "message": "Identity updated",
            "did": did,
            "device_fingerprint": device_fingerprint[:16] + "..."
        }

    # Store new identity
    db.table("anchor_identities").insert({
        "user_id": user_id,
        "client_id": client_id,
        "canvas_hash": canvas_hash,
        "screen_resolution": screen_resolution,
        "timezone": timezone_str,
        "hardware_concurrency": hardware_concurrency,
        "language": language,
        "webgl": webgl,
        "platform": platform,
        "device_fingerprint": device_fingerprint,
        "did": did,
        "status": "active",
        "registered_at": datetime.now(timezone.utc).isoformat()
    }).execute()

    log_event(f"{user_id}:{client_id}", "identity_registered")

    return {
        "status": "ok",
        "message": "Identity registered successfully",
        "did": did,
        "device_fingerprint": device_fingerprint[:16] + "..."
    }

# ─────────────────────────────────────────
# VERIFY LOGIN — Called at every login
# Compares current device to registered device
# ─────────────────────────────────────────
def verify_login(
    user_id: str,
    client_id: str,
    canvas_hash: str,
    screen_resolution: str,
    timezone_str: str,
    hardware_concurrency: int,
    language: str,
    webgl: str = "",
    platform: str = "",
    ip_address: str = ""
) -> dict:
    """
    Verifies the device at login time.
    
    This is the PRIMARY security check.
    Called before the user gets access to anything.
    
    Returns:
    - status: ok → known device, allow login
    - status: challenge → new device, send email verification
    - status: threat → suspicious device, block login
    """
    db = get_db()

    # Get registered identity
    result = db.table("anchor_identities")\
        .select("*")\
        .eq("user_id", user_id)\
        .eq("client_id", client_id)\
        .eq("status", "active")\
        .execute()

    # No identity registered yet
    if not result.data:
        return {
            "status": "challenge",
            "message": "No registered device found. Please verify your identity.",
            "action": "register_device",
            "risk": {"score": 50, "level": "medium", "reasons": ["No registered device"]}
        }

    identity = result.data[0]

    # Build current device fingerprint
    current_fingerprint = build_device_fingerprint(
        canvas_hash, screen_resolution, timezone_str,
        hardware_concurrency, language, webgl, platform
    )

    stored_fingerprint = identity["device_fingerprint"]

    # Perfect match — known device
    if current_fingerprint == stored_fingerprint:
        # Update last verified
        db.table("anchor_identities").update({
            "last_verified": datetime.now(timezone.utc).isoformat()
        }).eq("user_id", user_id).eq("client_id", client_id).execute()

        # Log successful login attempt
        db.table("anchor_login_attempts").insert({
            "user_id": user_id,
            "client_id": client_id,
            "device_fingerprint": current_fingerprint,
            "status": "allowed",
            "risk_score": 0,
            "risk_level": "safe",
            "reasons": [],
            "ip_address": ip_address,
            "attempted_at": datetime.now(timezone.utc).isoformat()
        }).execute()

        log_event(f"{user_id}:{client_id}", "login_verified_known_device")

        return {
            "status": "ok",
            "message": "Known device verified. Login approved.",
            "did": identity["did"],
            "risk": {"score": 0, "level": "safe", "reasons": []}
        }

    # Device doesn't match — calculate how different
    reasons = []
    score = 0

    if identity.get("canvas_hash") != canvas_hash:
        score += 40
        reasons.append("Canvas fingerprint mismatch — different GPU detected")

    if identity.get("screen_resolution") != screen_resolution:
        score += 15
        reasons.append("Screen resolution changed")

    if identity.get("timezone") != timezone_str:
        score += 20
        reasons.append("Timezone changed — possible VPN or different country")

    if identity.get("hardware_concurrency") != hardware_concurrency:
        score += 15
        reasons.append("CPU cores changed — different hardware")

    if identity.get("language") != language:
        score += 10
        reasons.append("Browser language changed")

    if identity.get("webgl") and identity.get("webgl") != webgl:
        score += 20
        reasons.append("Graphics card changed — different device")

    score = min(score, 100)

    if score < 30:
        level = "low"
    elif score < 60:
        level = "medium"
    elif score < 80:
        level = "high"
    else:
        level = "critical"

    risk = {"score": score, "level": level, "reasons": reasons}

    # Log the attempt
    db.table("anchor_login_attempts").insert({
        "user_id": user_id,
        "client_id": client_id,
        "device_fingerprint": current_fingerprint,
        "status": "challenge" if score < 70 else "blocked",
        "risk_score": score,
        "risk_level": level,
        "reasons": reasons,
        "ip_address": ip_address,
        "attempted_at": datetime.now(timezone.utc).isoformat()
    }).execute()

    # High risk — block completely
    if score >= 70:
        log_threat(
            f"{user_id}:{client_id}",
            "suspicious_login_blocked",
            ip_address
        )
        return {
            "status": "threat",
            "message": "Login blocked — device does not match registered identity.",
            "action": "contact_support",
            "risk": risk
        }

    # Medium risk — send email challenge
    log_event(f"{user_id}:{client_id}", "login_challenge_sent")
    return {
        "status": "challenge",
        "message": "New device detected. Email verification required.",
        "action": "verify_email",
        "risk": risk
    }
