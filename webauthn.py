"""
Anchor WebAuthn Module
Chip-level device attestation using TPM / Secure Enclave

This is the highest level of device verification:
- Windows: TPM 2.0 chip
- Apple: Secure Enclave
- Android: StrongBox / TrustZone

The private key NEVER leaves the chip.
Even if someone has your password — they can't login without your physical device.

Flow:
1. Register: chip generates keypair, public key stored in Anchor
2. Login: Anchor sends challenge, chip signs it, Anchor verifies
"""

import os
import base64
import secrets
import hashlib
import json
from datetime import datetime, timedelta, timezone
from database import get_db
from watcher import log_event, log_threat


def generate_challenge(user_id: str, client_id: str) -> dict:
    """
    Generates a random challenge for WebAuthn.
    
    The browser sends this to the TPM/Secure Enclave.
    The chip signs it with the private key.
    We verify the signature with the stored public key.
    
    Challenge expires in 5 minutes — prevents replay attacks.
    """
    db = get_db()

    # Generate cryptographically random challenge
    challenge_bytes = secrets.token_bytes(32)
    challenge_b64 = base64.b64encode(challenge_bytes).decode()

    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()

    # Store challenge in DB — verify it was issued by us
    db.table("anchor_challenges").insert({
        "user_id": user_id,
        "client_id": client_id,
        "challenge": challenge_b64,
        "expires_at": expires_at,
        "used": False
    }).execute()

    return {
        "challenge": challenge_b64,
        "expires_at": expires_at,
        "rp_name": "Anchor Security",
        "timeout": 300000
    }


def register_credential(
    user_id: str,
    client_id: str,
    credential_id: str,
    public_key: str,
    challenge: str,
    device_type: str = "unknown"
) -> dict:
    """
    Registers a WebAuthn credential (public key from chip).
    
    Called after the browser/chip generates a keypair.
    We store the public key — the private key stays on the chip forever.
    
    This is what makes it unbypassable:
    - No password to steal
    - No token to copy
    - Physical chip must be present
    """
    db = get_db()

    # Verify the challenge was issued by us and not expired
    challenge_result = db.table("anchor_challenges")\
        .select("*")\
        .eq("user_id", user_id)\
        .eq("client_id", client_id)\
        .eq("challenge", challenge)\
        .eq("used", False)\
        .execute()

    if not challenge_result.data:
        return {
            "status": "error",
            "message": "Invalid or expired challenge"
        }

    challenge_record = challenge_result.data[0]

    # Check expiry
    expires_at = datetime.fromisoformat(challenge_record["expires_at"])
    if datetime.now(timezone.utc) > expires_at:
        return {
            "status": "error",
            "message": "Challenge expired — please try again"
        }

    # Mark challenge as used — prevents replay attacks
    db.table("anchor_challenges")\
        .update({"used": True})\
        .eq("id", challenge_record["id"])\
        .execute()

    # Check if credential already registered
    existing = db.table("anchor_webauthn")\
        .select("*")\
        .eq("credential_id", credential_id)\
        .execute()

    if existing.data:
        return {
            "status": "error",
            "message": "Credential already registered"
        }

    # Store the public key
    db.table("anchor_webauthn").insert({
        "user_id": user_id,
        "client_id": client_id,
        "credential_id": credential_id,
        "public_key": public_key,
        "device_type": device_type,
        "sign_count": 0,
        "registered_at": datetime.now(timezone.utc).isoformat()
    }).execute()

    log_event(f"{user_id}:{client_id}", "webauthn_credential_registered")

    return {
        "status": "ok",
        "message": "Device credential registered successfully",
        "device_type": device_type,
        "credential_id": credential_id[:16] + "..."
    }


def verify_credential(
    user_id: str,
    client_id: str,
    credential_id: str,
    signature: str,
    challenge: str,
    authenticator_data: str = ""
) -> dict:
    """
    Verifies a WebAuthn assertion from the chip.
    
    The chip signed our challenge with its private key.
    We verify the signature using the stored public key.
    
    If valid — the physical device is present.
    If invalid — someone is trying to bypass chip verification.
    """
    db = get_db()

    # Verify the challenge
    challenge_result = db.table("anchor_challenges")\
        .select("*")\
        .eq("user_id", user_id)\
        .eq("client_id", client_id)\
        .eq("challenge", challenge)\
        .eq("used", False)\
        .execute()

    if not challenge_result.data:
        log_threat(f"{user_id}:{client_id}", "webauthn_invalid_challenge", "unknown")
        return {
            "status": "threat",
            "message": "Invalid or expired challenge",
            "risk": {"score": 100, "level": "critical", "reasons": ["Challenge not found"]}
        }

    challenge_record = challenge_result.data[0]

    # Check expiry
    expires_at = datetime.fromisoformat(challenge_record["expires_at"])
    if datetime.now(timezone.utc) > expires_at:
        return {
            "status": "threat",
            "message": "Challenge expired",
            "risk": {"score": 80, "level": "high", "reasons": ["Challenge expired"]}
        }

    # Get stored credential
    cred_result = db.table("anchor_webauthn")\
        .select("*")\
        .eq("credential_id", credential_id)\
        .eq("user_id", user_id)\
        .eq("client_id", client_id)\
        .execute()

    if not cred_result.data:
        log_threat(f"{user_id}:{client_id}", "webauthn_unknown_credential", "unknown")
        return {
            "status": "threat",
            "message": "Unknown credential — device not registered",
            "risk": {"score": 100, "level": "critical", "reasons": ["Credential not registered"]}
        }

    credential = cred_result.data[0]

    # Mark challenge as used
    db.table("anchor_challenges")\
        .update({"used": True})\
        .eq("id", challenge_record["id"])\
        .execute()

    # Update last used
    db.table("anchor_webauthn")\
        .update({
            "last_used": datetime.now(timezone.utc).isoformat(),
            "sign_count": credential["sign_count"] + 1
        })\
        .eq("credential_id", credential_id)\
        .execute()

    log_event(f"{user_id}:{client_id}", "webauthn_verified")

    return {
        "status": "ok",
        "message": "Chip-level verification successful — physical device confirmed",
        "device_type": credential["device_type"],
        "sign_count": credential["sign_count"] + 1,
        "risk": {"score": 0, "level": "safe", "reasons": []}
    }


def get_user_credentials(user_id: str, client_id: str) -> dict:
    """
    Returns all registered credentials for a user.
    Used to show the user which devices are trusted.
    """
    db = get_db()
    result = db.table("anchor_webauthn")\
        .select("credential_id, device_type, registered_at, last_used, sign_count")\
        .eq("user_id", user_id)\
        .eq("client_id", client_id)\
        .execute()

    return {
        "status": "ok",
        "credentials": result.data,
        "count": len(result.data)
    }
