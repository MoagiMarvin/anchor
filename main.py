import os
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from models import (
    SessionCreateRequest, SessionValidateRequest,
    SessionKillRequest, AnchorResponse, RiskScore,
    DeviceVerifyRequest, EncryptRequest, DecryptRequest,
    PrepareRecordRequest, IdentityRegisterRequest,
    IdentityVerifyLoginRequest,
    WebAuthnChallengeRequest, WebAuthnRegisterRequest,
    WebAuthnVerifyRequest
)
from session import create_session, validate_session, kill_session
from device import verify_device
from identity import register_identity, verify_login
from encryption import AnchorEncryption
from auth import verify_api_key
from limiter import check_rate_limit

app = FastAPI(
    title="Anchor",
    description="Identity & Session Protection Platform — SS26Hack 2026",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

@app.get("/")
def root():
    return {
        "message": "Anchor is running",
        "status": "ok",
        "version": "2.0.0",
        "tagline": "Identity & Session Protection Platform",
        "quantum_safe": True,
        "algorithm": "CRYSTALS-Dilithium ML-DSA-65"
    }

# ─────────────────────────────────────────
# IDENTITY ENDPOINTS
# Primary defence — runs at signup and login
# ─────────────────────────────────────────

@app.post("/identity/register", response_model=AnchorResponse)
def identity_register(body: IdentityRegisterRequest, client=Depends(verify_api_key)):
    if not check_rate_limit(client["api_key"]):
        raise HTTPException(status_code=429, detail="Rate limit exceeded.")
    result = register_identity(
        user_id=body.user_id,
        client_id=client["id"],
        canvas_hash=body.canvas_hash,
        screen_resolution=body.screen_resolution,
        timezone_str=body.timezone,
        hardware_concurrency=body.hardware_concurrency,
        language=body.language,
        webgl=body.webgl,
        platform=body.platform,
        ip_address=body.ip_address
    )
    return AnchorResponse(
        status=result["status"],
        message=result["message"],
        did=result.get("did")
    )

@app.post("/identity/verify-login", response_model=AnchorResponse)
def identity_verify_login(body: IdentityVerifyLoginRequest, client=Depends(verify_api_key)):
    if not check_rate_limit(client["api_key"]):
        raise HTTPException(status_code=429, detail="Rate limit exceeded.")
    result = verify_login(
        user_id=body.user_id,
        client_id=client["id"],
        canvas_hash=body.canvas_hash,
        screen_resolution=body.screen_resolution,
        timezone_str=body.timezone,
        hardware_concurrency=body.hardware_concurrency,
        language=body.language,
        webgl=body.webgl,
        platform=body.platform,
        ip_address=body.ip_address
    )
    return AnchorResponse(
        status=result["status"],
        message=result["message"],
        did=result.get("did"),
        action=result.get("action"),
        risk=RiskScore(**result["risk"]) if "risk" in result else None
    )

# ─────────────────────────────────────────
# SESSION ENDPOINTS
# Merged PQC + Supabase tokens
# ─────────────────────────────────────────

@app.post("/session/create", response_model=AnchorResponse)
def session_create(body: SessionCreateRequest, client=Depends(verify_api_key)):
    """
    Creates a quantum-safe session token.
    
    Returns a CRYSTALS-Dilithium signed token (ML-DSA-65).
    Also logs to Supabase so the Watcher can monitor it.
    
    The client stores this token and sends it on every request.
    """
    if not check_rate_limit(client["api_key"]):
        raise HTTPException(status_code=429, detail="Rate limit exceeded.")

    token = create_session(body.user_id, body.ip_address, body.user_agent)
    return AnchorResponse(
        status="ok",
        message="Quantum-safe session created for: " + client["client_name"],
        token=token
    )

@app.post("/session/validate", response_model=AnchorResponse)
def session_validate(body: SessionValidateRequest, client=Depends(verify_api_key)):
    """
    Three-layer validation:
    1. Dilithium signature verification (quantum safe)
    2. Supabase session check (watcher monitoring)
    3. Device fingerprint check (hijack detection)
    """
    if not check_rate_limit(client["api_key"]):
        raise HTTPException(status_code=429, detail="Rate limit exceeded.")

    result = validate_session(body.token, body.ip_address, body.user_agent)
    return AnchorResponse(
        status=result["status"],
        message=result["message"],
        risk=RiskScore(**result["risk"]) if "risk" in result else None
    )

@app.post("/session/verify-device", response_model=AnchorResponse)
def session_verify_device(body: DeviceVerifyRequest, client=Depends(verify_api_key)):
    if not check_rate_limit(client["api_key"]):
        raise HTTPException(status_code=429, detail="Rate limit exceeded.")
    result = verify_device(
        body.token, body.canvas_hash, body.screen_resolution,
        body.timezone, body.hardware_concurrency, body.language
    )
    return AnchorResponse(
        status=result["status"],
        message=result["message"],
        risk=RiskScore(**result["risk"]) if "risk" in result else None
    )

@app.post("/session/kill", response_model=AnchorResponse)
def session_kill(body: SessionKillRequest, client=Depends(verify_api_key)):
    result = kill_session(body.token)
    return AnchorResponse(status=result["status"], message=result["message"])

# ─────────────────────────────────────────
# ENCRYPTION ENDPOINTS
# ─────────────────────────────────────────

@app.post("/encrypt")
def encrypt_data(body: EncryptRequest, client=Depends(verify_api_key)):
    if not check_rate_limit(client["api_key"]):
        raise HTTPException(status_code=429, detail="Rate limit exceeded.")
    enc = AnchorEncryption(body.client_key)
    encrypted = enc.encrypt_record(body.data, body.fields)
    return {"status": "ok", "message": f"{len(body.fields)} field(s) encrypted", "data": encrypted}

@app.post("/decrypt")
def decrypt_data(body: DecryptRequest, client=Depends(verify_api_key)):
    if not check_rate_limit(client["api_key"]):
        raise HTTPException(status_code=429, detail="Rate limit exceeded.")
    enc = AnchorEncryption(body.client_key)
    decrypted = enc.decrypt_record(body.data, body.fields)
    return {"status": "ok", "message": f"{len(body.fields)} field(s) decrypted", "data": decrypted}

@app.post("/prepare-record")
def prepare_record(body: PrepareRecordRequest, client=Depends(verify_api_key)):
    if not check_rate_limit(client["api_key"]):
        raise HTTPException(status_code=429, detail="Rate limit exceeded.")
    enc = AnchorEncryption(body.client_key)
    result = enc.prepare_record(body.data, body.config)
    return {"status": "ok", "message": "Record prepared for secure storage", "data": result}

# ─────────────────────────────────────────
# PQC ENDPOINTS
# ─────────────────────────────────────────

@app.post("/pqc/sign")
def pqc_sign(body: dict, client=Depends(verify_api_key)):
    from pqc import AnchorPQC
    pqc = AnchorPQC(os.getenv("ANCHOR_SECRET", "anchor2026secret"))
    token = pqc.sign_token(body)
    info = pqc.get_algorithm_info()
    return {"status": "ok", "signed_token": token, "algorithm": info}

@app.post("/pqc/verify")
def pqc_verify(body: dict, client=Depends(verify_api_key)):
    from pqc import AnchorPQC
    token = body.get("token")
    if not token:
        raise HTTPException(status_code=400, detail="Token required")
    pqc = AnchorPQC(os.getenv("ANCHOR_SECRET", "anchor2026secret"))
    return pqc.verify_token(token)

@app.get("/pqc/info")
def pqc_info(client=Depends(verify_api_key)):
    from pqc import AnchorPQC
    pqc = AnchorPQC(os.getenv("ANCHOR_SECRET", "anchor2026secret"))
    return pqc.get_algorithm_info()

# ─────────────────────────────────────────
# WATCHER FEED
# ─────────────────────────────────────────

@app.get("/threats")
def get_threats(client=Depends(verify_api_key)):
    from database import get_db
    db = get_db()
    result = db.table("anchor_threats")\
        .select("*")\
        .order("detected_at", desc=True)\
        .limit(50)\
        .execute()
    return {"threats": result.data, "count": len(result.data)}

@app.get("/login-attempts")
def get_login_attempts(client=Depends(verify_api_key)):
    from database import get_db
    db = get_db()
    result = db.table("anchor_login_attempts")\
        .select("*")\
        .order("attempted_at", desc=True)\
        .limit(50)\
        .execute()
    return {"attempts": result.data, "count": len(result.data)}

@app.get("/sessions")
def get_sessions(client=Depends(verify_api_key)):
    """
    Returns all active sessions.
    Watcher dashboard reads from here.
    """
    from database import get_db
    db = get_db()
    result = db.table("anchor_sessions")\
        .select("*")\
        .order("created_at", desc=True)\
        .limit(50)\
        .execute()
    return {"sessions": result.data, "count": len(result.data)}

# ─────────────────────────────────────────
# WEBAUTHN ENDPOINTS
# Chip-level device attestation
# TPM / Secure Enclave / TrustZone
# ─────────────────────────────────────────

@app.post("/webauthn/challenge")
def webauthn_challenge(body: WebAuthnChallengeRequest, client=Depends(verify_api_key)):
    """
    Step 1 of WebAuthn flow.
    Call this to get a challenge before registration or login.
    Send the challenge to the browser — anchor.js passes it to the chip.
    """
    from webauthn import generate_challenge
    result = generate_challenge(body.user_id, client["id"])
    return result

@app.post("/webauthn/register")
def webauthn_register(body: WebAuthnRegisterRequest, client=Depends(verify_api_key)):
    """
    Step 2 of WebAuthn registration.
    The chip generated a keypair — we store the public key.
    Private key stays on the chip forever.
    Works with: Windows TPM, Apple Secure Enclave, Android TrustZone
    """
    from webauthn import register_credential
    result = register_credential(
        user_id=body.user_id,
        client_id=client["id"],
        credential_id=body.credential_id,
        public_key=body.public_key,
        challenge=body.challenge,
        device_type=body.device_type
    )
    return result

@app.post("/webauthn/verify")
def webauthn_verify(body: WebAuthnVerifyRequest, client=Depends(verify_api_key)):
    """
    WebAuthn login verification.
    The chip signed our challenge — we verify the signature.
    Physical device must be present. Cannot be faked remotely.
    """
    from webauthn import verify_credential
    result = verify_credential(
        user_id=body.user_id,
        client_id=client["id"],
        credential_id=body.credential_id,
        signature=body.signature,
        challenge=body.challenge,
        authenticator_data=body.authenticator_data
    )
    return result

@app.get("/webauthn/credentials/{user_id}")
def webauthn_credentials(user_id: str, client=Depends(verify_api_key)):
    """
    Returns all registered devices for a user.
    """
    from webauthn import get_user_credentials
    return get_user_credentials(user_id, client["id"])