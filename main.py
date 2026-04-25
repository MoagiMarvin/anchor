from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from models import (
    SessionCreateRequest, SessionValidateRequest,
    SessionKillRequest, AnchorResponse, RiskScore,
    DeviceVerifyRequest, EncryptRequest, DecryptRequest,
    IdentityRegisterRequest, IdentityVerifyLoginRequest
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
        "tagline": "Identity & Session Protection Platform"
    }

# ─────────────────────────────────────────
# IDENTITY ENDPOINTS
# The primary defence — runs at signup and login
# ─────────────────────────────────────────

@app.post("/identity/register", response_model=AnchorResponse)
def identity_register(body: IdentityRegisterRequest, client=Depends(verify_api_key)):
    """
    Call this when a user creates an account on your website.
    anchor.js collects device data and sends it here.
    Anchor stores the trusted device identity.
    """
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
    """
    Call this BEFORE granting login access.
    anchor.js collects device data and sends it here.
    
    Returns:
    - ok → known device, allow login
    - challenge → new device, send email verification  
    - threat → suspicious device, block login
    """
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
# Secondary defence — monitors after login
# ─────────────────────────────────────────

@app.post("/session/create", response_model=AnchorResponse)
def session_create(body: SessionCreateRequest, client=Depends(verify_api_key)):
    if not check_rate_limit(client["api_key"]):
        raise HTTPException(status_code=429, detail="Rate limit exceeded.")
    token = create_session(body.user_id, body.ip_address, body.user_agent)
    return AnchorResponse(
        status="ok",
        message=f"Session created for client: {client['client_name']}",
        token=token
    )

@app.post("/session/validate", response_model=AnchorResponse)
def session_validate(body: SessionValidateRequest, client=Depends(verify_api_key)):
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
# Client encrypts their own data
# Anchor never sees the raw data or the key
# ─────────────────────────────────────────

@app.post("/encrypt")
def encrypt_data(body: EncryptRequest, client=Depends(verify_api_key)):
    """
    Encrypts specific fields in a record using AES-256-GCM.
    The client provides their own key — Anchor never stores it.
    Safe to store encrypted values in client's own database.
    
    Example use: encrypt student ID before storing in Moodle DB
    """
    if not check_rate_limit(client["api_key"]):
        raise HTTPException(status_code=429, detail="Rate limit exceeded.")

    enc = AnchorEncryption(body.client_key)
    encrypted = enc.encrypt_record(body.data, body.fields)
    return {
        "status": "ok",
        "message": f"{len(body.fields)} field(s) encrypted",
        "data": encrypted
    }

@app.post("/decrypt")
def decrypt_data(body: DecryptRequest, client=Depends(verify_api_key)):
    """
    Decrypts fields previously encrypted by Anchor.
    Client must provide the same key used for encryption.
    """
    if not check_rate_limit(client["api_key"]):
        raise HTTPException(status_code=429, detail="Rate limit exceeded.")

    enc = AnchorEncryption(body.client_key)
    decrypted = enc.decrypt_record(body.data, body.fields)
    return {
        "status": "ok",
        "message": f"{len(body.fields)} field(s) decrypted",
        "data": decrypted
    }

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
    """
    Returns all login attempts — approved, challenged, and blocked.
    Full audit trail for compliance.
    """
    from database import get_db
    db = get_db()
    result = db.table("anchor_login_attempts")\
        .select("*")\
        .order("attempted_at", desc=True)\
        .limit(50)\
        .execute()
    return {"attempts": result.data, "count": len(result.data)}