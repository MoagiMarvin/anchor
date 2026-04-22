from fastapi import FastAPI, Depends, HTTPException
from models import (
    SessionCreateRequest, SessionValidateRequest,
    SessionKillRequest, AnchorResponse, RiskScore,
    DeviceVerifyRequest
)
from session import create_session, validate_session, kill_session
from device import verify_device
from auth import verify_api_key
from limiter import check_rate_limit

app = FastAPI(
    title="Anchor",
    description="Session protection and threat detection API — SS26Hack 2026",
    version="1.0.0"
)

@app.get("/")
def root():
    return {"message": "Anchor is running", "status": "ok", "version": "1.0.0"}

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
    """
    The real device fingerprinting endpoint.
    anchor.js calls this with actual browser/device data.
    Detects if a different physical device is using a stolen session.
    """
    if not check_rate_limit(client["api_key"]):
        raise HTTPException(status_code=429, detail="Rate limit exceeded.")
    result = verify_device(
        body.token,
        body.canvas_hash,
        body.screen_resolution,
        body.timezone,
        body.hardware_concurrency,
        body.language
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