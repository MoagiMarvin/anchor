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
    WebAuthnVerifyRequest,
    SessionEventRequest
)
from session import create_session, validate_session, kill_session
from session_events import (
    record_session_event,
    get_session_events,
    get_flagged_events
)
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
        "message":    "Anchor is running",
        "status":     "ok",
        "version":    "2.0.0",
        "tagline":    "Identity & Session Protection Platform",
        "quantum_safe": True,
        "algorithm":  "CRYSTALS-Dilithium ML-DSA-65"
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
        user_id              = body.user_id,
        client_id            = client["id"],
        canvas_hash          = body.canvas_hash,
        screen_resolution    = body.screen_resolution,
        timezone_str         = body.timezone,
        hardware_concurrency = body.hardware_concurrency,
        language             = body.language,
        webgl                = body.webgl,
        platform             = body.platform,
        ip_address           = body.ip_address
    )
    return AnchorResponse(
        status  = result["status"],
        message = result["message"],
        did     = result.get("did")
    )


@app.post("/identity/verify-login", response_model=AnchorResponse)
def identity_verify_login(body: IdentityVerifyLoginRequest, client=Depends(verify_api_key)):
    if not check_rate_limit(client["api_key"]):
        raise HTTPException(status_code=429, detail="Rate limit exceeded.")

    result = verify_login(
        user_id              = body.user_id,
        client_id            = client["id"],
        canvas_hash          = body.canvas_hash,
        screen_resolution    = body.screen_resolution,
        timezone_str         = body.timezone,
        hardware_concurrency = body.hardware_concurrency,
        language             = body.language,
        webgl                = body.webgl,
        platform             = body.platform,
        ip_address           = body.ip_address
    )

    # ── Honeypot trigger ─────────────────────────────────────
    # Risk >= 75 but not a hard block?
    # Don't block — contain silently inside a honeypot session.
    # Attacker sees "Login successful" and thinks they're in.
    risk_score = result.get("risk", {}).get("score", 0) if "risk" in result else 0

    if risk_score >= 75 and result.get("status") != "threat":
        from honeypot import create_honeypot_session
        honeypot_token = create_honeypot_session(
            user_id    = body.user_id,
            ip_address = body.ip_address,
            user_agent = getattr(body, "user_agent", "unknown")
        )
        return AnchorResponse(
            status  = "ok",
            message = "Login successful",
            token   = honeypot_token
        )
    # ── End honeypot trigger ─────────────────────────────────

    return AnchorResponse(
        status  = result["status"],
        message = result["message"],
        did     = result.get("did"),
        action  = result.get("action"),
        risk    = RiskScore(**result["risk"]) if "risk" in result else None
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
        status  = "ok",
        message = "Quantum-safe session created for: " + client["client_name"],
        token   = token
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
        status  = result["status"],
        message = result["message"],
        risk    = RiskScore(**result["risk"]) if "risk" in result else None
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
        status  = result["status"],
        message = result["message"],
        risk    = RiskScore(**result["risk"]) if "risk" in result else None
    )


@app.post("/session/kill", response_model=AnchorResponse)
def session_kill(body: SessionKillRequest, client=Depends(verify_api_key)):
    result = kill_session(body.token)
    return AnchorResponse(status=result["status"], message=result["message"])


# ─────────────────────────────────────────
# BEHAVIOURAL MONITORING ENDPOINTS
# Post-login session surveillance
# Watches what users do — not just who they are
# ─────────────────────────────────────────

@app.post("/session/event", response_model=AnchorResponse)
def session_event(body: SessionEventRequest, client=Depends(verify_api_key)):
    """
    Called by the institution's app every time a user does
    something meaningful after login.

    Examples:
      - "view_records"
      - "export_records"
      - "admin_access"
      - "database_query"
      - "bulk_download"
      - "delete_records"

    Anchor's AI agent analyses the full session timeline and returns:
      ok      → normal activity, keep going
      warning → suspicious, monitoring escalated
      threat  → session killed or re-auth required

    Honeypot sessions: attacker always gets "ok" back.
    Their actions are silently logged for intelligence.
    """
    if not check_rate_limit(client["api_key"]):
        raise HTTPException(status_code=429, detail="Rate limit exceeded.")

    result = record_session_event(
        token       = body.token,
        action      = body.action,
        endpoint    = body.endpoint,
        data_volume = body.data_volume,
        ip_address  = body.ip_address,
        user_agent  = body.user_agent,
        client_id   = client.get("id")
    )

    return AnchorResponse(
        status  = result["status"],
        message = result["message"],
        risk    = RiskScore(
            score   = result.get("risk_score", 0),
            level   = _risk_level(result.get("risk_score", 0)),
            reasons = [result.get("explanation", "")]
        ) if result.get("risk_score", 0) > 0 else None
    )


@app.get("/session/{session_uuid}/events")
def session_event_history(session_uuid: str, client=Depends(verify_api_key)):
    """Full event timeline for a session — dashboard drill-down."""
    events = get_session_events(session_uuid)
    return {"session_uuid": session_uuid, "events": events, "count": len(events)}


@app.get("/session/{session_uuid}/analysis")
def session_analysis(session_uuid: str, client=Depends(verify_api_key)):
    """Latest AI agent verdict for a specific session."""
    from database import get_db
    db     = get_db()
    result = db.table("anchor_ai_analyses") \
        .select("*") \
        .eq("session_uuid", session_uuid) \
        .order("created_at", desc=True) \
        .limit(1) \
        .execute()
    analysis = result.data[0] if result.data else {}
    return {"session_uuid": session_uuid, "analysis": analysis}


@app.get("/events/flagged")
def flagged_events(client=Depends(verify_api_key)):
    """All flagged events across all sessions — live threat feed."""
    events = get_flagged_events(limit=50)
    return {"events": events, "count": len(events)}


@app.get("/analyses")
def ai_analyses(client=Depends(verify_api_key)):
    """Recent AI agent verdicts across all sessions."""
    from database import get_db
    db     = get_db()
    result = db.table("anchor_ai_analyses") \
        .select("*") \
        .order("created_at", desc=True) \
        .limit(20) \
        .execute()
    return {"analyses": result.data, "count": len(result.data)}


# ─────────────────────────────────────────
# POPIA ENDPOINTS
# Breach notification drafts — Section 22
# ─────────────────────────────────────────

@app.get("/popia/reports")
def popia_reports(client=Depends(verify_api_key)):
    """
    All POPIA breach report drafts for this client.
    Admin reads from here, reviews, and sends to Information Regulator.
    """
    # pyrefly: ignore [missing-import]
    from popia import get_reports
    reports = get_reports(client_id=client.get("id"))
    return {"reports": reports, "count": len(reports)}


@app.get("/popia/reports/{report_id}")
def popia_report_detail(report_id: int, client=Depends(verify_api_key)):
    """Full report draft — ready to review and send."""
    # pyrefly: ignore [missing-import]
    from popia import get_report
    report = get_report(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return report


@app.post("/popia/generate/{session_uuid}")
def popia_generate(session_uuid: str, client=Depends(verify_api_key)):
    """
    Manually trigger a POPIA report for a session.
    Use from the dashboard when admin wants to force a report
    regardless of automatic breach threshold.
    """
    # pyrefly: ignore [missing-import]
    from popia import generate_manual_report
    report = generate_manual_report(
        session_uuid = session_uuid,
        client_id    = client.get("id")
    )
    return report


# ─────────────────────────────────────────
# HONEYPOT DASHBOARD ENDPOINTS
# Intelligence collected from attacker sessions
# ─────────────────────────────────────────

@app.get("/honeypot/sessions")
def honeypot_sessions(client=Depends(verify_api_key)):
    """
    All active and historical honeypot sessions.
    Shows how many attackers are currently contained.
    """
    from database import get_db
    db     = get_db()
    result = db.table("anchor_sessions") \
        .select("session_uuid, user_id, ip_address, status, created_at, expires_at") \
        .eq("is_honeypot", True) \
        .order("created_at", desc=True) \
        .limit(50) \
        .execute()
    return {"honeypot_sessions": result.data, "count": len(result.data)}


@app.get("/honeypot/activity")
def honeypot_activity(client=Depends(verify_api_key)):
    """
    Every action attackers have taken inside honeypot sessions.
    This is the intelligence feed — what are they after?
    """
    from database import get_db
    db     = get_db()
    result = db.table("anchor_honeypot_logs") \
        .select("*") \
        .order("created_at", desc=True) \
        .limit(100) \
        .execute()
    return {"activity": result.data, "count": len(result.data)}


@app.get("/honeypot/session/{session_uuid}")
def honeypot_session_detail(session_uuid: str, client=Depends(verify_api_key)):
    """
    Full action log for a specific honeypot session.
    Shows exactly what one attacker did step by step.
    """
    from database import get_db
    db     = get_db()
    result = db.table("anchor_honeypot_logs") \
        .select("*") \
        .eq("session_uuid", session_uuid) \
        .order("created_at", desc=True) \
        .execute()
    return {
        "session_uuid": session_uuid,
        "actions":      result.data,
        "count":        len(result.data)
    }


# ─────────────────────────────────────────
# DASHBOARD STATS
# Summary counts for the threat dashboard
# ─────────────────────────────────────────

@app.get("/dashboard/stats")
def dashboard_stats(client=Depends(verify_api_key)):
    """
    Summary numbers for the dashboard header.
    Antigravity reads from here for the stat cards.
    """
    from database import get_db
    db = get_db()

    threats    = db.table("anchor_threats") \
        .select("id", count="exact").execute()
    honeypots  = db.table("anchor_sessions") \
        .select("id", count="exact").eq("is_honeypot", True).execute()
    flagged    = db.table("anchor_session_events") \
        .select("id", count="exact").eq("flagged", True).execute()
    analyses   = db.table("anchor_ai_analyses") \
        .select("id", count="exact").execute()

    return {
        "total_threats":           threats.count    or 0,
        "active_honeypots":        honeypots.count  or 0,
        "flagged_events":          flagged.count     or 0,
        "ai_analyses_run":         analyses.count   or 0,
    }


# ─────────────────────────────────────────
# ENCRYPTION ENDPOINTS
# ─────────────────────────────────────────

@app.post("/encrypt")
def encrypt_data(body: EncryptRequest, client=Depends(verify_api_key)):
    if not check_rate_limit(client["api_key"]):
        raise HTTPException(status_code=429, detail="Rate limit exceeded.")
    enc       = AnchorEncryption(body.client_key)
    encrypted = enc.encrypt_record(body.data, body.fields)
    return {"status": "ok", "message": f"{len(body.fields)} field(s) encrypted", "data": encrypted}


@app.post("/decrypt")
def decrypt_data(body: DecryptRequest, client=Depends(verify_api_key)):
    if not check_rate_limit(client["api_key"]):
        raise HTTPException(status_code=429, detail="Rate limit exceeded.")
    enc       = AnchorEncryption(body.client_key)
    decrypted = enc.decrypt_record(body.data, body.fields)
    return {"status": "ok", "message": f"{len(body.fields)} field(s) decrypted", "data": decrypted}


@app.post("/prepare-record")
def prepare_record(body: PrepareRecordRequest, client=Depends(verify_api_key)):
    if not check_rate_limit(client["api_key"]):
        raise HTTPException(status_code=429, detail="Rate limit exceeded.")
    enc    = AnchorEncryption(body.client_key)
    result = enc.prepare_record(body.data, body.config)
    return {"status": "ok", "message": "Record prepared for secure storage", "data": result}


# ─────────────────────────────────────────
# PQC ENDPOINTS
# ─────────────────────────────────────────

@app.post("/pqc/sign")
def pqc_sign(body: dict, client=Depends(verify_api_key)):
    from pqc import AnchorPQC
    pqc   = AnchorPQC(os.getenv("ANCHOR_SECRET", "anchor2026secret"))
    token = pqc.sign_token(body)
    info  = pqc.get_algorithm_info()
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
    db     = get_db()
    result = db.table("anchor_threats") \
        .select("*") \
        .order("detected_at", desc=True) \
        .limit(50) \
        .execute()
    return {"threats": result.data, "count": len(result.data)}


@app.get("/login-attempts")
def get_login_attempts(client=Depends(verify_api_key)):
    from database import get_db
    db     = get_db()
    result = db.table("anchor_login_attempts") \
        .select("*") \
        .order("attempted_at", desc=True) \
        .limit(50) \
        .execute()
    return {"attempts": result.data, "count": len(result.data)}


@app.get("/sessions")
def get_sessions(client=Depends(verify_api_key)):
    """Returns all active sessions — Watcher dashboard reads from here."""
    from database import get_db
    db     = get_db()
    result = db.table("anchor_sessions") \
        .select("*") \
        .order("created_at", desc=True) \
        .limit(50) \
        .execute()
    return {"sessions": result.data, "count": len(result.data)}


# ─────────────────────────────────────────
# WEBAUTHN ENDPOINTS
# Chip-level device attestation
# TPM / Secure Enclave / TrustZone
# ─────────────────────────────────────────

@app.post("/webauthn/challenge")
def webauthn_challenge(body: WebAuthnChallengeRequest, client=Depends(verify_api_key)):
    """Step 1 — get a challenge before registration or login."""
    from webauthn import generate_challenge
    return generate_challenge(body.user_id, client["id"])


@app.post("/webauthn/register")
def webauthn_register(body: WebAuthnRegisterRequest, client=Depends(verify_api_key)):
    """Step 2 — chip generated a keypair, store the public key."""
    from webauthn import register_credential
    return register_credential(
        user_id       = body.user_id,
        client_id     = client["id"],
        credential_id = body.credential_id,
        public_key    = body.public_key,
        challenge     = body.challenge,
        device_type   = body.device_type
    )


@app.post("/webauthn/verify")
def webauthn_verify(body: WebAuthnVerifyRequest, client=Depends(verify_api_key)):
    """WebAuthn login — chip signed our challenge, verify the signature."""
    from webauthn import verify_credential
    return verify_credential(
        user_id            = body.user_id,
        client_id          = client["id"],
        credential_id      = body.credential_id,
        signature          = body.signature,
        challenge          = body.challenge,
        authenticator_data = body.authenticator_data
    )


@app.get("/webauthn/credentials/{user_id}")
def webauthn_credentials(user_id: str, client=Depends(verify_api_key)):
    """Returns all registered devices for a user."""
    from webauthn import get_user_credentials
    return get_user_credentials(user_id, client["id"])


# ─────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────

def _risk_level(score: int) -> str:
    if score >= 80: return "critical"
    if score >= 60: return "high"
    if score >= 40: return "medium"
    return "low"