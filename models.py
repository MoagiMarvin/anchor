from pydantic import BaseModel
from typing import Optional, List

class SessionCreateRequest(BaseModel):
    user_id: str
    ip_address: str
    user_agent: str

class SessionValidateRequest(BaseModel):
    token: str
    ip_address: str
    user_agent: str

class SessionKillRequest(BaseModel):
    token: str

class DeviceVerifyRequest(BaseModel):
    token: str
    canvas_hash: str
    screen_resolution: str
    timezone: str
    hardware_concurrency: int
    language: str

class IdentityRegisterRequest(BaseModel):
    user_id: str
    canvas_hash: str
    screen_resolution: str
    timezone: str
    hardware_concurrency: int
    language: str
    webgl: Optional[str] = ""
    platform: Optional[str] = ""
    ip_address: Optional[str] = ""

class IdentityVerifyLoginRequest(BaseModel):
    user_id: str
    canvas_hash: str
    screen_resolution: str
    timezone: str
    hardware_concurrency: int
    language: str
    webgl: Optional[str] = ""
    platform: Optional[str] = ""
    ip_address: Optional[str] = ""

class EncryptRequest(BaseModel):
    data: dict
    fields: list
    client_key: str

class DecryptRequest(BaseModel):
    data: dict
    fields: list
    client_key: str

class PrepareRecordRequest(BaseModel):
    data: dict
    config: dict
    client_key: str

class RiskScore(BaseModel):
    score: int
    level: str
    reasons: List[str]

class AnchorResponse(BaseModel):
    status: str
    message: str
    token: Optional[str] = None
    risk: Optional[RiskScore] = None
    did: Optional[str] = None
    action: Optional[str] = None

class SessionCreateResponse(BaseModel):
    status: str
    message: str
    pqc_token: Optional[str] = None
    session_id: Optional[str] = None
    token_type: Optional[str] = None
    expires_at: Optional[str] = None

class WebAuthnChallengeRequest(BaseModel):
    user_id: str

class WebAuthnRegisterRequest(BaseModel):
    user_id: str
    credential_id: str
    public_key: str
    challenge: str
    device_type: Optional[str] = "unknown"

class WebAuthnVerifyRequest(BaseModel):
    user_id: str
    credential_id: str
    signature: str
    challenge: str
    authenticator_data: Optional[str] = ""

class SessionEventRequest(BaseModel):
    token:       str
    action:      str
    endpoint:    str  = None
    data_volume: int  = 0
    ip_address:  str  = None
    user_agent:  str  = None
    user_role:   str  = None