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