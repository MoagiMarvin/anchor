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

class RiskScore(BaseModel):
    score: int
    level: str
    reasons: List[str]

class AnchorResponse(BaseModel):
    status: str
    message: str
    token: Optional[str] = None
    risk: Optional[RiskScore] = None