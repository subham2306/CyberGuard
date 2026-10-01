from typing import Optional, Dict, Any
from pydantic import BaseModel


class AnalyzeRequest(BaseModel):
    type: str
    username: Optional[str] = None
    password: Optional[str] = None
    ip_address: Optional[str] = None
    location: Optional[str] = None
    device_id: Optional[str] = None
    user_agent: Optional[str] = "CyberGuard-Sentinel"

    sender: Optional[str] = None
    message: Optional[str] = None
    subject: Optional[str] = ""

    sender_name: Optional[str] = None
    sender_email: Optional[str] = None
    receiver_name: Optional[str] = ""
    receiver_email: Optional[str] = ""
    reply_to: Optional[str] = ""
    date_time: Optional[str] = None


class AnalyzeResponse(BaseModel):
    source: str
    threat_type: str
    risk_score: float
    severity: str
    decision: str
    confidence: Optional[float] = None
    indicators: list = []
    explanation: Any = None
    recommended_actions: list = []
    raw_response: Optional[Dict[str, Any]] = None


class CorrelationRequest(BaseModel):
    results: list[Dict[str, Any]]
