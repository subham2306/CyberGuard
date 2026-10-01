from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ImpersonationRequest(BaseModel):
    sender_name: str = ""
    sender_email: str
    receiver_name: str = ""
    receiver_email: str = ""
    reply_to: str = ""
    date_time: Optional[str] = None
    subject: str = ""
    message: str = ""


class ImpersonationResponse(BaseModel):
    prediction: str
    risk_score: float
    risk_level: str

    legitimate_probability: float
    impersonation_probability: float

    attack_type: Optional[str] = None
    attack_type_confidence: Optional[float] = None
    top3_attack_types: List[Any] = Field(default_factory=list)

    behavioral_status: str
    behavioral_score: Optional[float] = None
    behavior_details: Dict[str, Any] = Field(default_factory=dict)

    indicators: List[str] = Field(default_factory=list)
    explanation: List[str] = Field(default_factory=list)
    recommended_actions: List[str] = Field(default_factory=list)
