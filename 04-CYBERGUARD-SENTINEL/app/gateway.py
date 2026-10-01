from fastapi import APIRouter, HTTPException

from app.schemas import AnalyzeRequest, CorrelationRequest
from app.adapters.pilu import analyze_message as analyze_phishing
from app.adapters.abhijit import analyze_message as analyze_impersonation
from app.adapters.subham_ato import analyze_login as analyze_ato
from app.risk_correlation import correlate_results

router = APIRouter()


@router.post("/api/v1/analyze")
def analyze(request: AnalyzeRequest):
    request_type = request.type.lower().strip()

    if request_type == "message":
        if not request.message:
            raise HTTPException(
                status_code=400,
                detail="message is required for type='message'"
            )

        return analyze_phishing(
            sender=request.sender or "",
            message=request.message,
            subject=request.subject or "",
        )

    if request_type == "identity":
        if not request.sender_email:
            raise HTTPException(
                status_code=400,
                detail="sender_email is required for type='identity'"
            )

        return analyze_impersonation(
            sender_name=request.sender_name or "",
            sender_email=request.sender_email,
            receiver_name=request.receiver_name or "",
            receiver_email=request.receiver_email or "",
            reply_to=request.reply_to or "",
            date_time=request.date_time or "",
            subject=request.subject or "",
            message=request.message or "",
        )

    if request_type == "login":
        required_fields = {
            "username": request.username,
            "password": request.password,
            "ip_address": request.ip_address,
            "location": request.location,
            "device_id": request.device_id,
        }

        missing = [
            field
            for field, value in required_fields.items()
            if value is None
        ]

        if missing:
            raise HTTPException(
                status_code=400,
                detail=f"Missing required login fields: {', '.join(missing)}"
            )

        return analyze_ato(
            username=request.username,
            password=request.password,
            ip_address=request.ip_address,
            location=request.location,
            device_id=request.device_id,
            user_agent=request.user_agent or "CyberGuard-Sentinel",
        )

    raise HTTPException(
        status_code=400,
        detail="Unsupported type. Use: message, identity, or login."
    )


@router.post("/api/v1/correlate")
def correlate(request: CorrelationRequest):
    if not request.results:
        raise HTTPException(
            status_code=400,
            detail="At least one detection result is required."
        )

    return correlate_results(request.results)
