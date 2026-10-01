from fastapi import FastAPI, HTTPException

from .inference import analyze_message
from .schemas import ImpersonationRequest, ImpersonationResponse


app = FastAPI(
    title="CyberGuard Digital Impersonation Detection API",
    version="1.0.0",
    description="CyberGuard digital impersonation detection service using Abhijit's ML models.",
)


@app.get("/health")
def health():
    return {
        "status": "online",
        "module": "digital_impersonation",
        "model_1": "active",
        "model_2": "active",
        "model_3": "active",
    }


@app.post(
    "/api/v1/detect",
    response_model=ImpersonationResponse,
)
def detect(request: ImpersonationRequest):
    try:
        return analyze_message(request)
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Detection failed: {str(exc)}",
        )


@app.get("/")
def root():
    return {
        "service": "CyberGuard Digital Impersonation Detection",
        "status": "online",
        "docs": "/docs",
    }
