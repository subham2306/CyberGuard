from fastapi import FastAPI
from app.gateway import router


app = FastAPI(
    title="CyberGuard Sentinel",
    description="Unified Cyber Threat Detection and Response Gateway",
    version="1.0.0",
)


@app.get("/")
def root():
    return {
        "service": "CyberGuard Sentinel",
        "status": "online",
        "version": "1.0.0",
    }


@app.get("/health")
def health():
    return {
        "status": "online",
        "service": "cyberguard-sentinel",
        "modules": {
            "phishing": "Pilu",
            "digital_impersonation": "Abhijit",
            "account_takeover": "Subham",
        },
    }


app.include_router(router)
