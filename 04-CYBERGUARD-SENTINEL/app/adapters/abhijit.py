import requests


ABHIJIT_BASE_URL = "http://127.0.0.1:8002"
TIMEOUT = 10


def analyze_message(
    sender_name: str,
    sender_email: str,
    receiver_name: str = "",
    receiver_email: str = "",
    reply_to: str = "",
    date_time: str = "",
    subject: str = "",
    message: str = "",
):
    """Send an email/message to Abhijit's impersonation detector."""

    payload = {
        "sender_name": sender_name,
        "sender_email": sender_email,
        "receiver_name": receiver_name,
        "receiver_email": receiver_email,
        "reply_to": reply_to,
        "date_time": date_time or None,
        "subject": subject,
        "message": message,
    }

    try:
        response = requests.post(
            f"{ABHIJIT_BASE_URL}/api/v1/detect",
            json=payload,
            timeout=TIMEOUT,
        )

        response.raise_for_status()
        result = response.json()

        return {
            "source": "abhijit",
            "threat_type": "digital_impersonation",
            "risk_score": result.get("risk_score", 0),
            "severity": result.get("risk_level", "UNKNOWN"),
            "decision": (
                "BLOCK"
                if result.get("risk_level") == "CRITICAL"
                else "MONITOR"
            ),
            "confidence": result.get(
                "impersonation_probability",
                0,
            ),
            "prediction": result.get("prediction"),
            "attack_type": result.get("attack_type"),
            "attack_type_confidence": result.get(
                "attack_type_confidence"
            ),
            "behavioral_status": result.get(
                "behavioral_status"
            ),
            "behavioral_score": result.get(
                "behavioral_score"
            ),
            "indicators": result.get("indicators", []),
            "explanation": result.get("explanation", []),
            "recommended_actions": result.get(
                "recommended_actions",
                [],
            ),
            "raw_response": result,
        }

    except requests.exceptions.RequestException as exc:
        return {
            "source": "abhijit",
            "threat_type": "digital_impersonation",
            "risk_score": 0,
            "severity": "UNKNOWN",
            "decision": "SERVICE_UNAVAILABLE",
            "confidence": 0,
            "prediction": None,
            "attack_type": None,
            "attack_type_confidence": None,
            "behavioral_status": "UNKNOWN",
            "behavioral_score": None,
            "indicators": [],
            "explanation": [
                f"Abhijit service unavailable: {exc}"
            ],
            "recommended_actions": [
                "Check whether the Abhijit API is running on port 8002."
            ],
            "raw_response": {},
        }

    except ValueError as exc:
        return {
            "source": "abhijit",
            "threat_type": "digital_impersonation",
            "risk_score": 0,
            "severity": "UNKNOWN",
            "decision": "INVALID_RESPONSE",
            "confidence": 0,
            "prediction": None,
            "attack_type": None,
            "attack_type_confidence": None,
            "behavioral_status": "UNKNOWN",
            "behavioral_score": None,
            "indicators": [],
            "explanation": [
                f"Abhijit returned invalid JSON: {exc}"
            ],
            "recommended_actions": [
                "Check the Abhijit API response."
            ],
            "raw_response": {},
        }
