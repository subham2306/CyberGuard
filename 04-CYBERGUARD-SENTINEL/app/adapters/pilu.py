import requests


PILU_BASE_URL = "http://127.0.0.1:8001"
TIMEOUT = 10


def analyze_message(sender: str, message: str, subject: str = ""):
    """Send a message to Pilu's phishing detection service."""

    text_parts = []

    if sender:
        text_parts.append(f"Sender: {sender}")

    if subject:
        text_parts.append(f"Subject: {subject}")

    if message:
        text_parts.append(f"Message: {message}")

    payload = {
        "text": "\n".join(text_parts),
        "channel": "EMAIL",
    }

    try:
        response = requests.post(
            f"{PILU_BASE_URL}/api/v1/detect",
            json=payload,
            timeout=TIMEOUT,
        )

        response.raise_for_status()
        result = response.json()

        return {
            "source": "pilu",
            "threat_type": "phishing",
            "risk_score": result.get("risk_score", 0),
            "severity": result.get("severity", "UNKNOWN"),
            "decision": result.get(
                "decision",
                result.get("action", "MONITOR"),
            ),
            "confidence": result.get(
                "calibrated_probability",
                result.get(
                    "malicious_probability",
                    result.get("confidence", 0),
                ),
            ),
            "prediction": result.get("prediction"),
            "indicators": result.get("indicators", []),
            "explanation": result.get("explanation", []),
            "recommended_actions": (
                result.get("recommended_actions")
                or [result.get("recommendation")]
                if result.get("recommendation")
                else []
            ),
            "raw_response": result,
        }

    except requests.exceptions.RequestException as exc:
        return {
            "source": "pilu",
            "threat_type": "phishing",
            "risk_score": 0,
            "severity": "UNKNOWN",
            "decision": "SERVICE_UNAVAILABLE",
            "confidence": 0,
            "prediction": None,
            "indicators": [],
            "explanation": [
                f"Pilu service unavailable: {exc}"
            ],
            "recommended_actions": [
                "Check whether the Pilu API is running on port 8001."
            ],
            "raw_response": {},
        }

    except ValueError as exc:
        return {
            "source": "pilu",
            "threat_type": "phishing",
            "risk_score": 0,
            "severity": "UNKNOWN",
            "decision": "INVALID_RESPONSE",
            "confidence": 0,
            "prediction": None,
            "indicators": [],
            "explanation": [
                f"Pilu returned invalid JSON: {exc}"
            ],
            "recommended_actions": [
                "Check the Pilu API response."
            ],
            "raw_response": {},
        }
