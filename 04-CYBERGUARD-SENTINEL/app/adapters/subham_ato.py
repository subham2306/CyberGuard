import requests

ATO_BASE_URL = "http://127.0.0.1:8000"
TIMEOUT = 10


def analyze_login(
    username: str,
    password: str,
    ip_address: str,
    location: str,
    device_id: str,
    user_agent: str = "CyberGuard-Sentinel",
):
    payload = {
        "username": username,
        "password": password,
        "ip_address": ip_address,
        "location": location,
        "device_id": device_id,
        "user_agent": user_agent,
    }

    try:
        response = requests.post(
            f"{ATO_BASE_URL}/login",
            json=payload,
            timeout=TIMEOUT,
        )
        response.raise_for_status()
        result = response.json()

        ml_detection = result.get("ml_detection", {})

        return {
            "source": "ato",
            "threat_type": result.get(
                "threat_type",
                "account_takeover",
            ),
            "event_id": result.get("event_id"),
            "risk_score": result.get("risk_score", 0),
            "severity": result.get("severity", "UNKNOWN"),
            "decision": result.get("decision", "MONITOR"),

            # ATO does not provide a probability-style confidence value.
            "confidence": None,
            "ml_risk_score": ml_detection.get(
                "ml_risk_score",
                0,
            ),

            "login": result.get("login"),
            "failed_attempts": result.get(
                "failed_attempts_last_10_minutes",
                0,
            ),
            "new_ip": result.get("new_ip", False),
            "new_device": result.get("new_device", False),
            "new_location": result.get("new_location", False),

            "rule_detection": result.get(
                "rule_detection",
                {},
            ),
            "ml_detection": ml_detection,

            "password_spraying": result.get(
                "password_spraying",
                {},
            ),
            "blocklist": result.get(
                "blocklist",
                {},
            ),

            "indicators": result.get(
                "indicators",
                [],
            ),
            "explanation": result.get(
                "explanation",
                "",
            ),
            "recommended_actions": result.get(
                "recommended_actions",
                [],
            ),

            "raw_response": result,
        }

    except requests.exceptions.RequestException as exc:
        return {
            "source": "ato",
            "threat_type": "account_takeover",
            "risk_score": 0,
            "severity": "SERVICE_UNAVAILABLE",
            "decision": "MONITOR",
            "confidence": None,
            "ml_risk_score": 0,
            "indicators": [
                "ATO service unavailable"
            ],
            "explanation": str(exc),
            "recommended_actions": [
                "Check the ATO service on port 8000."
            ],
        }

    except ValueError as exc:
        return {
            "source": "ato",
            "threat_type": "account_takeover",
            "risk_score": 0,
            "severity": "INVALID_RESPONSE",
            "decision": "MONITOR",
            "confidence": None,
            "ml_risk_score": 0,
            "indicators": [
                "Invalid response received from ATO service"
            ],
            "explanation": str(exc),
            "recommended_actions": [
                "Check the ATO API response."
            ],
        }
