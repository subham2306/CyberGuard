from typing import Any


def _normalize(value: Any) -> str:
    return str(value or "").strip().lower()


def _collect_text(result: dict) -> str:
    parts = []

    for key in ("threat_type", "prediction", "decision", "severity"):
        parts.append(_normalize(result.get(key)))

    indicators = result.get("indicators", [])
    if isinstance(indicators, list):
        parts.extend(_normalize(item) for item in indicators)

    explanation = result.get("explanation", [])
    if isinstance(explanation, list):
        parts.extend(_normalize(item) for item in explanation)
    elif explanation:
        parts.append(_normalize(explanation))

    return " ".join(parts)


def _severity_for_risk(risk: float) -> str:
    if risk >= 80:
        return "CRITICAL"
    if risk >= 60:
        return "HIGH"
    if risk >= 40:
        return "MEDIUM"
    if risk > 0:
        return "LOW"
    return "SAFE"


def _decision_for_risk(risk: float) -> str:
    if risk >= 80:
        return "BLOCK"
    if risk >= 60:
        return "MFA_REQUIRED"
    if risk >= 40:
        return "MONITOR"
    return "ALLOW"


def correlate_results(results: list[dict]) -> dict:
    if not results:
        return {
            "correlated": False,
            "risk_score": 0,
            "severity": "SAFE",
            "decision": "ALLOW",
            "threat_types": [],
            "module_count": 0,
            "correlation_bonus": 0,
            "correlation_factors": [],
            "chain_detected": False,
            "credential_chain_detected": False,
            "indicators": [],
            "explanation": ["No detection results available."],
        }

    threat_types = []
    indicators = []
    explanations = []
    module_risks = {}
    texts = []

    for result in results:
        threat_type = _normalize(result.get("threat_type"))

        if threat_type and threat_type not in threat_types:
            threat_types.append(threat_type)

        risk = result.get("risk_score", 0)

        if isinstance(risk, (int, float)):
            risk = float(risk)
            module_risks[threat_type or f"module_{len(module_risks) + 1}"] = risk

        result_indicators = result.get("indicators", [])
        if isinstance(result_indicators, list):
            indicators.extend(result_indicators)

        explanation = result.get("explanation")
        if isinstance(explanation, list):
            explanations.extend(str(item) for item in explanation)
        elif explanation:
            explanations.append(str(explanation))

        texts.append(_collect_text(result))

    threat_set = set(threat_types)
    combined_text = " ".join(texts)

    max_risk = max(
        [float(r) for r in module_risks.values()],
        default=0,
    )

    correlation_bonus = 0
    correlation_factors = []

    # Independent module correlation
    if len(threat_types) >= 2:
        correlation_bonus += 8
        correlation_factors.append(
            "Multiple independent CyberGuard detection modules triggered."
        )

    if len(threat_types) >= 3:
        correlation_bonus += 4
        correlation_factors.append(
            "All three primary CyberGuard threat domains are involved."
        )

    # Full attack-chain detection
    full_chain = {
        "phishing",
        "digital_impersonation",
        "account_takeover",
    }.issubset(threat_set)

    if full_chain:
        correlation_bonus += 15
        correlation_factors.append(
            "Phishing → digital impersonation → account takeover attack chain detected."
        )

    # Credential-theft indicators
    credential_keywords = (
        "credential",
        "password",
        "otp",
        "one-time password",
        "login",
        "account takeover",
        "credential request",
        "authentication",
        "sensitive request",
    )

    credential_chain = any(
        keyword in combined_text for keyword in credential_keywords
    )

    if credential_chain:
        correlation_bonus += 5
        correlation_factors.append(
            "Cross-module credential or authentication indicators detected."
        )

    correlated_risk = min(100, max_risk + correlation_bonus)

    # A critical individual module remains critical.
    critical_module = any(
        isinstance(result.get("risk_score"), (int, float))
        and float(result.get("risk_score")) >= 80
        for result in results
    )

    if critical_module:
        correlated_risk = max(correlated_risk, 80)

    severity = _severity_for_risk(correlated_risk)
    decision = _decision_for_risk(correlated_risk)

    if critical_module:
        decision = "BLOCK"

    correlated = len(threat_types) >= 2

    if correlated:
        correlation_message = (
            "Multiple CyberGuard modules detected related security threats: "
            + ", ".join(threat_types)
            + "."
        )
    else:
        correlation_message = "No multi-module threat correlation detected."

    return {
        "correlated": correlated,
        "risk_score": round(correlated_risk, 2),
        "severity": severity,
        "decision": decision,
        "threat_types": threat_types,
        "module_count": len(threat_types),
        "module_risks": module_risks,
        "max_module_risk": round(max_risk, 2),
        "correlation_bonus": correlation_bonus,
        "correlation_factors": correlation_factors,
        "chain_detected": full_chain,
        "credential_chain_detected": credential_chain,
        "indicators": indicators,
        "explanation": [
            correlation_message,
            *correlation_factors,
            *explanations,
        ],
    }
