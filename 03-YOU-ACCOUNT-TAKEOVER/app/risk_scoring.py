def calculate_risk(rule_score: float, ml_score: float = 0):
    """
    Calculate final ATO risk score.

    Currently rules are the primary detector.
    ML score will be integrated later.
    """

    final_score = (
        0.70 * rule_score +
        0.30 * ml_score
    )

    return round(min(max(final_score, 0), 100), 2)


def get_severity(score: float):

    if score <= 20:
        return "Safe"

    elif score <= 40:
        return "Low"

    elif score <= 60:
        return "Medium"

    elif score <= 80:
        return "High"

    else:
        return "Critical"


def get_decision(score: float):

    if score <= 40:
        return "ALLOW"

    elif score <= 60:
        return "MONITOR"

    elif score <= 80:
        return "MFA_REQUIRED"

    else:
        return "BLOCK"