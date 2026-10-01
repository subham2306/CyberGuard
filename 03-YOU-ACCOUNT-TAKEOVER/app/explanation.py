def generate_explanation(
    username,
    risk_score,
    severity,
    indicators
):

    if not indicators:

        return (
            f"Login behaviour for {username} appears consistent "
            f"with the user's normal profile."
        )

    reasons = "; ".join(indicators)

    return (
        f"CyberGuard classified this login as {severity} risk "
        f"with a score of {risk_score}/100 because: {reasons}."
    )