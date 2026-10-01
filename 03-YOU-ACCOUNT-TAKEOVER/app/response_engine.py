def generate_response(decision):

    if decision == "ALLOW":

        return [
            "Allow authentication"
        ]

    if decision == "MONITOR":

        return [
            "Allow authentication",
            "Monitor user activity"
        ]

    if decision == "MFA_REQUIRED":

        return [
            "Require additional authentication",
            "Monitor user session"
        ]

    if decision == "BLOCK":

        return [
            "Block authentication",
            "Revoke suspicious session",
            "Require password reset",
            "Require MFA",
            "Notify security administrator"
        ]

    return [
        "Investigate event"
    ]