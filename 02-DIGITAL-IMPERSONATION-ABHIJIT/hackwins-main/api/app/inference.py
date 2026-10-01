import re
from datetime import datetime
from email.utils import parseaddr

from .model_loader import load_models


MODELS = load_models()


PUBLIC_EMAIL_DOMAINS = {
    "gmail.com",
    "yahoo.com",
    "outlook.com",
    "hotmail.com",
    "proton.me",
    "protonmail.com",
    "icloud.com",
}


URGENCY_WORDS = [
    "urgent",
    "immediately",
    "as soon as possible",
    "right away",
    "within",
    "suspended",
    "suspension",
    "today",
    "now",
]


SENSITIVE_WORDS = [
    "password",
    "login credentials",
    "credential",
    "verification code",
    "otp",
    "pin",
    "account details",
    "bank details",
    "financial information",
]


ATTACHMENT_EXTENSIONS = [
    ".pdf",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".zip",
    ".rar",
    ".exe",
]


def extract_domain(value: str) -> str:
    if not value:
        return ""

    _, address = parseaddr(value)
    address = address.strip().lower()

    if "@" not in address:
        return ""

    return address.split("@", 1)[1]


def parse_datetime(value):
    if not value:
        return datetime.now()

    if isinstance(value, datetime):
        return value

    value = str(value).strip()

    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(
            tzinfo=None
        )
    except ValueError:
        pass

    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%d-%m-%Y %H:%M:%S",
        "%d-%m-%Y %H:%M",
        "%d/%m/%Y %H:%M:%S",
        "%d/%m/%Y %H:%M",
    ]

    for fmt in formats:
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue

    return datetime.now()


def find_identity(sender_name, sender_email):
    """
    Look up the sender in Model 3's stored identity profiles.

    The behavioral model stores identity profiles in dataset3_profiles.
    """
    profiles = MODELS["model_3"].get("dataset3_profiles")

    if profiles is None:
        return {
            "found": False,
            "ambiguous": False,
            "identity_id": None,
            "identity_name": None,
            "organization": None,
            "official_domain": None,
        }

    sender_email = (sender_email or "").strip().lower()
    sender_name = (sender_name or "").strip().lower()

    try:
        matches = profiles[
            profiles["official_email"]
            .astype(str)
            .str.strip()
            .str.lower()
            == sender_email
        ]
    except Exception:
        return {
            "found": False,
            "ambiguous": False,
            "identity_id": None,
            "identity_name": None,
            "organization": None,
            "official_domain": None,
        }

    if len(matches) == 0:
        return {
            "found": False,
            "ambiguous": False,
            "identity_id": None,
            "identity_name": None,
            "organization": None,
            "official_domain": None,
        }

    if len(matches) > 1 and sender_name:
        name_matches = matches[
            matches["identity_name"]
            .astype(str)
            .str.strip()
            .str.lower()
            == sender_name
        ]

        if len(name_matches) == 1:
            matches = name_matches

    ambiguous = len(matches) > 1
    row = matches.iloc[0]

    def get_value(column):
        if column in row.index:
            value = row[column]
            if value is not None:
                return str(value)
        return None

    identity_id = get_value("identity_id")

    return {
        "found": True,
        "ambiguous": ambiguous,
        "identity_id": identity_id,
        "identity_name": get_value("identity_name"),
        "organization": get_value("organization"),
        "official_domain": get_value("official_domain"),
    }


def calculate_risk(
    impersonation_probability,
    identity_found,
    identity_ambiguous,
    domain_matches,
    reply_to_matches,
    public_email,
    urgency_detected,
    sensitive_request_detected,
    behavioral_score,
):
    contributions = {}

    contributions["Model 1 impersonation"] = (
        impersonation_probability * 25
    )

    contributions["Unknown / ambiguous identity"] = (
        10 if (not identity_found or identity_ambiguous) else 0
    )

    contributions["Domain mismatch"] = (
        25 if identity_found and not identity_ambiguous and not domain_matches else 0
    )

    contributions["Reply-To mismatch"] = (
        15 if not reply_to_matches else 0
    )

    contributions["Public email"] = (
        10 if public_email else 0
    )

    contributions["Urgency"] = (
        15 if urgency_detected else 0
    )

    contributions["Sensitive information request"] = (
        20 if sensitive_request_detected else 0
    )

    contributions["Behavioral anomaly"] = (
        (behavioral_score or 0) * 15
    )

    risk_score = min(100.0, sum(contributions.values()))

    if risk_score <= 20:
        risk_level = "SAFE"
    elif risk_score <= 40:
        risk_level = "LOW"
    elif risk_score <= 60:
        risk_level = "MEDIUM"
    elif risk_score <= 80:
        risk_level = "HIGH"
    else:
        risk_level = "CRITICAL"

    return round(risk_score, 2), risk_level, contributions


def analyze_message(data):
    model_1 = MODELS["model_1"]
    tfidf_1 = MODELS["tfidf_1"]

    model_2 = MODELS["model_2"]
    tfidf_2 = MODELS["tfidf_2"]

    model_3 = MODELS["model_3"]

    sender_name = data.sender_name or ""
    sender_email = data.sender_email or ""
    receiver_name = data.receiver_name or ""
    receiver_email = data.receiver_email or ""
    reply_to = data.reply_to or ""
    subject = data.subject or ""
    message = data.message or ""

    dt = parse_datetime(data.date_time)

    text_input = f"{subject} {message}".strip()

    sender_domain = extract_domain(sender_email)
    reply_to_domain = extract_domain(reply_to)
    receiver_domain = extract_domain(receiver_email)

    message_length = len(message)

    current_hour = dt.hour

    if 6 <= current_hour < 12:
        current_period = "morning"
    elif 12 <= current_hour < 17:
        current_period = "afternoon"
    elif 17 <= current_hour < 21:
        current_period = "evening"
    else:
        current_period = "night"

    current_day = dt.strftime("%A")

    identity = find_identity(sender_name, sender_email)

    identity_found = identity["found"]
    identity_ambiguous = identity["ambiguous"]

    official_domain = identity["official_domain"]

    # ---------------------------------------------------------
    # MODEL 1 — IMPERSONATION
    # ---------------------------------------------------------

    X_m1 = tfidf_1.transform([text_input])

    m1_probabilities = model_1.predict_proba(X_m1)[0]

    class_to_probability = {
        int(cls): float(prob)
        for cls, prob in zip(
            model_1.classes_,
            m1_probabilities,
        )
    }

    legitimate_probability = class_to_probability.get(0, 0.0)
    impersonation_probability = class_to_probability.get(1, 0.0)

    model1_prediction = (
        "IMPERSONATION"
        if impersonation_probability >= 0.5
        else "LEGITIMATE"
    )

    # ---------------------------------------------------------
    # MODEL 2 — ATTACK TYPE
    # ---------------------------------------------------------

    X_m2 = tfidf_2.transform([text_input])

    m2_probabilities = model_2.predict_proba(X_m2)[0]

    m2_index = m2_probabilities.argmax()

    model2_prediction = str(model_2.classes_[m2_index])
    model2_confidence = float(m2_probabilities[m2_index])

    top3_indices = m2_probabilities.argsort()[-3:][::-1]

    top3_attacks = [
        {
            "attack_type": str(model_2.classes_[i]),
            "probability": round(float(m2_probabilities[i]), 4),
        }
        for i in top3_indices
    ]

    # ---------------------------------------------------------
    # MODEL 3 — BEHAVIOR
    # ---------------------------------------------------------

    model3_status = "UNKNOWN"
    model3_score = None

    behavior_details = {
        "time_match": None,
        "day_match": None,
        "domain_match": None,
        "length_match": None,
        "length_ratio": None,
    }

    if identity_found and not identity_ambiguous:
        profiles = model_3["dataset3_profiles"]
        weights = model_3["weights"]

        profile_matches = profiles[
            profiles["identity_id"].astype(str)
            == str(identity["identity_id"])
        ]

        if len(profile_matches) > 0:
            profile = profile_matches.iloc[0]

            usual_hours = str(profile["usual_hours"]).lower()

            time_match = current_period.lower() in usual_hours

            usual_days = str(profile["usual_days"]).lower()

            if "all days" in usual_days:
                day_match = True
            elif "weekdays" in usual_days:
                day_match = current_day not in ["Saturday", "Sunday"]
            else:
                day_match = current_day.lower() in usual_days

            behavior_domain = str(
                profile["usual_sender_domain"]
            ).strip().lower()

            domain_match = (
                sender_domain == behavior_domain
            )

            avg_length = float(
                profile["avg_message_length"]
            )

            if avg_length > 0:
                length_ratio = message_length / avg_length
                length_match = 0.5 <= length_ratio <= 1.5
            else:
                length_ratio = None
                length_match = False

            model3_score = (
                weights["time_of_day"] * (0 if time_match else 1)
                + weights["day_of_week"] * (0 if day_match else 1)
                + weights["sender_domain"] * (0 if domain_match else 1)
                + weights["message_length"] * (0 if length_match else 1)
            )

            model3_status = (
                "ANOMALOUS"
                if model3_score >= 0.5
                else "NORMAL"
            )

            behavior_details = {
                "time_match": time_match,
                "day_match": day_match,
                "domain_match": domain_match,
                "length_match": length_match,
                "length_ratio": (
                    round(length_ratio, 3)
                    if length_ratio is not None
                    else None
                ),
            }

    # ---------------------------------------------------------
    # TECHNICAL SIGNALS
    # ---------------------------------------------------------

    public_email = sender_domain in PUBLIC_EMAIL_DOMAINS

    if identity_found and not identity_ambiguous:
        sender_domain_matches_identity = (
            sender_domain == str(official_domain).lower()
        )
    else:
        sender_domain_matches_identity = None

    if reply_to:
        reply_to_matches_sender = (
            reply_to_domain == sender_domain
        )
    else:
        reply_to_matches_sender = True

    lower_text = text_input.lower()

    urgency_detected = any(
        word in lower_text
        for word in URGENCY_WORDS
    )

    sensitive_request_detected = any(
        word in lower_text
        for word in SENSITIVE_WORDS
    )

    links = re.findall(
        r"https?://[^\s]+|www\.[^\s]+",
        text_input,
        flags=re.IGNORECASE,
    )

    has_link = len(links) > 0

    has_attachment = any(
        ext in lower_text
        for ext in ATTACHMENT_EXTENSIONS
    )

    # ---------------------------------------------------------
    # RISK
    # ---------------------------------------------------------

    risk_score, risk_level, contributions = calculate_risk(
        impersonation_probability=impersonation_probability,
        identity_found=identity_found,
        identity_ambiguous=identity_ambiguous,
        domain_matches=(
            sender_domain_matches_identity
            if sender_domain_matches_identity is not None
            else False
        ),
        reply_to_matches=reply_to_matches_sender,
        public_email=public_email,
        urgency_detected=urgency_detected,
        sensitive_request_detected=sensitive_request_detected,
        behavioral_score=model3_score,
    )

    # ---------------------------------------------------------
    # INDICATORS
    # ---------------------------------------------------------

    indicators = []

    if model1_prediction == "IMPERSONATION":
        indicators.append(
            "Model 1 detected impersonation characteristics."
        )

    if not identity_found:
        indicators.append(
            "Sender identity could not be matched to a known professional identity."
        )

    elif identity_ambiguous:
        indicators.append(
            "Multiple identity records matched the sender email."
        )

    if sender_domain_matches_identity is False:
        indicators.append(
            "Sender domain does not match the official identity domain."
        )

    if not reply_to_matches_sender:
        indicators.append(
            "Reply-To domain does not match the sender domain."
        )

    if public_email:
        indicators.append(
            "Sender uses a public email provider."
        )

    if urgency_detected:
        indicators.append(
            "Urgency-related language detected."
        )

    if sensitive_request_detected:
        indicators.append(
            "Sensitive credential or financial information request detected."
        )

    if has_link:
        indicators.append(
            f"External link detected ({len(links)} link(s))."
        )

    if has_attachment:
        indicators.append(
            "Attachment-related file extension detected."
        )

    if model3_status == "ANOMALOUS":
        indicators.append(
            "Sender behavior differs from the stored identity profile."
        )

    # ---------------------------------------------------------
    # EXPLANATION
    # ---------------------------------------------------------

    explanation = [
        f"Model 1 classification: {model1_prediction}.",
        f"Impersonation probability: {impersonation_probability:.2%}.",
        f"Model 2 likely attack type: {model2_prediction}.",
        f"Behavioral status: {model3_status}.",
        f"Final engineering risk score: {risk_score}/100.",
    ]

    # ---------------------------------------------------------
    # RECOMMENDATIONS
    # ---------------------------------------------------------

    if risk_level == "CRITICAL":
        recommended_actions = [
            "Block or quarantine the message.",
            "Do not click links or open suspicious attachments.",
            "Verify the sender through an independent trusted channel.",
        ]
    elif risk_level == "HIGH":
        recommended_actions = [
            "Require additional verification.",
            "Avoid clicking links or opening suspicious attachments.",
            "Verify the sender through an independent trusted channel.",
        ]
    elif risk_level == "MEDIUM":
        recommended_actions = [
            "Monitor the message and verify the sender if sensitive action is requested.",
        ]
    elif risk_level == "LOW":
        recommended_actions = [
            "Allow with monitoring.",
        ]
    else:
        recommended_actions = [
            "Allow the message.",
        ]

    return {
        "prediction": model1_prediction,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "legitimate_probability": round(legitimate_probability, 6),
        "impersonation_probability": round(impersonation_probability, 6),
        "attack_type": model2_prediction,
        "attack_type_confidence": round(model2_confidence, 6),
        "top3_attack_types": top3_attacks,
        "behavioral_status": model3_status,
        "behavioral_score": (
            round(float(model3_score), 6)
            if model3_score is not None
            else None
        ),
        "behavior_details": behavior_details,
        "indicators": indicators,
        "explanation": explanation,
        "recommended_actions": recommended_actions,
        "technical_signals": {
            "sender_domain": sender_domain,
            "receiver_domain": receiver_domain,
            "reply_to_domain": reply_to_domain,
            "public_email": public_email,
            "sender_domain_matches_identity": sender_domain_matches_identity,
            "reply_to_matches_sender": reply_to_matches_sender,
            "urgency_detected": urgency_detected,
            "sensitive_request_detected": sensitive_request_detected,
            "has_link": has_link,
            "links": links,
            "has_attachment": has_attachment,
        },
        "identity": {
            "found": identity_found,
            "ambiguous": identity_ambiguous,
            "identity_id": identity["identity_id"],
            "identity_name": identity["identity_name"],
            "organization": identity["organization"],
            "official_domain": identity["official_domain"],
        },
        "risk_contributions": contributions,
    }
