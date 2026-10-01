# ============================================================
# CYBERGUARD - ACCOUNT TAKEOVER RULE ENGINE
# ============================================================

from datetime import datetime, timezone
from zoneinfo import ZoneInfo


# ============================================================
# TIMEZONE CONFIGURATION
# ============================================================

IST = ZoneInfo("Asia/Kolkata")


# ============================================================
# LOCAL LOGIN HOUR
# ============================================================

def get_local_login_hour(timestamp):
    """
    Convert the supplied timestamp to India Standard Time (IST)
    and return the local login hour.

    Naive timestamps are treated as UTC.
    Timezone-aware timestamps preserve their timezone.
    """

    # --------------------------------------------------------
    # Handle naive timestamps
    # --------------------------------------------------------

    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(
            tzinfo=timezone.utc
        )

    # --------------------------------------------------------
    # Convert timestamp to IST
    # --------------------------------------------------------

    local_timestamp = timestamp.astimezone(
        IST
    )

    return local_timestamp.hour


# ============================================================
# NORMALIZE LOCATION
# ============================================================

def normalize_location(location):
    """
    Normalize a location value for comparison.

    Empty, unknown, and unavailable locations are represented
    as an empty string.

    This is important for the VMware laboratory because private
    VMware IP addresses cannot reliably provide geographic
    location information.
    """

    if location is None:
        return ""

    normalized = str(location).strip().lower()

    if normalized in {
        "",
        "unknown",
        "unknown location",
        "unavailable",
        "n/a",
        "na",
        "none"
    }:
        return ""

    return normalized


# ============================================================
# LOGIN RULE EVALUATION
# ============================================================

def evaluate_login_rules(
    user,
    ip_address,
    location,
    device_id,
    timestamp,
    failed_attempts,
    is_new_device=False,
    is_new_ip=False
):
    """
    CyberGuard Account Takeover Detection Rule Engine.

    Evaluates:

        - New device
        - New IP address
        - Unusual location
        - Unusual login time
        - Failed login attempts

    Returns:

        rule_score
        indicators
    """

    score = 0

    indicators = []


    # ========================================================
    # 1. NEW / UNKNOWN DEVICE
    # ========================================================

    if is_new_device:

        score += 20

        indicators.append(
            "Login from a new or unknown device"
        )


    # ========================================================
    # 2. NEW IP ADDRESS
    # ========================================================

    if is_new_ip:

        score += 15

        indicators.append(
            "Login from a new IP address"
        )


    # ========================================================
    # 3. UNUSUAL LOCATION
    # ========================================================

    # --------------------------------------------------------
    # Safely retrieve user's normal/home location.
    # --------------------------------------------------------

    try:

        home_location = user["home_location"]

    except (
        KeyError,
        IndexError,
        TypeError
    ):

        home_location = None


    # --------------------------------------------------------
    # Normalize both locations.
    # --------------------------------------------------------

    normalized_login_location = normalize_location(
        location
    )

    normalized_home_location = normalize_location(
        home_location
    )


    # --------------------------------------------------------
    # IMPORTANT:
    #
    # Unknown / unavailable location is NOT treated as a new
    # geographic location.
    #
    # This prevents VMware private IP addresses from causing
    # false "unusual location" detections.
    # --------------------------------------------------------

    if (
        normalized_login_location
        and normalized_home_location
        and normalized_login_location
        != normalized_home_location
    ):

        score += 20

        indicators.append(
            "Login from an unusual location"
        )


    # ========================================================
    # 4. UNUSUAL LOGIN TIME
    # ========================================================

    # --------------------------------------------------------
    # Convert timestamp to IST before checking login hours.
    # --------------------------------------------------------

    login_hour = get_local_login_hour(
        timestamp
    )


    # --------------------------------------------------------
    # Default normal login window
    # --------------------------------------------------------

    normal_start = 6
    normal_end = 22


    # --------------------------------------------------------
    # User-specific login start time
    # --------------------------------------------------------

    try:

        if user["usual_login_start"] is not None:

            normal_start = int(
                user["usual_login_start"]
            )

    except (
        KeyError,
        IndexError,
        TypeError,
        ValueError
    ):

        pass


    # --------------------------------------------------------
    # User-specific login end time
    # --------------------------------------------------------

    try:

        if user["usual_login_end"] is not None:

            normal_end = int(
                user["usual_login_end"]
            )

    except (
        KeyError,
        IndexError,
        TypeError,
        ValueError
    ):

        pass


    # --------------------------------------------------------
    # Check login time
    # --------------------------------------------------------

    if not (
        normal_start
        <= login_hour
        <= normal_end
    ):

        score += 15

        indicators.append(
            "Login occurred outside the user's normal login hours"
        )


    # ========================================================
    # 5. RECENT FAILED LOGIN ATTEMPTS
    # ========================================================

    if failed_attempts >= 3:

        score += 15

        indicators.append(
            f"{failed_attempts} recent failed login attempts detected"
        )


    # ========================================================
    # 6. MULTIPLE FAILED ATTEMPTS
    # ========================================================

    if failed_attempts >= 5:

        score += 15

        indicators.append(
            "Multiple consecutive authentication failures"
        )


    # ========================================================
    # LIMIT SCORE
    # ========================================================

    score = min(
        score,
        100
    )


    # ========================================================
    # RETURN RESULT
    # ========================================================

    return score, indicators