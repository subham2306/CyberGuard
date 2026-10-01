from datetime import datetime, timezone, timedelta


# ============================================================
# CYBERGUARD CONTROLLED IP BLOCKLIST
# ============================================================

BLOCKED_IPS = {}


# ============================================================
# BLOCK IP
# ============================================================

def block_ip(
    ip_address: str,
    reason: str,
    duration_minutes: int = 15
):
    """
    Add an IP address to the CyberGuard application-level
    blocklist.

    This does NOT modify the operating system firewall.
    """

    blocked_until = (
        datetime.now(timezone.utc)
        + timedelta(minutes=duration_minutes)
    )

    BLOCKED_IPS[ip_address] = {
        "ip_address": ip_address,
        "reason": reason,
        "blocked_at": datetime.now(timezone.utc).isoformat(),
        "blocked_until": blocked_until.isoformat()
    }

    return BLOCKED_IPS[ip_address]


# ============================================================
# CHECK WHETHER IP IS BLOCKED
# ============================================================

def is_ip_blocked(ip_address: str):
    """
    Check whether an IP is currently blocked.
    """

    entry = BLOCKED_IPS.get(ip_address)

    if not entry:
        return False

    blocked_until = datetime.fromisoformat(
        entry["blocked_until"]
    )

    now = datetime.now(timezone.utc)

    # --------------------------------------------------------
    # BLOCK EXPIRED
    # --------------------------------------------------------

    if now >= blocked_until:

        del BLOCKED_IPS[ip_address]

        return False

    return True


# ============================================================
# GET BLOCK DETAILS
# ============================================================

def get_block_details(ip_address: str):

    if not is_ip_blocked(ip_address):
        return None

    return BLOCKED_IPS.get(ip_address)


# ============================================================
# GET ALL BLOCKED IPS
# ============================================================

def get_blocked_ips():

    # Remove expired entries first
    for ip_address in list(BLOCKED_IPS.keys()):

        is_ip_blocked(ip_address)

    return list(BLOCKED_IPS.values())