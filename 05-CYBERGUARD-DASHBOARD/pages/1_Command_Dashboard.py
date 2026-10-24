import streamlit as st
import requests
from datetime import datetime

from backend.login import login_form, logout, is_authenticated, current_user

st.set_page_config(
    page_title="CyberGuard Command Center",
    page_icon="shield",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ============================================================
# ACCESS CONTROL
# ============================================================

if not is_authenticated():
    login_form()
    st.stop()

user = current_user()

if user.get("role") != "ADMIN":
    st.error("Access denied. The Command Center is restricted to administrators.")
    st.stop()

# ============================================================
# CONFIGURATION
# ============================================================

SERVICES = {
    "Phishing Engine": "http://127.0.0.1:8001/health",
    "Digital Impersonation": "http://127.0.0.1:8002/health",
    "Account Takeover": "http://127.0.0.1:8000/health",
    "CyberGuard Sentinel": "http://127.0.0.1:8010/health",
}

# ============================================================
# STYLING
# ============================================================

st.markdown(
    """
    <style>

    .block-container {
        padding-top: 1.5rem;
        padding-bottom: 3rem;
        max-width: 1500px;
    }

    .top-header {
        padding: 24px 28px;
        border-radius: 18px;
        border: 1px solid rgba(255,255,255,0.10);
        background: linear-gradient(
            135deg,
            rgba(20,30,45,0.95),
            rgba(10,15,25,0.98)
        );
        margin-bottom: 22px;
    }

    .top-title {
        font-size: 34px;
        font-weight: 800;
        margin: 0;
        letter-spacing: -0.5px;
    }

    .top-subtitle {
        margin-top: 6px;
        font-size: 15px;
        opacity: 0.68;
    }

    .admin-badge {
        display: inline-block;
        margin-top: 14px;
        padding: 6px 12px;
        border-radius: 20px;
        background: rgba(59,130,246,0.15);
        border: 1px solid rgba(59,130,246,0.35);
        color: #60a5fa;
        font-size: 13px;
        font-weight: 700;
    }

    .section-title {
        font-size: 22px;
        font-weight: 750;
        margin-top: 25px;
        margin-bottom: 14px;
    }

    .metric-card {
        padding: 20px;
        border-radius: 15px;
        border: 1px solid rgba(255,255,255,0.09);
        background: rgba(20,25,35,0.72);
        min-height: 125px;
    }

    .metric-label {
        font-size: 12px;
        text-transform: uppercase;
        letter-spacing: 0.8px;
        opacity: 0.60;
    }

    .metric-value {
        font-size: 32px;
        font-weight: 800;
        margin-top: 8px;
    }

    .metric-note {
        font-size: 12px;
        opacity: 0.55;
        margin-top: 4px;
    }

    .module-card {
        padding: 18px;
        border-radius: 14px;
        border: 1px solid rgba(255,255,255,0.08);
        background: rgba(20,25,35,0.65);
        min-height: 125px;
    }

    .module-name {
        font-size: 15px;
        font-weight: 700;
    }

    .module-status {
        margin-top: 10px;
        font-size: 13px;
        font-weight: 700;
    }

    .online {
        color: #4ade80;
    }

    .offline {
        color: #f87171;
    }

    .event-card {
        padding: 15px 18px;
        border-radius: 12px;
        border: 1px solid rgba(255,255,255,0.08);
        background: rgba(20,25,35,0.55);
        margin-bottom: 10px;
    }

    .event-title {
        font-weight: 700;
        font-size: 14px;
    }

    .event-meta {
        font-size: 12px;
        opacity: 0.58;
        margin-top: 5px;
    }

    .footer-note {
        text-align: center;
        margin-top: 35px;
        opacity: 0.45;
        font-size: 12px;
    }

    </style>
    """,
    unsafe_allow_html=True,
)

# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:

    st.markdown("## CYBERGUARD")
    st.caption("Security Operations Center")

    st.divider()

    st.markdown("### Administrator")
    st.write(f"**{user['username']}**")
    st.caption("Role: ADMIN")

    if st.button("Logout", use_container_width=True):
        logout()

    st.divider()

    st.markdown("### Command Center")
    st.caption("Security monitoring and incident visibility")

    st.divider()

    st.markdown("### System")
    st.caption("Dashboard mode: ADMIN")
    st.caption("Data mode: Demo + API integration")

# ============================================================
# HEADER
# ============================================================

st.markdown(
    """
    <div class="top-header">
        <div class="top-title">CyberGuard Command Center</div>
        <div class="top-subtitle">
            Unified cybersecurity monitoring, threat detection and incident response
        </div>
        <div class="admin-badge">ADMIN ACCESS</div>
    </div>
    """,
    unsafe_allow_html=True,
)

# ============================================================
# OVERVIEW
# ============================================================

st.markdown('<div class="section-title">Security Overview</div>', unsafe_allow_html=True)

m1, m2, m3, m4 = st.columns(4)

with m1:
    st.markdown(
        """
        <div class="metric-card">
            <div class="metric-label">Total Events</div>
            <div class="metric-value">1,248</div>
            <div class="metric-note">Analyzed security events</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with m2:
    st.markdown(
        """
        <div class="metric-card">
            <div class="metric-label">Threats Detected</div>
            <div class="metric-value">327</div>
            <div class="metric-note">Detected by security engines</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with m3:
    st.markdown(
        """
        <div class="metric-card">
            <div class="metric-label">Critical Threats</div>
            <div class="metric-value">42</div>
            <div class="metric-note">High-priority security events</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with m4:
    st.markdown(
        """
        <div class="metric-card">
            <div class="metric-label">Active Incidents</div>
            <div class="metric-value">86</div>
            <div class="metric-note">Requires investigation</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

# ============================================================
# CHARTS
# ============================================================

left, right = st.columns(2)

with left:
    st.markdown('<div class="section-title">Threat Category</div>', unsafe_allow_html=True)

    threat_data = {
        "Phishing": 65,
        "Digital Impersonation": 42,
        "Account Takeover": 88,
        "Deepfake": 37,
        "Other": 120,
    }

    st.bar_chart(threat_data, height=300)

with right:
    st.markdown('<div class="section-title">Risk Distribution</div>', unsafe_allow_html=True)

    risk_data = {
        "Low": 128,
        "Medium": 61,
        "High": 99,
        "Critical": 42,
    }

    st.bar_chart(risk_data, height=300)

# ============================================================
# MODULE HEALTH
# ============================================================

st.markdown('<div class="section-title">Security Module Health</div>', unsafe_allow_html=True)

health_cols = st.columns(4)

for column, (name, url) in zip(health_cols, SERVICES.items()):

    status = "OFFLINE"
    css_class = "offline"

    try:
        response = requests.get(url, timeout=2)

        if response.ok:
            status = "ONLINE"
            css_class = "online"

    except requests.RequestException:
        status = "OFFLINE"

    with column:
        st.markdown(
            f"""
            <div class="module-card">
                <div class="module-name">{name}</div>
                <div class="module-status {css_class}">
                    {status}
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

# ============================================================
# RECENT EVENTS
# ============================================================

st.markdown('<div class="section-title">Recent Security Events</div>', unsafe_allow_html=True)

events = [
    ("Account Takeover", "Critical", "BLOCK", "Suspicious session detected"),
    ("Phishing Detection", "Critical", "BLOCK", "Malicious URL detected"),
    ("Digital Impersonation", "Critical", "BLOCK", "Credential request detected"),
    ("Account Takeover", "High", "MFA_REQUIRED", "Password spraying pattern"),
]

for module, severity, decision, description in events:

    st.markdown(
        f"""
        <div class="event-card">
            <div class="event-title">
                {module} - {severity} - {decision}
            </div>
            <div class="event-meta">
                {description}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

# ============================================================
# BLOCKED IPS
# ============================================================

st.markdown('<div class="section-title">Blocked IP Addresses</div>', unsafe_allow_html=True)

try:
    response = requests.get(
        "http://127.0.0.1:8000/blocked-ips",
        timeout=2,
    )

    if response.ok:
        blocked = response.json()

        if blocked:
            st.dataframe(blocked, use_container_width=True)
        else:
            st.info("No currently blocked IP addresses.")

    else:
        st.info("ATO blocklist is currently unavailable.")

except requests.RequestException:
    st.info("ATO blocklist is currently unavailable.")

# ============================================================
# FOOTER
# ============================================================

st.markdown(
    """
    <div class="footer-note">
        CyberGuard AI Command Center | Administrator Security View
    </div>
    """,
    unsafe_allow_html=True,
)
