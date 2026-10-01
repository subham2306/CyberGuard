import streamlit as st
import pandas as pd

# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="CyberGuard Command Dashboard",
    page_icon="ðŸ›¡ï¸",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ============================================================
# CUSTOM CSS
# ============================================================

st.markdown("""
<style>

    .main-title {
        font-size: 36px;
        font-weight: 800;
        margin-bottom: 0;
    }

    .subtitle {
        font-size: 16px;
        opacity: 0.70;
        margin-bottom: 25px;
    }

    .section-title {
        font-size: 23px;
        font-weight: 750;
        margin-top: 10px;
        margin-bottom: 15px;
    }

    .status-card {
        padding: 18px;
        border-radius: 14px;
        border: 1px solid rgba(128,128,128,0.25);
        min-height: 105px;
    }

    .status-number {
        font-size: 30px;
        font-weight: 800;
        margin-top: 5px;
    }

    .status-label {
        font-size: 14px;
        opacity: 0.70;
    }

    .attack-card {
        padding: 18px;
        border-radius: 14px;
        border: 1px solid rgba(128,128,128,0.25);
        min-height: 125px;
    }

    .attack-number {
        font-size: 28px;
        font-weight: 800;
    }

    .attack-label {
        font-size: 14px;
        opacity: 0.70;
    }

    .recommendation {
        padding: 12px 15px;
        margin-bottom: 9px;
        border-radius: 10px;
        border: 1px solid rgba(128,128,128,0.20);
    }

    .incident-open {
        color: #ff4b4b;
        font-weight: 800;
    }

    .incident-investigating {
        color: #ff8c42;
        font-weight: 800;
    }

    .incident-contained {
        color: #4dabf7;
        font-weight: 800;
    }

    .incident-resolved {
        color: #51cf66;
        font-weight: 800;
    }

</style>
""", unsafe_allow_html=True)


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:
    st.markdown("## ðŸ›¡ï¸ CYBERGUARD")
    st.caption("AI-Powered Cybersecurity Command Center")

    st.divider()

    st.markdown("### Navigation")
    st.markdown("ðŸ  **Command Dashboard**")
    st.markdown("ðŸ“§ Analyze Email")
    st.markdown("ðŸŽ£ Phishing Detection")
    st.markdown("ðŸ‘¤ Digital Impersonation")
    st.markdown("ðŸ” Account Takeover")
    st.markdown("ðŸŽ­ Deepfake Detection")
    st.markdown("ðŸš¨ Incidents")
    st.markdown("ðŸ“Š Reports")
    st.markdown("âš™ï¸ Settings")

    st.divider()

    st.markdown("### System Status")

    st.success("Phishing Detection â€” Online")
    st.success("Digital Impersonation Detection â€” Online")
    st.success("Credential Theft & Account Takeover â€” Online")
    st.warning("Sentinel â€” Check Required")


# ============================================================
# HEADER
# ============================================================

st.markdown(
    '<div class="main-title">ðŸ›¡ï¸ CyberGuard Command Dashboard</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="subtitle">'
    'Unified cybersecurity monitoring, threat detection and incident response'
    '</div>',
    unsafe_allow_html=True
)


# ============================================================
# TOP STATUS
# ============================================================

st.info(
    "ðŸ”Ž Command Center â€” Monitoring phishing, digital impersonation, "
    "account takeover, deepfake and related security events."
)


# ============================================================
# KPI CARDS
# ============================================================

st.markdown(
    '<div class="section-title">Security Overview</div>',
    unsafe_allow_html=True
)

k1, k2, k3, k4 = st.columns(4)

with k1:
    st.markdown("""
    <div class="status-card">
        <div class="status-label">TOTAL EVENTS ANALYSED</div>
        <div class="status-number">1,248</div>
    </div>
    """, unsafe_allow_html=True)

with k2:
    st.markdown("""
    <div class="status-card">
        <div class="status-label">THREATS DETECTED</div>
        <div class="status-number">327</div>
    </div>
    """, unsafe_allow_html=True)

with k3:
    st.markdown("""
    <div class="status-card">
        <div class="status-label">CRITICAL THREATS</div>
        <div class="status-number">42</div>
    </div>
    """, unsafe_allow_html=True)

with k4:
    st.markdown("""
    <div class="status-card">
        <div class="status-label">ACTIVE INCIDENTS</div>
        <div class="status-number">86</div>
    </div>
    """, unsafe_allow_html=True)


st.divider()


# ============================================================
# THREAT CATEGORY + RISK LEVEL
# ============================================================

left, right = st.columns(2)

with left:

    st.markdown(
        '<div class="section-title">Threat Category</div>',
        unsafe_allow_html=True
    )

    threat_data = pd.DataFrame({
        "Threat Category": [
            "Phishing",
            "Impersonation",
            "Account Takeover",
            "Credential Theft",
            "Deepfake",
        ],
        "Threats": [
            120,
            87,
            65,
            38,
            17,
        ],
    })

    st.bar_chart(
        threat_data.set_index("Threat Category"),
        height=300
    )


with right:

    st.markdown(
        '<div class="section-title">Risk Level</div>',
        unsafe_allow_html=True
    )

    risk_data = pd.DataFrame({
        "Risk Level": [
            "Critical",
            "High",
            "Medium",
            "Low",
        ],
        "Events": [
            42,
            126,
            98,
            61,
        ],
    })

    st.bar_chart(
        risk_data.set_index("Risk Level"),
        height=300
    )


st.divider()


# ============================================================
# ATTACK STATISTICS
# ============================================================

st.markdown(
    '<div class="section-title">Attack Statistics</div>',
    unsafe_allow_html=True
)

a1, a2, a3, a4 = st.columns(4)

with a1:
    st.markdown("""
    <div class="attack-card">
        <div>ðŸŽ£</div>
        <div class="attack-number">120</div>
        <div class="attack-label">PHISHING ATTEMPTS</div>
    </div>
    """, unsafe_allow_html=True)

with a2:
    st.markdown("""
    <div class="attack-card">
        <div>ðŸ‘¤</div>
        <div class="attack-number">87</div>
        <div class="attack-label">IMPERSONATION ATTEMPTS</div>
    </div>
    """, unsafe_allow_html=True)

with a3:
    st.markdown("""
    <div class="attack-card">
        <div>ðŸŽ­</div>
        <div class="attack-number">17</div>
        <div class="attack-label">SUSPECTED DEEPFAKES</div>
    </div>
    """, unsafe_allow_html=True)

with a4:
    st.markdown("""
    <div class="attack-card">
        <div>ðŸ”</div>
        <div class="attack-number">65</div>
        <div class="attack-label">ACCOUNT TAKEOVER ATTEMPTS</div>
    </div>
    """, unsafe_allow_html=True)


st.divider()


# ============================================================
# ATTACK TIMELINE
# ============================================================

st.markdown(
    '<div class="section-title">Attack Timeline</div>',
    unsafe_allow_html=True
)

timeline = pd.DataFrame({
    "Phishing": [8, 13, 19, 32, 21, 17, 10],
    "Impersonation": [4, 6, 10, 18, 13, 11, 7],
    "Account Takeover": [3, 4, 7, 12, 8, 10, 5],
    "Deepfake": [1, 2, 3, 5, 4, 2, 2],
}, index=[
    "00:00",
    "04:00",
    "08:00",
    "12:00",
    "16:00",
    "20:00",
    "24:00",
])

st.line_chart(timeline, height=350)


st.divider()


# ============================================================
# TARGETED USERS + RECOMMENDATIONS
# ============================================================

left, right = st.columns(2)

with left:

    st.markdown(
        '<div class="section-title">Frequently Targeted Users / Services</div>',
        unsafe_allow_html=True
    )

    targets = pd.DataFrame({
        "Target": [
            "Finance Department",
            "Administrator",
            "HR Department",
            "IT Department",
            "Payroll Service",
        ],
        "Incidents": [
            42,
            31,
            27,
            19,
            16,
        ],
        "Risk": [
            "HIGH",
            "HIGH",
            "HIGH",
            "MEDIUM",
            "HIGH",
        ],
    })

    st.dataframe(
        targets,
        use_container_width=True,
        hide_index=True
    )


with right:

    st.markdown(
        '<div class="section-title">Recommended Actions</div>',
        unsafe_allow_html=True
    )

    recommendations = [
        "ðŸ”´ Block suspicious sender",
        "ðŸŸ  Verify sender identity",
        "ðŸŸ¡ Reset affected credentials",
        "ðŸŸ¡ Enable MFA for affected account",
        "ðŸ”µ Investigate related authentication events",
    ]

    for recommendation in recommendations:
        st.markdown(
            f'<div class="recommendation">{recommendation}</div>',
            unsafe_allow_html=True
        )


st.divider()


# ============================================================
# INCIDENT STATUS
# ============================================================

st.markdown(
    '<div class="section-title">Incident Status</div>',
    unsafe_allow_html=True
)

i1, i2, i3, i4 = st.columns(4)

with i1:
    st.metric("ðŸ”´ OPEN", "38")

with i2:
    st.metric("ðŸŸ  INVESTIGATING", "27")

with i3:
    st.metric("ðŸ”µ CONTAINED", "14")

with i4:
    st.metric("ðŸŸ¢ RESOLVED", "7")


# ============================================================
# FOOTER
# ============================================================

st.divider()

st.caption(
    "CyberGuard AI â€¢ BPUT Hackathon 2026 â€¢ "
    "Phishing Detection + Digital Impersonation Detection + Credential Theft & Account Takeover + CyberGuard Sentinel"
)
