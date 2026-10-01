import streamlit as st
import requests

SENTINEL_URL = "http://127.0.0.1:8010"

st.set_page_config(
    page_title="CyberGuard AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------- Styling ----------
st.markdown("""
<style>
    .main-title {
        font-size: 42px;
        font-weight: 800;
        margin-bottom: 0;
    }

    .subtitle {
        font-size: 18px;
        opacity: 0.75;
        margin-bottom: 25px;
    }

    .module-card {
        padding: 20px;
        border-radius: 14px;
        border: 1px solid rgba(128,128,128,0.25);
        min-height: 150px;
    }

    .risk-critical {
        color: #ff4b4b;
        font-weight: 800;
    }

    .risk-high {
        color: #ff8c42;
        font-weight: 800;
    }

    .risk-medium {
        color: #ffd166;
        font-weight: 800;
    }

    .risk-low {
        color: #4dabf7;
        font-weight: 800;
    }

    .risk-safe {
        color: #51cf66;
        font-weight: 800;
    }
</style>
""", unsafe_allow_html=True)


# ---------- Helpers ----------
def sentinel_health():
    try:
        response = requests.get(
            f"{SENTINEL_URL}/health",
            timeout=3
        )
        response.raise_for_status()
        return response.json()
    except Exception as e:
        return {"status": "offline", "error": str(e)}


def analyze(payload):
    try:
        response = requests.post(
            f"{SENTINEL_URL}/api/v1/analyze",
            json=payload,
            timeout=15
        )
        return response.status_code, response.json()
    except Exception as e:
        return 0, {"error": str(e)}


def risk_class(severity):
    return {
        "CRITICAL": "risk-critical",
        "HIGH": "risk-high",
        "MEDIUM": "risk-medium",
        "LOW": "risk-low",
        "SAFE": "risk-safe",
    }.get(str(severity).upper(), "")


# ---------- Header ----------
st.markdown(
    '<div class="main-title">🛡️ CyberGuard AI</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="subtitle">AI-Powered Cyber Threat Detection & Response Platform</div>',
    unsafe_allow_html=True
)


# ---------- Sentinel Status ----------
health = sentinel_health()

if health.get("status") == "online":
    st.success("🟢 CyberGuard Sentinel is ONLINE")
else:
    st.error("🔴 CyberGuard Sentinel is OFFLINE")


# ---------- Metrics ----------
modules = health.get("modules", {})

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric("Phishing Detection", "Phishing Detection")

with col2:
    st.metric("Digital Impersonation", "Digital Impersonation Detection")

with col3:
    st.metric("Account Takeover", "Credential Theft & Account Takeover")

with col4:
    st.metric("Gateway", "CyberGuard Sentinel")


st.divider()


# ---------- Module Cards ----------
st.subheader("Detection Modules")

c1, c2, c3 = st.columns(3)

with c1:
    st.markdown("""
    <div class="module-card">
        <h3>🎣 Phishing Detection</h3>
        <p><b>Phishing Detection</b></p>
        <p>Detects malicious messages, URLs, credential theft attempts and phishing indicators.</p>
    </div>
    """, unsafe_allow_html=True)

with c2:
    st.markdown("""
    <div class="module-card">
        <h3>🕵️ Digital Impersonation</h3>
        <p><b>Digital Impersonation Detection</b></p>
        <p>Detects identity impersonation, suspicious senders and credential-request attacks.</p>
    </div>
    """, unsafe_allow_html=True)

with c3:
    st.markdown("""
    <div class="module-card">
        <h3>🔐 Account Takeover</h3>
        <p><b>Credential Theft & Account Takeover</b></p>
        <p>Detects abnormal logins, credential attacks, session takeover and suspicious behavior.</p>
    </div>
    """, unsafe_allow_html=True)


st.divider()


# ---------- Analyzer ----------
st.subheader("🔎 Cyber Threat Analyzer")

analysis_type = st.selectbox(
    "Select Detection Module",
    [
        "Phishing / Message",
        "Digital Impersonation",
        "Account Takeover",
    ]
)


# ---------- Phishing ----------
if analysis_type == "Phishing / Message":

    st.write("Analyze a suspicious message using the Phishing Detection engine.")

    sender = st.text_input(
        "Sender",
        placeholder="security@example.com"
    )

    subject = st.text_input(
        "Subject",
        placeholder="Urgent account verification required"
    )

    message = st.text_area(
        "Message",
        height=180,
        placeholder="Paste the suspicious email, SMS or message here..."
    )

    if st.button("🚀 Analyze Phishing", use_container_width=True):

        if not message.strip():
            st.warning("Please enter a message.")
        else:
            status, result = analyze({
                "type": "message",
                "sender": sender,
                "subject": subject,
                "message": message,
            })

            if status == 200:
                st.session_state["last_result"] = result
            else:
                st.error(f"Analysis failed: {result}")


# ---------- Impersonation ----------
elif analysis_type == "Digital Impersonation":

    st.write("Analyze a suspicious identity or email using the Digital Impersonation Detection engine.")

    sender_name = st.text_input(
        "Sender Name",
        placeholder="CEO / Manager"
    )

    sender_email = st.text_input(
        "Sender Email",
        placeholder="ceo@example.com"
    )

    receiver_name = st.text_input(
        "Receiver Name",
        placeholder="Employee Name"
    )

    receiver_email = st.text_input(
        "Receiver Email",
        placeholder="employee@example.com"
    )

    reply_to = st.text_input(
        "Reply-To",
        placeholder="attacker@example.com"
    )

    subject = st.text_input(
        "Subject",
        placeholder="Urgent payment request"
    )

    message = st.text_area(
        "Message",
        height=180,
        placeholder="Paste the suspicious email/message here..."
    )

    if st.button("🚀 Analyze Impersonation", use_container_width=True):

        if not sender_email.strip():
            st.warning("Please enter the sender email.")
        else:
            status, result = analyze({
                "type": "identity",
                "sender_name": sender_name,
                "sender_email": sender_email,
                "receiver_name": receiver_name,
                "receiver_email": receiver_email,
                "reply_to": reply_to,
                "subject": subject,
                "message": message,
            })

            if status == 200:
                st.session_state["last_result"] = result
            else:
                st.error(f"Analysis failed: {result}")


# ---------- ATO ----------
else:

    st.write("Analyze a login attempt using the Account Takeover Detection engine.")

    username = st.text_input(
        "Username",
        placeholder="alice"
    )

    password = st.text_input(
        "Password",
        type="password",
        placeholder="Password"
    )

    ip_address = st.text_input(
        "IP Address",
        value="192.168.150.131"
    )

    location = st.text_input(
        "Location",
        value="Unknown"
    )

    device_id = st.text_input(
        "Device ID",
        placeholder="LAB-DEVICE-001"
    )

    if st.button("🚀 Analyze Login", use_container_width=True):

        missing = []

        if not username.strip():
            missing.append("username")

        if not password:
            missing.append("password")

        if not ip_address.strip():
            missing.append("IP address")

        if not location.strip():
            missing.append("location")

        if not device_id.strip():
            missing.append("device ID")

        if missing:
            st.warning(
                "Please provide: " + ", ".join(missing)
            )
        else:
            status, result = analyze({
                "type": "login",
                "username": username,
                "password": password,
                "ip_address": ip_address,
                "location": location,
                "device_id": device_id,
                "user_agent": "CyberGuard-Dashboard",
            })

            if status == 200:
                st.session_state["last_result"] = result
            else:
                st.error(f"Analysis failed: {result}")


# ---------- Result ----------
if "last_result" in st.session_state:

    result = st.session_state["last_result"]

    st.divider()
    st.subheader("📊 Latest Detection Result")

    if "error" in result:
        st.error(result["error"])
    else:

        risk = result.get("risk_score", 0)
        severity = result.get("severity", "UNKNOWN")
        decision = result.get("decision", "UNKNOWN")
        threat_type = result.get("threat_type", "unknown")
        source = result.get("source", "unknown")

        a, b, c, d = st.columns(4)

        with a:
            st.metric("Risk Score", f"{risk}")

        with b:
            st.metric("Severity", severity)

        with c:
            st.metric("Decision", decision)

        with d:
            st.metric("Detection Source", source.upper())

        st.markdown(
            f"### Threat Type: `{threat_type}`"
        )

        st.markdown(
            f'<p class="{risk_class(severity)}">'
            f'● {severity} — {decision}'
            f'</p>',
            unsafe_allow_html=True
        )

        indicators = result.get("indicators", [])

        if indicators:
            st.write("### 🚨 Indicators")

            for indicator in indicators:
                st.write(f"• {indicator}")

        explanation = result.get("explanation")

        if explanation:
            st.write("### 🧠 AI / Detection Explanation")

            if isinstance(explanation, list):
                for item in explanation:
                    st.write(f"• {item}")
            else:
                st.write(explanation)

        actions = result.get("recommended_actions", [])

        if actions:
            st.write("### 🛡️ Recommended Actions")

            for action in actions:
                st.write(f"• {action}")

        with st.expander("🔧 Raw Detection Response"):
            st.json(result)


# ---------- Footer ----------
st.divider()

st.caption(
    "CyberGuard AI • Unified Cyber Threat Detection & Response • "
    "Phishing Detection + Digital Impersonation Detection + Credential Theft & Account Takeover + CyberGuard Sentinel"
)


