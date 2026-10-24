import streamlit as st
import requests

from backend.login import login_form, logout, is_authenticated, current_user

SENTINEL_URL = "http://127.0.0.1:8010"

st.set_page_config(
    page_title="CyberGuard AI",
    page_icon="shield",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------- Authentication ----------
if not is_authenticated():
    login_form()
    st.stop()

user = current_user()

with st.sidebar:
    st.markdown("## CYBERGUARD")
    st.caption(f"Logged in as: **{user['username']}**")
    st.caption(f"Role: **{user['role']}**")

    if st.button("Logout", use_container_width=True):
        logout()

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
