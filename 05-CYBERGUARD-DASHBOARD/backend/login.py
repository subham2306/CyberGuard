import streamlit as st

from .auth import authenticate_user


def login_form():
    st.markdown(
        """
        <div style="text-align:center; margin-top:70px;">
            <h1> CyberGuard AI</h1>
            <p>AI-Powered Cyber Threat Detection & Response Platform</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    left, center, right = st.columns([1, 2, 1])

    with center:
        st.subheader(" Secure Login")

        username = st.text_input(
            "Username",
            placeholder="Enter username",
        )

        password = st.text_input(
            "Password",
            type="password",
            placeholder="Enter password",
        )

        if st.button(
            "Login",
            use_container_width=True,
            type="primary",
        ):
            if not username.strip() or not password:
                st.warning("Please enter username and password.")
                return

            user = authenticate_user(
                username.strip(),
                password,
            )

            if user:
                st.session_state["authenticated"] = True
                st.session_state["user"] = user
                st.rerun()
            else:
                st.error("Invalid username or password.")


def logout():
    st.session_state.pop("authenticated", None)
    st.session_state.pop("user", None)
    st.session_state.pop("last_result", None)
    st.rerun()


def is_authenticated():
    return st.session_state.get("authenticated", False)


def current_user():
    return st.session_state.get("user")


def require_role(role):
    user = current_user()

    if not user:
        return False

    return user.get("role") == role
