# ============================================================
# CYBERGUARD - ATO DASHBOARD / LOGIN GATEWAY
# ============================================================

from flask import Flask, render_template, jsonify, request
import requests
from datetime import datetime
import uuid


# ============================================================
# FLASK APPLICATION
# ============================================================

app = Flask(__name__)


# ============================================================
# CYBERGUARD ATO DASHBOARD
# ============================================================

# FastAPI ATO detection engine runs locally on Windows.
# Flask acts as the user-facing gateway.
ATO_API = "http://127.0.0.1:8000"


# ============================================================
# IN-MEMORY THREAT EVENT HISTORY
# ============================================================

# Demo-only event storage.
# This resets whenever Flask restarts.
THREAT_EVENTS = []

MAX_EVENTS = 50


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/")
def dashboard():

    return render_template(
        "index.html"
    )


# ============================================================
# USER LOGIN PAGE
# ============================================================

@app.route("/login")
def login_page():

    return render_template(
        "login.html"
    )


# ============================================================
# USER LOGIN API PROXY
#
# AUTOMATIC CLIENT CONTEXT DETECTION
# ============================================================

@app.route(
    "/api/login",
    methods=["POST"]
)
def user_login():

    try:

        # ====================================================
        # 1. READ ORIGINAL JSON REQUEST
        # ====================================================

        data = request.get_json(
            silent=True
        ) or {}

        # Make sure the request body is a dictionary.
        if not isinstance(data, dict):

            return jsonify({
                "error":
                    "Invalid JSON request body"
            }), 400


        # ====================================================
        # 2. PRESERVE USERNAME AND PASSWORD
        # ====================================================

        # These two fields MUST NOT be removed when we
        # automatically add the security context.

        username = data.get(
            "username"
        )

        password = data.get(
            "password"
        )

        if not username or not password:

            return jsonify({
                "error":
                    "username and password are required"
            }), 400


        # ====================================================
        # 3. AUTOMATIC CLIENT IP DETECTION
        # ====================================================

        # Because Flask is exposed on 0.0.0.0:8501,
        # request.remote_addr will contain the actual
        # connecting VM/client address.
        #
        # Example:
        #
        # Ubuntu VM:
        # 192.168.150.146
        #
        # Kali VM:
        # 192.168.150.131
        #
        # Another VM:
        # 192.168.150.149

        client_ip = (
            request.remote_addr
            or "unknown"
        )


        # ====================================================
        # 4. AUTOMATIC USER-AGENT DETECTION
        # ====================================================

        # Detect the real browser/client User-Agent.
        #
        # Example:
        #
        # Firefox
        # Chrome
        # curl
        # etc.

        client_user_agent = request.headers.get(
            "User-Agent",
            "unknown"
        )


        # ====================================================
        # 5. AUTOMATIC CYBERGUARD DEVICE ID
        # ====================================================

        # CyberGuard does NOT collect hardware serial numbers.
        #
        # Instead, every browser receives a random
        # CyberGuard device identifier stored in a cookie.

        device_id = request.cookies.get(
            "cyberguard_device_id"
        )

        new_device_id = False


        # ----------------------------------------------------
        # Create a new device ID if this browser has none.
        # ----------------------------------------------------

        if not device_id:

            device_id = (
                "CG-"
                + uuid.uuid4().hex[:12].upper()
            )

            new_device_id = True


        # ====================================================
        # 6. RESTORE / PRESERVE AUTHENTICATION DATA
        # ====================================================

        # Explicitly place username and password back into
        # the request dictionary.
        #
        # This prevents the automatic security-context
        # processing from accidentally sending a request
        # without authentication credentials.

        data["username"] = username

        data["password"] = password


        # ====================================================
        # 7. OVERRIDE SECURITY CONTEXT WITH REAL REQUEST DATA
        # ====================================================

        # IMPORTANT:
        #
        # These values are NOT trusted from JavaScript.
        #
        # They are obtained from the actual HTTP request.

        data["ip_address"] = client_ip

        data["user_agent"] = client_user_agent

        data["device_id"] = device_id


        # ====================================================
        # 8. LOCATION HANDLING
        # ====================================================

        # Private VMware addresses such as:
        #
        # 192.168.150.146
        #
        # cannot reliably determine a physical city.
        #
        # Therefore CyberGuard does NOT fake a geographic
        # location.
        #
        # Until a trusted location mechanism is integrated,
        # location is explicitly marked as Unknown.

        data["location"] = "Unknown"


        # ====================================================
        # 9. SEND COMPLETE REQUEST TO REAL ATO ENGINE
        # ====================================================

        # At this point the request contains:
        #
        # username
        # password
        # ip_address
        # device_id
        # user_agent
        # location

        response = requests.post(
            f"{ATO_API}/login",
            json=data,
            timeout=5
        )


        # ====================================================
        # 10. PARSE FASTAPI RESPONSE
        # ====================================================

        try:

            response_data = response.json()

        except ValueError:

            response_data = {
                "error":
                    "ATO API returned invalid JSON",
                "status_code":
                    response.status_code
            }


        # ====================================================
        # 11. ADD AUTOMATIC CLIENT CONTEXT
        # ====================================================

        # This is returned to the frontend so the dashboard
        # can demonstrate what CyberGuard automatically
        # detected.

        if isinstance(
            response_data,
            dict
        ):

            response_data["client_context"] = {

                "source_ip":
                    client_ip,

                "user_agent":
                    client_user_agent,

                "device_id":
                    device_id,

                "location":
                    data["location"],

                "context_source":
                    "AUTOMATIC_REQUEST_DETECTION"
            }


        # ====================================================
        # 12. BUILD FLASK RESPONSE
        # ====================================================

        flask_response = jsonify(
            response_data
        )

        flask_response.status_code = (
            response.status_code
        )


        # ====================================================
        # 13. SAVE DEVICE COOKIE
        # ====================================================

        # Only create the cookie when this is a new browser.

        if new_device_id:

            flask_response.set_cookie(

                "cyberguard_device_id",

                device_id,

                max_age=(
                    60
                    * 60
                    * 24
                    * 30
                ),

                httponly=True,

                samesite="Lax"
            )


        # ====================================================
        # 14. RETURN ATO RESULT
        # ====================================================

        return flask_response


    # ========================================================
    # ATO API CONNECTION ERROR
    # ========================================================

    except requests.exceptions.ConnectionError:

        return jsonify({

            "error":
                "ATO API is offline. "
                "Start the FastAPI server on port 8000."

        }), 503


    # ========================================================
    # ATO API TIMEOUT
    # ========================================================

    except requests.exceptions.Timeout:

        return jsonify({

            "error":
                "ATO API request timed out."

        }), 504


    # ========================================================
    # GENERAL ERROR
    # ========================================================

    except Exception as e:

        return jsonify({

            "error":
                "Unexpected error in CyberGuard login gateway.",

            "details":
                str(e)

        }), 500


# ============================================================
# MFA VERIFICATION API PROXY
# ============================================================

@app.route(
    "/api/mfa/verify",
    methods=["POST"]
)
def user_mfa_verify():

    try:

        data = request.get_json(
            silent=True
        ) or {}


        # Send the MFA verification request
        # to the real FastAPI engine.

        response = requests.post(

            f"{ATO_API}/mfa/verify",

            json=data,

            timeout=5
        )


        # Return the real MFA result.

        return jsonify(
            response.json()
        ), response.status_code


    # ========================================================
    # CONNECTION ERROR
    # ========================================================

    except requests.exceptions.ConnectionError:

        return jsonify({

            "error":
                "ATO API is offline. "
                "Start the FastAPI server on port 8000."

        }), 503


    # ========================================================
    # TIMEOUT
    # ========================================================

    except requests.exceptions.Timeout:

        return jsonify({

            "error":
                "MFA verification request timed out."

        }), 504


    # ========================================================
    # GENERAL ERROR
    # ========================================================

    except Exception as e:

        return jsonify({

            "error":
                str(e)

        }), 500


# ============================================================
# SESSION CHECK API PROXY
# ============================================================

@app.route(
    "/api/session/check",
    methods=["POST"]
)
def user_session_check():

    try:

        data = request.get_json(
            silent=True
        ) or {}


        # Send the session-check request to the
        # real FastAPI session monitoring engine.

        response = requests.post(

            f"{ATO_API}/session/check",

            json=data,

            timeout=5
        )


        return jsonify(
            response.json()
        ), response.status_code


    # ========================================================
    # CONNECTION ERROR
    # ========================================================

    except requests.exceptions.ConnectionError:

        return jsonify({

            "error":
                "ATO API is offline. "
                "Start the FastAPI server on port 8000."

        }), 503


    # ========================================================
    # TIMEOUT
    # ========================================================

    except requests.exceptions.Timeout:

        return jsonify({

            "error":
                "Session check request timed out."

        }), 504


    # ========================================================
    # GENERAL ERROR
    # ========================================================

    except Exception as e:

        return jsonify({

            "error":
                str(e)

        }), 500


# ============================================================
# SYSTEM HEALTH
# ============================================================

@app.route("/api/health")
def health():

    try:

        response = requests.get(

            f"{ATO_API}/health",

            timeout=5
        )


        return jsonify(
            response.json()
        )


    except Exception as e:

        return jsonify({

            "status":
                "offline",

            "error":
                str(e)

        }), 503


# ============================================================
# BLOCKED IPs
# ============================================================

@app.route("/api/blocked-ips")
def blocked_ips():

    try:

        response = requests.get(

            f"{ATO_API}/blocked-ips",

            timeout=5
        )


        return jsonify(
            response.json()
        )


    except Exception as e:

        return jsonify({

            "count":
                0,

            "blocked_ips":
                [],

            "error":
                str(e)

        })


# ============================================================
# ACTIVE SESSIONS
# ============================================================

@app.route("/api/sessions")
def sessions():

    try:

        response = requests.get(

            f"{ATO_API}/sessions",

            timeout=5
        )


        return jsonify(
            response.json()
        )


    except Exception as e:

        return jsonify({

            "sessions":
                [],

            "error":
                str(e)

        })


# ============================================================
# SESSION STATISTICS
# ============================================================

@app.route("/api/session-statistics")
def session_statistics():

    try:

        response = requests.get(

            f"{ATO_API}/session/statistics",

            timeout=5
        )


        return jsonify(
            response.json()
        )


    except Exception as e:

        return jsonify({

            "total_sessions":
                0,

            "active_sessions":
                0,

            "revoked_sessions":
                0,

            "expired_sessions":
                0,

            "suspicious_sessions":
                0,

            "error":
                str(e)

        })


# ============================================================
# THREAT EVENT LOG
# ============================================================

@app.route("/api/threat-events")
def threat_events():

    return jsonify({

        "count":
            len(THREAT_EVENTS),

        "events":
            THREAT_EVENTS

    })


# ============================================================
# CLEAR DEMO EVENT LOG
# ============================================================

@app.route(
    "/api/threat-events/clear",
    methods=["POST"]
)
def clear_threat_events():

    THREAT_EVENTS.clear()


    return jsonify({

        "status":
            "success",

        "message":
            "Threat event log cleared",

        "count":
            0

    })


# ============================================================
# SAVE THREAT EVENT
# ============================================================

def save_threat_event(
    scenario,
    result,
    payload
):

    # ========================================================
    # CLASSIFY EVENT BASED ON DEMO SCENARIO
    # ========================================================

    scenario_threat_types = {

        "normal":
            "normal_login",

        "suspicious":
            "suspicious_login",

        "ato":
            "account_takeover"

    }


    threat_type = (
        scenario_threat_types.get(

            scenario,

            result.get(
                "threat_type",
                "account_takeover"
            )
        )
    )


    # ========================================================
    # EXTRACT INFORMATION FROM FASTAPI RESPONSE
    # ========================================================

    event = {

        "timestamp":
            datetime.now()
            .astimezone()
            .isoformat(),

        "scenario":
            scenario,

        "event_id":
            result.get(
                "event_id",
                "N/A"
            ),

        "threat_type":
            threat_type,

        "username":
            payload.get(
                "username",
                "unknown"
            ),

        "ip_address":
            payload.get(
                "ip_address",
                "unknown"
            ),

        "location":
            payload.get(
                "location",
                "unknown"
            ),

        "device_id":
            payload.get(
                "device_id",
                "unknown"
            ),

        "risk_score":
            result.get(
                "risk_score",
                0
            ),

        "severity":
            result.get(
                "severity",
                "Unknown"
            ),

        "decision":
            result.get(
                "decision",
                "UNKNOWN"
            ),

        "login":
            result.get(
                "login",
                "unknown"
            ),

        "indicators":
            result.get(
                "indicators",
                []
            ),

        "explanation":
            result.get(
                "explanation",
                ""
            ),

        "recommended_actions":
            result.get(
                "recommended_actions",
                []
            ),

        "ml_detection":
            result.get(
                "ml_detection",
                {}
            ),

        "rule_detection":
            result.get(
                "rule_detection",
                {}
            ),

        "password_spraying":
            result.get(
                "password_spraying",
                {}
            ),

        "session":
            result.get(
                "session",
                {}
            )

    }


    # ========================================================
    # NEWEST EVENTS FIRST
    # ========================================================

    THREAT_EVENTS.insert(
        0,
        event
    )


    # ========================================================
    # KEEP ONLY LATEST 50 EVENTS
    # ========================================================

    del THREAT_EVENTS[
        MAX_EVENTS:
    ]


# ============================================================
# LIVE THREAT SIMULATION
# ============================================================

@app.route(
    "/api/simulate",
    methods=["POST"]
)
def simulate():

    try:

        data = request.get_json(
            silent=True
        ) or {}


        scenario = data.get(
            "scenario",
            "normal"
        )


        # ====================================================
        # DEMO SCENARIOS
        # ====================================================

        scenarios = {

            # =================================================
            # 1. NORMAL LOGIN
            # =================================================

            "normal": {

                "username":
                    "alice",

                "password":
                    "Alice@123",

                "ip_address":
                    "192.0.2.10",

                "location":
                    "Bhubaneswar",

                "device_id":
                    "DEV001",

                "user_agent":
                    "CyberGuard-Demo-Client"

            },


            # =================================================
            # 2. SUSPICIOUS LOGIN
            # =================================================

            "suspicious": {

                "username":
                    "alice",

                "password":
                    "Alice@123",

                "ip_address":
                    "198.51.100.25",

                "location":
                    "Delhi",

                "device_id":
                    "NEW-DEVICE-001",

                "user_agent":
                    "CyberGuard-Demo-Client"

            },


            # =================================================
            # 3. ACCOUNT TAKEOVER
            # =================================================

            "ato": {

                "username":
                    "alice",

                "password":
                    "WrongPassword@999",

                "ip_address":
                    "203.0.113.50",

                "location":
                    "Delhi",

                "device_id":
                    "UNKNOWN-ATTACKER-001",

                "user_agent":
                    "Unknown-Attacker-Agent"

            }

        }


        # ====================================================
        # VALIDATE SCENARIO
        # ====================================================

        payload = scenarios.get(
            scenario
        )


        if payload is None:

            return jsonify({

                "error":
                    "Invalid simulation scenario",

                "available_scenarios": [

                    "normal",

                    "suspicious",

                    "ato"

                ]

            }), 400


        # ====================================================
        # SEND REQUEST TO REAL ATO ENGINE
        # ====================================================

        response = requests.post(

            f"{ATO_API}/login",

            json=payload,

            timeout=5
        )


        result = response.json()


        # ====================================================
        # SAVE REAL RESULT TO EVENT LOG
        # ====================================================

        save_threat_event(

            scenario,

            result,

            payload
        )


        # ====================================================
        # RETURN REAL ATO RESPONSE
        # ====================================================

        return jsonify(
            result
        ), response.status_code


    # ========================================================
    # ATO API CONNECTION ERROR
    # ========================================================

    except requests.exceptions.ConnectionError:

        return jsonify({

            "error":
                "ATO API is offline. "
                "Start the FastAPI server on port 8000."

        }), 503


    # ========================================================
    # ATO API TIMEOUT
    # ========================================================

    except requests.exceptions.Timeout:

        return jsonify({

            "error":
                "ATO API request timed out."

        }), 504


    # ========================================================
    # GENERAL ERROR
    # ========================================================

    except Exception as e:

        return jsonify({

            "error":
                str(e)

        }), 500


# ============================================================
# RUN DASHBOARD
# ============================================================

if __name__ == "__main__":

    app.run(

        # IMPORTANT:
        # 0.0.0.0 allows the VMware VMs to access
        # the CyberGuard dashboard.

        host="0.0.0.0",

        port=8501,

        debug=True

    )
