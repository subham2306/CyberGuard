import os
import joblib
import pandas as pd


# ============================================================
# LOAD MODEL
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

MODEL_PATH = os.path.join(
    BASE_DIR,
    "models",
    "isolation_forest.pkl"
)

model_data = joblib.load(MODEL_PATH)

model = model_data["model"]
features = model_data["features"]


# ============================================================
# NORMAL LOGIN
# ============================================================

normal_login = pd.DataFrame([
    {
        "login_hour": 10,
        "failed_attempts": 0,
        "new_ip": 0,
        "new_device": 0,
        "new_location": 0,
        "login_frequency": 3,
        "session_duration": 25,
        "actions_count": 20
    }
])


# ============================================================
# ATTACKER LOGIN
# ============================================================

suspicious_login = pd.DataFrame([
    {
        "login_hour": 3,
        "failed_attempts": 12,
        "new_ip": 1,
        "new_device": 1,
        "new_location": 1,
        "login_frequency": 15,
        "session_duration": 2,
        "actions_count": 150
    }
])


# ============================================================
# AI PREDICTION
# ============================================================

normal_prediction = model.predict(
    normal_login[features]
)[0]

suspicious_prediction = model.predict(
    suspicious_login[features]
)[0]


# ============================================================
# ANOMALY SCORES
# ============================================================

normal_score = model.decision_function(
    normal_login[features]
)[0]

suspicious_score = model.decision_function(
    suspicious_login[features]
)[0]


# ============================================================
# DISPLAY RESULTS
# ============================================================

print()
print("=" * 60)
print("CYBERGUARD ATO - AI TEST")
print("=" * 60)

print()
print("NORMAL LOGIN")
print("-" * 30)

print("AI Prediction :", normal_prediction)
print("Anomaly Score :", round(normal_score, 4))

if normal_prediction == 1:
    print("Result        : NORMAL")
else:
    print("Result        : ANOMALOUS")


print()
print("SUSPICIOUS LOGIN")
print("-" * 30)

print("AI Prediction :", suspicious_prediction)
print("Anomaly Score :", round(suspicious_score, 4))

if suspicious_prediction == -1:
    print("Result        : ANOMALOUS / POSSIBLE ATO")
else:
    print("Result        : NORMAL")


print()
print("=" * 60)