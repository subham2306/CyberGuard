import os
import joblib
import pandas as pd


# ============================================================
# MODEL PATH
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

MODEL_PATH = os.path.join(
    BASE_DIR,
    "models",
    "isolation_forest_v2.pkl"
)


# ============================================================
# LOAD MODEL
# ============================================================

_model_data = joblib.load(MODEL_PATH)

_model = _model_data["model"]

FEATURES = _model_data["features"]


# ============================================================
# ML SCORE → RISK SCORE
# ============================================================

def anomaly_score_to_risk(raw_score: float) -> float:
    """
    Convert Isolation Forest decision_function score
    into a 0–100 CyberGuard ML risk score.

    Isolation Forest:
        Positive score  -> more normal
        Negative score  -> more anomalous

    CyberGuard:
        Lower score     -> lower risk
        Higher score    -> higher risk

    The conversion is centered around 50:
        raw_score = 0       -> risk 50
        positive score      -> risk decreases
        negative score      -> risk increases

    This keeps the numerical ML risk consistent with
    the model's anomaly classification.
    """

    risk = 50 - (raw_score * 1000)

    risk = max(0, min(risk, 100))

    return round(risk, 2)


# ============================================================
# PREDICTION
# ============================================================

def predict_anomaly(features: dict):
    """
    Run the Isolation Forest model against login features.

    Returns:
        prediction
        raw_score
        ml_risk_score
        anomalous
    """

    # Build model input using the exact training features
    data = {}

    for feature in FEATURES:
        data[feature] = [
            features.get(feature, 0)
        ]

    df = pd.DataFrame(data)

    # Model prediction
    prediction = _model.predict(
        df[FEATURES]
    )[0]

    # Raw Isolation Forest score
    raw_score = _model.decision_function(
        df[FEATURES]
    )[0]

    # Convert raw score to CyberGuard risk
    ml_risk = anomaly_score_to_risk(
        float(raw_score)
    )

    return {
        "prediction": int(prediction),
        "raw_score": round(float(raw_score), 4),
        "ml_risk_score": ml_risk,
        "anomalous": prediction == -1
    }