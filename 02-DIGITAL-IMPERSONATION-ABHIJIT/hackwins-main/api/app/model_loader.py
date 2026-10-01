from pathlib import Path
import joblib


BASE_DIR = Path(__file__).resolve().parents[2]


MODEL_1 = BASE_DIR / "cyberguard_model_1_impersonation.pkl"
TFIDF_1 = BASE_DIR / "cyberguard_model_1_tfidf.pkl"

MODEL_2 = BASE_DIR / "cyberguard_model_2_attack_type.pkl"
TFIDF_2 = BASE_DIR / "cyberguard_model_2_tfidf.pkl"

MODEL_3 = BASE_DIR / "cyberguard_model_3_behavioral.pkl"


def load_models():
    required_files = [
        MODEL_1,
        TFIDF_1,
        MODEL_2,
        TFIDF_2,
        MODEL_3,
    ]

    for path in required_files:
        if not path.exists():
            raise FileNotFoundError(f"Model file not found: {path}")

    return {
        "model_1": joblib.load(MODEL_1),
        "tfidf_1": joblib.load(TFIDF_1),
        "model_2": joblib.load(MODEL_2),
        "tfidf_2": joblib.load(TFIDF_2),
        "model_3": joblib.load(MODEL_3),
    }
