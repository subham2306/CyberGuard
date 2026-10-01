import os
import numpy as np
import pandas as pd
import joblib

from sklearn.ensemble import IsolationForest


# --------------------------------------------------
# PATHS
# --------------------------------------------------

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DATASET_DIR = os.path.join(BASE_DIR, "datasets")
MODEL_DIR = os.path.join(BASE_DIR, "models")

os.makedirs(DATASET_DIR, exist_ok=True)
os.makedirs(MODEL_DIR, exist_ok=True)


# --------------------------------------------------
# RANDOM SEED
# --------------------------------------------------

np.random.seed(42)


# --------------------------------------------------
# GENERATE NORMAL LOGIN BEHAVIOUR
# --------------------------------------------------

NUM_SAMPLES = 3000

data = {
    "login_hour": np.random.normal(
        loc=10,
        scale=2.5,
        size=NUM_SAMPLES
    ),

    "failed_attempts": np.random.poisson(
        lam=0.3,
        size=NUM_SAMPLES
    ),

    "new_ip": np.random.choice(
        [0, 1],
        size=NUM_SAMPLES,
        p=[0.95, 0.05]
    ),

    "new_device": np.random.choice(
        [0, 1],
        size=NUM_SAMPLES,
        p=[0.97, 0.03]
    ),

    "new_location": np.random.choice(
        [0, 1],
        size=NUM_SAMPLES,
        p=[0.98, 0.02]
    ),

    "login_frequency": np.random.normal(
        loc=3,
        scale=1,
        size=NUM_SAMPLES
    ),

    "session_duration": np.random.normal(
        loc=25,
        scale=8,
        size=NUM_SAMPLES
    ),

    "actions_count": np.random.normal(
        loc=20,
        scale=6,
        size=NUM_SAMPLES
    )
}


df = pd.DataFrame(data)


# --------------------------------------------------
# CLEAN VALUES
# --------------------------------------------------

df["login_hour"] = df["login_hour"].clip(0, 23)

df["failed_attempts"] = df["failed_attempts"].clip(0, 20)

df["login_frequency"] = df["login_frequency"].clip(0, 20)

df["session_duration"] = df["session_duration"].clip(1, 180)

df["actions_count"] = df["actions_count"].clip(1, 200)


# --------------------------------------------------
# FEATURES USED BY AI MODEL
# --------------------------------------------------

FEATURES = [
    "login_hour",
    "failed_attempts",
    "new_ip",
    "new_device",
    "new_location",
    "login_frequency",
    "session_duration",
    "actions_count"
]


X = df[FEATURES]


# --------------------------------------------------
# TRAIN ISOLATION FOREST
# --------------------------------------------------

model = IsolationForest(
    n_estimators=200,
    contamination=0.05,
    random_state=42,
    n_jobs=-1
)

model.fit(X)


# --------------------------------------------------
# SAVE DATASET
# --------------------------------------------------

dataset_path = os.path.join(
    DATASET_DIR,
    "ato_training_data.csv"
)

df.to_csv(
    dataset_path,
    index=False
)


# --------------------------------------------------
# SAVE MODEL
# --------------------------------------------------

model_path = os.path.join(
    MODEL_DIR,
    "isolation_forest.pkl"
)

joblib.dump(
    {
        "model": model,
        "features": FEATURES
    },
    model_path
)


# --------------------------------------------------
# OUTPUT
# --------------------------------------------------

print()
print("=" * 60)
print("CyberGuard ATO AI MODEL TRAINING")
print("=" * 60)

print(f"Training samples : {len(df)}")
print(f"Features         : {len(FEATURES)}")

print()
print("Features used:")

for feature in FEATURES:
    print(f"  - {feature}")

print()
print(f"Dataset saved to:")
print(dataset_path)

print()
print(f"Model saved to:")
print(model_path)

print()
print("Isolation Forest training completed successfully.")
print("=" * 60)