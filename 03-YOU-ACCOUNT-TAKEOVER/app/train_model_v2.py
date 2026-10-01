import os
import numpy as np
import pandas as pd
import joblib

from sklearn.ensemble import IsolationForest


# --------------------------------------------------
# PATHS
# --------------------------------------------------

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

DATASET_DIR = os.path.join(
    BASE_DIR,
    "datasets"
)

MODEL_DIR = os.path.join(
    BASE_DIR,
    "models"
)

os.makedirs(
    DATASET_DIR,
    exist_ok=True
)

os.makedirs(
    MODEL_DIR,
    exist_ok=True
)


# --------------------------------------------------
# RANDOM SEED
# --------------------------------------------------

np.random.seed(42)


# --------------------------------------------------
# GENERATE REALISTIC NORMAL LOGIN BEHAVIOUR
# --------------------------------------------------

NUM_SAMPLES = 5000


data = {

    # Users can legitimately log in throughout the day.
    # We use a mixture instead of concentrating everything
    # around 10 AM.

    "login_hour": np.random.choice(
        np.arange(6, 24),
        size=NUM_SAMPLES,
        p=[
            0.02, 0.03, 0.04, 0.05,
            0.07, 0.09, 0.10, 0.10,
            0.10, 0.10, 0.09, 0.08,
            0.07, 0.05, 0.01, 0.00,
            0.00, 0.00
        ]
    ),

    # Most legitimate logins have few failures,
    # but 1-2 failures are normal.

    "failed_attempts": np.random.choice(
        [0, 1, 2, 3],
        size=NUM_SAMPLES,
        p=[0.70, 0.20, 0.08, 0.02]
    ),

    # New IPs occasionally happen because of
    # mobile networks, VPNs, home networks, etc.

    "new_ip": np.random.choice(
        [0, 1],
        size=NUM_SAMPLES,
        p=[0.88, 0.12]
    ),

    # New devices occasionally happen legitimately.

    "new_device": np.random.choice(
        [0, 1],
        size=NUM_SAMPLES,
        p=[0.90, 0.10]
    ),

    # New locations are less common but possible.

    "new_location": np.random.choice(
        [0, 1],
        size=NUM_SAMPLES,
        p=[0.93, 0.07]
    ),

    # Normal users generally have relatively
    # low login frequency.

    "login_frequency": np.random.normal(
        loc=4,
        scale=2,
        size=NUM_SAMPLES
    ),

    # Normal sessions can vary considerably.

    "session_duration": np.random.normal(
        loc=30,
        scale=15,
        size=NUM_SAMPLES
    ),

    # Normal users perform different numbers
    # of actions during a session.

    "actions_count": np.random.normal(
        loc=25,
        scale=12,
        size=NUM_SAMPLES
    )
}


df = pd.DataFrame(data)


# --------------------------------------------------
# CLEAN VALUES
# --------------------------------------------------

df["login_hour"] = df["login_hour"].clip(
    0,
    23
)

df["failed_attempts"] = df[
    "failed_attempts"
].clip(
    0,
    10
)

df["login_frequency"] = df[
    "login_frequency"
].clip(
    1,
    20
)

df["session_duration"] = df[
    "session_duration"
].clip(
    1,
    180
)

df["actions_count"] = df[
    "actions_count"
].clip(
    1,
    150
)


# --------------------------------------------------
# FEATURES
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
# TRAIN ISOLATION FOREST V2
# --------------------------------------------------

model = IsolationForest(
    n_estimators=300,
    contamination=0.03,
    random_state=42,
    n_jobs=-1
)

model.fit(X)


# --------------------------------------------------
# SAVE TRAINING DATA
# --------------------------------------------------

dataset_path = os.path.join(
    DATASET_DIR,
    "ato_training_data_v2.csv"
)

df.to_csv(
    dataset_path,
    index=False
)


# --------------------------------------------------
# SAVE MODEL V2
# --------------------------------------------------

model_path = os.path.join(
    MODEL_DIR,
    "isolation_forest_v2.pkl"
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
print("CyberGuard ATO AI MODEL V2 TRAINING")
print("=" * 60)

print(
    f"Training samples : {len(df)}"
)

print(
    f"Features         : {len(FEATURES)}"
)

print(
    "Contamination    : 0.03"
)

print()
print("Features used:")

for feature in FEATURES:
    print(f"  - {feature}")

print()
print("Dataset saved to:")
print(dataset_path)

print()
print("Model saved to:")
print(model_path)

print()
print(
    "Isolation Forest V2 training completed successfully."
)

print("=" * 60)