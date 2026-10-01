"""
CyberGuard ATO Detection
Evaluation Dataset Generator

Creates a labeled dataset containing:
    0 = Normal login
    1 = Account Takeover / Anomalous login

This dataset is used to evaluate the trained Isolation Forest model.
"""

from pathlib import Path

import numpy as np
import pandas as pd


# ============================================================
# CONFIGURATION
# ============================================================

RANDOM_STATE = 42
NORMAL_SAMPLES = 1000
ATO_SAMPLES = 1000

FEATURES = [
    "login_hour",
    "failed_attempts",
    "new_ip",
    "new_device",
    "new_location",
    "login_frequency",
    "session_duration",
    "actions_count",
]


# ============================================================
# OUTPUT PATH
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent
DATASET_DIR = BASE_DIR / "datasets"

DATASET_DIR.mkdir(parents=True, exist_ok=True)

OUTPUT_FILE = DATASET_DIR / "ato_evaluation_data.csv"


# ============================================================
# RANDOM GENERATOR
# ============================================================

rng = np.random.default_rng(RANDOM_STATE)


# ============================================================
# GENERATE NORMAL LOGINS
# ============================================================

normal_data = pd.DataFrame({
    "login_hour": rng.integers(7, 22, NORMAL_SAMPLES),

    "failed_attempts": rng.choice(
        [0, 1, 2],
        size=NORMAL_SAMPLES,
        p=[0.75, 0.20, 0.05]
    ),

    "new_ip": rng.choice(
        [0, 1],
        size=NORMAL_SAMPLES,
        p=[0.90, 0.10]
    ),

    "new_device": rng.choice(
        [0, 1],
        size=NORMAL_SAMPLES,
        p=[0.92, 0.08]
    ),

    "new_location": rng.choice(
        [0, 1],
        size=NORMAL_SAMPLES,
        p=[0.95, 0.05]
    ),

    "login_frequency": rng.integers(
        1, 8, NORMAL_SAMPLES
    ),

    "session_duration": rng.integers(
        60, 600, NORMAL_SAMPLES
    ),

    "actions_count": rng.integers(
        5, 80, NORMAL_SAMPLES
    ),
})

normal_data["actual"] = 0


# ============================================================
# GENERATE ATO / ANOMALOUS LOGINS
# ============================================================

ato_data = pd.DataFrame({
    "login_hour": rng.choice(
        list(range(0, 6)) + list(range(22, 24)),
        size=ATO_SAMPLES
    ),

    "failed_attempts": rng.integers(
        3, 10, ATO_SAMPLES
    ),

    "new_ip": rng.choice(
        [0, 1],
        size=ATO_SAMPLES,
        p=[0.15, 0.85]
    ),

    "new_device": rng.choice(
        [0, 1],
        size=ATO_SAMPLES,
        p=[0.15, 0.85]
    ),

    "new_location": rng.choice(
        [0, 1],
        size=ATO_SAMPLES,
        p=[0.10, 0.90]
    ),

    "login_frequency": rng.integers(
        10, 30, ATO_SAMPLES
    ),

    "session_duration": rng.integers(
        1, 40, ATO_SAMPLES
    ),

    "actions_count": rng.integers(
        0, 10, ATO_SAMPLES
    ),
})

ato_data["actual"] = 1


# ============================================================
# COMBINE DATA
# ============================================================

evaluation_data = pd.concat(
    [normal_data, ato_data],
    ignore_index=True
)


# ============================================================
# SHUFFLE
# ============================================================

evaluation_data = evaluation_data.sample(
    frac=1,
    random_state=RANDOM_STATE
).reset_index(drop=True)


# ============================================================
# SAVE
# ============================================================

evaluation_data.to_csv(
    OUTPUT_FILE,
    index=False
)


# ============================================================
# DISPLAY SUMMARY
# ============================================================

print("=" * 60)
print("CYBERGUARD ATO EVALUATION DATASET")
print("=" * 60)

print(f"\nDataset saved to:")
print(OUTPUT_FILE)

print(f"\nTotal samples : {len(evaluation_data)}")
print(f"Normal cases  : {(evaluation_data['actual'] == 0).sum()}")
print(f"ATO cases     : {(evaluation_data['actual'] == 1).sum()}")

print("\nFeatures:")
for feature in FEATURES:
    print(f"  - {feature}")

print("\nDataset preview:")
print(evaluation_data.head(10))

print("\nDataset generation complete.")
print("=" * 60)