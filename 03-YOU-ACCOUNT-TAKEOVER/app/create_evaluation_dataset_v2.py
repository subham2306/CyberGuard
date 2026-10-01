from pathlib import Path
import numpy as np
import pandas as pd


BASE_DIR = Path(__file__).resolve().parent.parent
DATASET_DIR = BASE_DIR / "datasets"
DATASET_DIR.mkdir(exist_ok=True)

rng = np.random.default_rng(42)

rows = []

# ============================================================
# 1. NORMAL LOGIN SCENARIOS
# ============================================================

for _ in range(1500):

    login_hour = int(rng.integers(7, 22))

    failed_attempts = int(
        rng.choice(
            [0, 1, 2],
            p=[0.78, 0.17, 0.05]
        )
    )

    new_ip = int(
        rng.choice(
            [0, 1],
            p=[0.90, 0.10]
        )
    )

    new_device = int(
        rng.choice(
            [0, 1],
            p=[0.92, 0.08]
        )
    )

    new_location = int(
        rng.choice(
            [0, 1],
            p=[0.95, 0.05]
        )
    )

    login_frequency = int(rng.integers(1, 9))

    session_duration = int(
        rng.integers(60, 601)
    )

    actions_count = int(
        rng.integers(5, 81)
    )

    rows.append([
        login_hour,
        failed_attempts,
        new_ip,
        new_device,
        new_location,
        login_frequency,
        session_duration,
        actions_count,
        0
    ])


# ============================================================
# 2. BORDERLINE / SUSPICIOUS LEGITIMATE LOGINS
# ============================================================

for _ in range(300):

    login_hour = int(
        rng.choice(
            list(range(5, 7)) + list(range(22, 24))
        )
    )

    failed_attempts = int(
        rng.choice([1, 2, 3])
    )

    new_ip = int(
        rng.choice([0, 1], p=[0.45, 0.55])
    )

    new_device = int(
        rng.choice([0, 1], p=[0.50, 0.50])
    )

    new_location = int(
        rng.choice([0, 1], p=[0.60, 0.40])
    )

    login_frequency = int(
        rng.integers(5, 13)
    )

    session_duration = int(
        rng.integers(30, 301)
    )

    actions_count = int(
        rng.integers(5, 50)
    )

    rows.append([
        login_hour,
        failed_attempts,
        new_ip,
        new_device,
        new_location,
        login_frequency,
        session_duration,
        actions_count,
        0
    ])


# ============================================================
# 3. ACCOUNT TAKEOVER SCENARIOS
# ============================================================

for _ in range(1500):

    attack_type = rng.integers(0, 4)

    # --------------------------------------------------------
    # Credential stuffing / brute-force style ATO
    # --------------------------------------------------------

    if attack_type == 0:

        login_hour = int(
            rng.integers(0, 24)
        )

        failed_attempts = int(
            rng.integers(4, 11)
        )

        new_ip = int(
            rng.choice([0, 1], p=[0.15, 0.85])
        )

        new_device = int(
            rng.choice([0, 1], p=[0.20, 0.80])
        )

        new_location = int(
            rng.choice([0, 1], p=[0.25, 0.75])
        )

        login_frequency = int(
            rng.integers(10, 31)
        )

        session_duration = int(
            rng.integers(1, 61)
        )

        actions_count = int(
            rng.integers(0, 16)
        )

    # --------------------------------------------------------
    # Session hijacking
    # --------------------------------------------------------

    elif attack_type == 1:

        login_hour = int(
            rng.integers(0, 24)
        )

        failed_attempts = int(
            rng.integers(0, 4)
        )

        new_ip = 1
        new_device = 1
        new_location = int(
            rng.choice([0, 1], p=[0.20, 0.80])
        )

        login_frequency = int(
            rng.integers(8, 26)
        )

        session_duration = int(
            rng.integers(1, 45)
        )

        actions_count = int(
            rng.integers(0, 12)
        )

    # --------------------------------------------------------
    # Impossible / unusual login
    # --------------------------------------------------------

    elif attack_type == 2:

        login_hour = int(
            rng.choice(
                list(range(0, 6)) + list(range(23, 24))
            )
        )

        failed_attempts = int(
            rng.integers(2, 8)
        )

        new_ip = int(
            rng.choice([0, 1], p=[0.10, 0.90])
        )

        new_device = int(
            rng.choice([0, 1], p=[0.10, 0.90])
        )

        new_location = 1

        login_frequency = int(
            rng.integers(8, 25)
        )

        session_duration = int(
            rng.integers(1, 90)
        )

        actions_count = int(
            rng.integers(0, 20)
        )

    # --------------------------------------------------------
    # Highly suspicious combined attack
    # --------------------------------------------------------

    else:

        login_hour = int(
            rng.integers(0, 6)
        )

        failed_attempts = int(
            rng.integers(6, 15)
        )

        new_ip = 1
        new_device = 1
        new_location = 1

        login_frequency = int(
            rng.integers(15, 35)
        )

        session_duration = int(
            rng.integers(1, 30)
        )

        actions_count = int(
            rng.integers(0, 10)
        )

    rows.append([
        login_hour,
        failed_attempts,
        new_ip,
        new_device,
        new_location,
        login_frequency,
        session_duration,
        actions_count,
        1
    ])


# ============================================================
# CREATE DATAFRAME
# ============================================================

columns = [
    "login_hour",
    "failed_attempts",
    "new_ip",
    "new_device",
    "new_location",
    "login_frequency",
    "session_duration",
    "actions_count",
    "actual"
]

df = pd.DataFrame(rows, columns=columns)

# Shuffle the dataset
df = df.sample(
    frac=1,
    random_state=42
).reset_index(drop=True)


# ============================================================
# SAVE
# ============================================================

output_file = DATASET_DIR / "ato_evaluation_data_v2.csv"

df.to_csv(
    output_file,
    index=False
)

print("=" * 60)
print("ATO V2 EVALUATION DATASET CREATED")
print("=" * 60)

print(f"Dataset : {output_file}")
print(f"Samples : {len(df)}")

print("\nClass distribution:")

print(
    df["actual"]
    .value_counts()
    .rename({
        0: "Normal",
        1: "ATO"
    })
)

print("\nFeature columns:")

for column in columns:
    print(f"- {column}")

print("\nDataset preview:")
print(df.head(10))

print("\nDataset saved successfully.")