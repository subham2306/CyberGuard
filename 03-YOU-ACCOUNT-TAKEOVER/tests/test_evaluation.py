from pathlib import Path
import sys
import json

import pandas as pd
import matplotlib.pyplot as plt

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)

BASE_DIR = Path(__file__).resolve().parent.parent

if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from app.anomaly_model import predict_anomaly


# ============================================================
# PATHS
# ============================================================

DATASET = BASE_DIR / "datasets" / "ato_evaluation_data_v2.csv"
EVALUATION_DIR = BASE_DIR / "evaluation"

EVALUATION_DIR.mkdir(exist_ok=True)


# ============================================================
# LOAD DATASET
# ============================================================

df = pd.read_csv(DATASET)

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
y_actual = df["actual"]


# ============================================================
# RUN MODEL
# ============================================================

predictions = []
risk_scores = []

for _, row in X.iterrows():

    result = predict_anomaly(
        row.to_dict()
    )

    # Isolation Forest:
    # -1 = anomaly
    #  1 = normal

    if result["prediction"] == -1:
        predicted = 1
    else:
        predicted = 0

    predictions.append(predicted)
    risk_scores.append(
        result["ml_risk_score"]
    )


# ============================================================
# METRICS
# ============================================================

accuracy = accuracy_score(
    y_actual,
    predictions
)

precision = precision_score(
    y_actual,
    predictions,
    zero_division=0
)

recall = recall_score(
    y_actual,
    predictions,
    zero_division=0
)

f1 = f1_score(
    y_actual,
    predictions,
    zero_division=0
)

cm = confusion_matrix(
    y_actual,
    predictions
)

report = classification_report(
    y_actual,
    predictions,
    target_names=[
        "Normal",
        "ATO / Anomalous"
    ],
    zero_division=0
)


# ============================================================
# PRINT RESULTS
# ============================================================

print("=" * 60)
print("CYBERGUARD ATO - V2 MODEL EVALUATION")
print("=" * 60)

print(f"Dataset samples : {len(df)}")

print()
print(f"Accuracy  : {accuracy:.4f}")
print(f"Precision : {precision:.4f}")
print(f"Recall    : {recall:.4f}")
print(f"F1 Score  : {f1:.4f}")

print()
print("Confusion Matrix:")
print(cm)

print()
print("Classification Report:")
print(report)


# ============================================================
# SAVE METRICS
# ============================================================

metrics = {
    "dataset": "ato_evaluation_data_v2.csv",
    "samples": len(df),
    "accuracy": round(float(accuracy), 4),
    "precision": round(float(precision), 4),
    "recall": round(float(recall), 4),
    "f1_score": round(float(f1), 4),
    "confusion_matrix": cm.tolist()
}

metrics_file = (
    EVALUATION_DIR /
    "metrics_v2.json"
)

with open(
    metrics_file,
    "w",
    encoding="utf-8"
) as file:

    json.dump(
        metrics,
        file,
        indent=4
    )


# ============================================================
# SAVE REPORT
# ============================================================

report_file = (
    EVALUATION_DIR /
    "evaluation_report_v2.txt"
)

with open(
    report_file,
    "w",
    encoding="utf-8"
) as file:

    file.write(
        "CYBERGUARD ATO - V2 MODEL EVALUATION\n"
    )

    file.write(
        "=" * 50 + "\n\n"
    )

    file.write(
        f"Dataset samples : {len(df)}\n\n"
    )

    file.write(
        f"Accuracy  : {accuracy:.4f}\n"
    )

    file.write(
        f"Precision : {precision:.4f}\n"
    )

    file.write(
        f"Recall    : {recall:.4f}\n"
    )

    file.write(
        f"F1 Score  : {f1:.4f}\n\n"
    )

    file.write(
        "Confusion Matrix:\n"
    )

    file.write(
        str(cm) + "\n\n"
    )

    file.write(
        "Classification Report:\n"
    )

    file.write(report)


# ============================================================
# CONFUSION MATRIX IMAGE
# ============================================================

plt.figure(figsize=(6, 5))

plt.imshow(cm)

plt.title(
    "CyberGuard ATO - V2 Confusion Matrix"
)

plt.xlabel(
    "Predicted"
)

plt.ylabel(
    "Actual"
)

plt.xticks(
    [0, 1],
    ["Normal", "ATO"]
)

plt.yticks(
    [0, 1],
    ["Normal", "ATO"]
)

for i in range(2):

    for j in range(2):

        plt.text(
            j,
            i,
            cm[i, j],
            ha="center",
            va="center"
        )

plt.tight_layout()

confusion_file = (
    EVALUATION_DIR /
    "confusion_matrix_v2.png"
)

plt.savefig(
    confusion_file,
    dpi=150
)

plt.close()


# ============================================================
# COMPLETE
# ============================================================

print()
print("=" * 60)
print("V2 EVALUATION COMPLETED")
print("=" * 60)

print(f"Metrics  : {metrics_file}")
print(f"Report   : {report_file}")
print(f"Matrix   : {confusion_file}")