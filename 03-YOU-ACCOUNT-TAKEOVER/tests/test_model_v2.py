from pathlib import Path
import sys
import json

import matplotlib
matplotlib.use("Agg")

import joblib
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


# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent

DATASET_PATH = (
    BASE_DIR /
    "datasets" /
    "ato_evaluation_data_v2.csv"
)

MODEL_PATH = (
    BASE_DIR /
    "models" /
    "isolation_forest_v2.pkl"
)

EVALUATION_DIR = (
    BASE_DIR /
    "evaluation"
)

EVALUATION_DIR.mkdir(
    exist_ok=True
)


# ============================================================
# LOAD MODEL
# ============================================================

bundle = joblib.load(
    MODEL_PATH
)

model = bundle["model"]

FEATURES = bundle["features"]


# ============================================================
# LOAD EVALUATION DATA
# ============================================================

df = pd.read_csv(
    DATASET_PATH
)

X = df[FEATURES]

y_actual = df["actual"]


# ============================================================
# PREDICT
# ============================================================

raw_predictions = model.predict(X)

# Isolation Forest:
#  1  = normal
# -1  = anomaly

predictions = [
    1 if prediction == -1 else 0
    for prediction in raw_predictions
]


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
print("CYBERGUARD ATO - ISOLATION FOREST V2")
print("MODEL EVALUATION")
print("=" * 60)

print()

print(f"Model          : {MODEL_PATH.name}")
print(f"Dataset        : {DATASET_PATH.name}")
print(f"Samples        : {len(df)}")

print()

print(f"Accuracy       : {accuracy:.4f}")
print(f"Precision      : {precision:.4f}")
print(f"Recall         : {recall:.4f}")
print(f"F1 Score       : {f1:.4f}")

print()

print("Confusion Matrix:")
print(cm)

print()

print("Classification Report:")
print(report)


# ============================================================
# FALSE POSITIVES / FALSE NEGATIVES
# ============================================================

true_normal = cm[0][0]
false_positive = cm[0][1]
false_negative = cm[1][0]
true_ato = cm[1][1]

print()

print("Detection Summary:")
print(f"True Normal       : {true_normal}")
print(f"False Positives   : {false_positive}")
print(f"False Negatives   : {false_negative}")
print(f"True ATO          : {true_ato}")


# ============================================================
# SAVE METRICS
# ============================================================

metrics = {
    "model": MODEL_PATH.name,
    "dataset": DATASET_PATH.name,
    "samples": int(len(df)),
    "accuracy": round(float(accuracy), 4),
    "precision": round(float(precision), 4),
    "recall": round(float(recall), 4),
    "f1_score": round(float(f1), 4),
    "true_normal": int(true_normal),
    "false_positive": int(false_positive),
    "false_negative": int(false_negative),
    "true_ato": int(true_ato),
    "confusion_matrix": cm.tolist()
}


metrics_path = (
    EVALUATION_DIR /
    "model_v2_metrics.json"
)

with open(
    metrics_path,
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

report_path = (
    EVALUATION_DIR /
    "model_v2_report.txt"
)

with open(
    report_path,
    "w",
    encoding="utf-8"
) as file:

    file.write(
        "CYBERGUARD ATO - ISOLATION FOREST V2\n"
    )

    file.write(
        "MODEL EVALUATION\n"
    )

    file.write(
        "=" * 50 + "\n\n"
    )

    file.write(
        f"Model   : {MODEL_PATH.name}\n"
    )

    file.write(
        f"Dataset : {DATASET_PATH.name}\n"
    )

    file.write(
        f"Samples : {len(df)}\n\n"
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
        "Detection Summary:\n"
    )

    file.write(
        f"True Normal     : {true_normal}\n"
    )

    file.write(
        f"False Positives : {false_positive}\n"
    )

    file.write(
        f"False Negatives : {false_negative}\n"
    )

    file.write(
        f"True ATO        : {true_ato}\n\n"
    )

    file.write(
        "Confusion Matrix:\n"
    )

    file.write(
        str(cm)
    )

    file.write(
        "\n\nClassification Report:\n"
    )

    file.write(report)


# ============================================================
# CONFUSION MATRIX IMAGE
# ============================================================

plt.figure(
    figsize=(6, 5)
)

plt.imshow(cm)

plt.title(
    "CyberGuard ATO - Isolation Forest V2"
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


matrix_path = (
    EVALUATION_DIR /
    "model_v2_confusion_matrix.png"
)

plt.savefig(
    matrix_path,
    dpi=150
)

plt.close()


# ============================================================
# COMPLETE
# ============================================================

print()

print("=" * 60)
print("MODEL V2 EVALUATION COMPLETED")
print("=" * 60)

print()

print("Files created:")

print(metrics_path)
print(report_path)
print(matrix_path)