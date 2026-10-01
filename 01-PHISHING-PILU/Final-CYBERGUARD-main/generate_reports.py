import os
import json
import pickle
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, roc_curve, precision_recall_curve, confusion_matrix
)
from sklearn.calibration import calibration_curve

from url_intelligence.url_features import URLFeatureExtractor
from url_intelligence.preprocessing import URLCanonicalizer

DATA_DIR = r'.\data'
SAVED_MODELS_DIR = r'.\saved_models'
REPORTS_DIR = r'.\reports'
BUNDLE_PATH = os.path.join(SAVED_MODELS_DIR, 'url_intelligence_bundle.pkl')

def run_evaluation_and_generate_plots():
    os.makedirs(REPORTS_DIR, exist_ok=True)

    with open(BUNDLE_PATH, 'rb') as f:
        bundle = pickle.load(f)

    model = bundle['model']
    scaler = bundle['scaler']
    calibrator = bundle['calibrator']
    extractor = URLFeatureExtractor()

    test_suites = [
        ("Random Test", "test_random.csv"),
        ("Unseen Domain Test", "test_unseen_domain.csv"),
        ("Unseen QR Test", "test_qr_unseen.csv"),
        ("Temporal Test", "test_temporal.csv")
    ]

    all_metrics = {}
    curves_data = {}

    for name, filename in test_suites:
        filepath = os.path.join(DATA_DIR, filename)
        if not os.path.exists(filepath):
            continue

        df = pd.read_csv(filepath)
        y_true = df['label'].values

        X = []
        for row in df.itertuples(index=False):
            f_dict = extractor.extract_features(row.normalized_url)
            X.append([f_dict[k] for k in extractor.FEATURE_NAMES])
        X = np.array(X, dtype=np.float32)

        X_scaled = scaler.transform(X)
        raw_probs = model.predict_proba(X_scaled)[:, 1]
        cal_probs = calibrator.predict(raw_probs)
        preds = (cal_probs >= 0.5).astype(int)

        acc = float(accuracy_score(y_true, preds))
        prec = float(precision_score(y_true, preds, zero_division=0))
        rec = float(recall_score(y_true, preds, zero_division=0))
        f1 = float(f1_score(y_true, preds, zero_division=0))
        auc = float(roc_auc_score(y_true, cal_probs))

        cm = confusion_matrix(y_true, preds)
        tn, fp, fn, tp = [int(v) for v in cm.ravel()]
        fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
        fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0

        all_metrics[name] = {
            "samples": len(df),
            "accuracy": round(acc * 100, 2),
            "precision": round(prec * 100, 2),
            "recall": round(rec * 100, 2),
            "f1": round(f1 * 100, 2),
            "roc_auc": round(auc, 4),
            "false_positive_rate": round(fpr * 100, 2),
            "false_negative_rate": round(fnr * 100, 2),
            "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn}
        }

        curves_data[name] = {
            "y_true": y_true,
            "cal_probs": cal_probs,
            "preds": preds,
            "cm": cm
        }

    # Save final_evaluation.json
    with open(os.path.join(REPORTS_DIR, 'final_evaluation.json'), 'w', encoding='utf-8') as f:
        json.dump(all_metrics, f, indent=2)

    # Save final_evaluation.txt
    txt_out = "="*70 + "\n"
    txt_out += "FINAL EVALUATION & GENERALIZATION REPORT\n"
    txt_out += "="*70 + "\n\n"
    for suite, m in all_metrics.items():
        txt_out += f"--- {suite} ({m['samples']} samples) ---\n"
        txt_out += f"  Accuracy:            {m['accuracy']}%\n"
        txt_out += f"  Precision:           {m['precision']}%\n"
        txt_out += f"  Recall:              {m['recall']}%\n"
        txt_out += f"  F1 Score:            {m['f1']}%\n"
        txt_out += f"  ROC-AUC:             {m['roc_auc']}\n"
        txt_out += f"  False Positive Rate: {m['false_positive_rate']}%\n"
        txt_out += f"  False Negative Rate: {m['false_negative_rate']}%\n"
        txt_out += f"  TP: {m['confusion_matrix']['tp']}, FP: {m['confusion_matrix']['fp']}, TN: {m['confusion_matrix']['tn']}, FN: {m['confusion_matrix']['fn']}\n\n"

    with open(os.path.join(REPORTS_DIR, 'final_evaluation.txt'), 'w', encoding='utf-8') as f:
        f.write(txt_out)
    print("Saved final_evaluation.json and final_evaluation.txt")

    # 1. Confusion Matrix Plot
    fig, axes = plt.subplots(2, 2, figsize=(11, 9))
    axes = axes.flatten()
    for idx, (suite, data) in enumerate(curves_data.items()):
        ax = axes[idx]
        sns.heatmap(data['cm'], annot=True, fmt='d', cmap='Blues', ax=ax,
                    xticklabels=['Benign', 'Malicious'], yticklabels=['Benign', 'Malicious'])
        ax.set_title(f"{suite}")
        ax.set_xlabel('Predicted Label')
        ax.set_ylabel('True Label')
    plt.tight_layout()
    plt.savefig(os.path.join(REPORTS_DIR, 'confusion_matrix.png'), dpi=200)
    plt.close()

    # 2. ROC Curve Plot
    plt.figure(figsize=(8, 6))
    for suite, data in curves_data.items():
        fpr, tpr, _ = roc_curve(data['y_true'], data['cal_probs'])
        plt.plot(fpr, tpr, lw=2, label=f"{suite} (AUC = {all_metrics[suite]['roc_auc']})")
    plt.plot([0, 1], [0, 1], 'k--', lw=1.5)
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title('Receiver Operating Characteristic (ROC) Across Test Sets')
    plt.legend(loc='lower right')
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(os.path.join(REPORTS_DIR, 'roc_curve.png'), dpi=200)
    plt.close()

    # 3. Precision-Recall Curve Plot
    plt.figure(figsize=(8, 6))
    for suite, data in curves_data.items():
        prec, rec, _ = precision_recall_curve(data['y_true'], data['cal_probs'])
        plt.plot(rec, prec, lw=2, label=f"{suite} (F1 = {all_metrics[suite]['f1']}%)")
    plt.xlabel('Recall')
    plt.ylabel('Precision')
    plt.title('Precision-Recall Curve Across Test Sets')
    plt.legend(loc='lower left')
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(os.path.join(REPORTS_DIR, 'pr_curve.png'), dpi=200)
    plt.close()

    # 4. Calibration Curve Plot
    plt.figure(figsize=(8, 6))
    for suite, data in curves_data.items():
        prob_true, prob_pred = calibration_curve(data['y_true'], data['cal_probs'], n_bins=10)
        plt.plot(prob_pred, prob_true, marker='o', lw=2, label=f"{suite}")
    plt.plot([0, 1], [0, 1], 'k--', lw=1.5, label='Perfectly Calibrated')
    plt.xlabel('Mean Predicted Probability')
    plt.ylabel('Fraction of Positives')
    plt.title('Probability Calibration Reliability Curve')
    plt.legend(loc='lower right')
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(os.path.join(REPORTS_DIR, 'calibration_curve.png'), dpi=200)
    plt.close()

    print("All evaluation plots generated successfully in reports/")

if __name__ == '__main__':
    run_evaluation_and_generate_plots()
