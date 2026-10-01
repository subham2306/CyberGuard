# 🛡️ UNIFIED URL & QR INTELLIGENCE — BENCHMARK EVALUATION REPORT

Comprehensive empirical verification of the URL Intelligence Classifier across Standard, Zero-Leakage Unseen Domains, Unseen QR Codes, and Temporal Mutation suites.

## 1. Multi-Level Evaluation Matrix

| Evaluation Set | Samples | Accuracy | Precision | Recall | F1 Score | ROC-AUC | ECE | Status |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Test 1 (Standard Stratified Random)** | 8824 | **97.89%** | 98.74% | 96.55% | **97.63%** | 0.9937 | 0.37% | PASS |
| **Test 2 (Unseen Domains - Zero Leakage)** | 16129 | **96.11%** | 98.84% | 92.15% | **95.38%** | 0.9916 | 2.49% | PASS |
| **Test 3 (Unseen QR Decoded URLs)** | 5942 | **98.94%** | 98.25% | 98.98% | **98.61%** | 0.9981 | 1.35% | PASS |
| **Test 4 (Temporal / Mutation Shift)** | 600 | **97.00%** | 97.96% | 96.00% | **96.97%** | 0.9923 | 1.02% | PASS |

## 2. Confusion Matrix & False Negative Breakdown

| Evaluation Set | True Positives (TP) | False Positives (FP) | True Negatives (TN) | False Negatives (FN) |
| :--- | :---: | :---: | :---: | :---: |
| Test 1 (Standard Stratified Random) | 3833 | 49 | 4805 | 137 |
| Test 2 (Unseen Domains - Zero Leakage) | 6470 | 76 | 9032 | 551 |
| Test 3 (Unseen QR Decoded URLs) | 2242 | 40 | 3637 | 23 |
| Test 4 (Temporal / Mutation Shift) | 288 | 6 | 294 | 12 |

## 3. Generalization & Zero-Leakage Verification Summary
- **Test 1 (Standard Random Holdout)**: Confirms base-distribution performance on seen domains.
- **Test 2 (Unseen Domains Holdout)**: Strictly validates zero-day phishing detection on domains NEVER seen during model training (anti-leakage mathematical assertion).
- **Test 3 (QR Unseen Holdout)**: Demonstrates that the unified model generalizes seamlessly to QR-borne phishing threats without needing a separate QR classifier.
- **Test 4 (Temporal / Mutation Shift)**: Assesses resilience against long, high-entropy, and obfuscated phishing campaigns.
