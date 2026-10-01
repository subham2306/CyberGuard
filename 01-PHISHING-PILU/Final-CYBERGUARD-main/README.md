# CyberGuard — Digital Threat Intelligence

[![Python Version](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/Backend-FastAPI-009688.svg)](https://fastapi.tiangolo.com/)
[![Deep Learning](https://img.shields.io/badge/ML-PyTorch%20%7C%20Scikit--Learn-EE4C2C.svg)](https://pytorch.org/)
[![Computer Vision](https://img.shields.io/badge/Vision-OpenCV%204.x-5C3EE8.svg)](https://opencv.org/)
[![License](https://img.shields.io/badge/Status-Hackathon%20Delivery-00FF87.svg)](#)

> **"Analyze the threat before it reaches you."**  
> CyberGuard is an enterprise-grade digital threat intelligence platform that analyzes **Messages (Email, SMS, Social Chat)**, **Direct URLs**, and **Optical QR Codes** using dual-branch machine learning, isotonic risk calibration, and explainable AI (XAI).

---

## 1. Project Overview & Problem Statement

Digital communication channels are constantly exploited by attackers through sophisticated social engineering:
- **Smishing & Phishing:** Urgency-driven text messages and credential harvesting emails designed to bypass traditional keyword filters.
- **Malicious URL Infrastructure:** Disposable domains (`.xyz`, `.top`, `.tk`), typosquatting, high entropy paths, and unencrypted HTTP credential forms.
- **Quishing (QR Code Phishing):** Deceptive physical or digital QR codes that conceal malicious destinations from basic text crawlers.

**CyberGuard** solves this through a unified multi-modal AI architecture. Incoming threats are canonicalized, parsed into semantic representations and programmatic feature vectors, scored by calibrated machine learning models, and paired with human-interpretable XAI justifications and actionable security recommendations.

---

## 2. Key Features

- **Multi-Vector Threat Defense:** Unified intelligence across three primary digital entry points:
  - **Message Intelligence:** Sub-analyzers for Email, SMS/Text, and Social/Chat conversations.
  - **URL Intelligence:** Deep lexical, structural, entropy, and top-level domain (TLD) risk analysis.
  - **QR Threat Scanner:** Multi-stage OpenCV optical decoding pipeline that routes extracted URLs into deep URL intelligence (zero mock/dummy inference).
- **Calibrated Risk Scoring (0–100):** Probabilities calibrated via `IsotonicRegression` mapped to strictly defined security severity tiers.
- **Explainable AI (XAI):**
  - Model gradient saliency attribution for suspicious message language patterns.
  - Structural heuristic signatures (42 engineered lexical indicators) for URLs.
- **Action Recommendation Engine:** Deterministic mapping to clear operational actions: `ALLOW`, `FLAG_SUSPICIOUS (WARN)`, `BLOCK_LINK (BLOCK)`, and `QUARANTINE`.
- **Zero-Dependency Frontend:** High-performance, ultra-refined dark glassmorphism interface built with Vanilla HTML5, CSS3, and ES6+ JavaScript. **No Node.js or npm required**—served directly by the FastAPI backend.
- **Local Audit Trail:** Client-side assessment history with filtering across vectors (ALL, MESSAGE, URL, QR) and one-click re-inspection.

---

## 3. System Architecture

```text
USER INTERACTION
       │
       ├── [1] Message (Email / SMS / Social)
       ├── [2] Direct URL
       └── [3] QR Code Image
               │
               ▼
CYBERGUARD FRONTEND (Vanilla HTML5 / CSS3 / ES6+)
• SOC Dark Glassmorphism Command Center
• Threat Core Radar Telemetry Visualizer
• Dynamic Vector Switcher & Local Audit Trail
               │
               ▼ (REST JSON / Multipart Form-Data)
FASTAPI BACKEND HUB (cyberguard/api.py)
       │
       ├───────────────────────────────┬───────────────────────────────┐
       ▼                               ▼                               ▼
[MESSAGE ML PIPELINE]         [DIRECT URL PIPELINE]           [QR OPTICAL PIPELINE]
• 21-d Cyber Feature Vector   • URL Canonicalizer             • Multi-stage OpenCV Vision
• Text Semantic Embeddings    • 42-d Lexical & TLD Features   • Optical Payload Extractor
• CyberGuard Hybrid Model     • Hybrid CNN + Feature MLP      • Traced to URL Engine
       │                               │                               │
       │                               └───────────────┬───────────────┘
       │                                               │
       ▼                                               ▼
ISOTONIC RISK ENGINE (0-100)                    ISOTONIC RISK ENGINE (0-100)
Threshold: LOW / MEDIUM / HIGH / CRITICAL       Threshold: LOW / MEDIUM / HIGH / CRITICAL
       │                                               │
       ▼                                               ▼
DUAL XAI ATTRIBUTION (Grads + Rules)            URL EXPLAINER (Structural Signatures)
       │                                               │
       └───────────────────────┬───────────────────────┘
                               │
                               ▼
                   UNIFIED SECURITY ASSESSMENT
                   • Calibrated Risk Score (0–100)
                   • Severity Tier (LOW, MEDIUM, HIGH, CRITICAL)
                   • Recommended Action (ALLOW, WARN, BLOCK, QUARANTINE)
                   • Explainable Indicators & Suspicious Tokens
```

---

## 4. Technology Stack

### Backend & Machine Learning
- **Framework:** [FastAPI](https://fastapi.tiangolo.com/) with [Uvicorn](https://www.uvicorn.org/) ASGI server
- **Language:** Python 3.10+
- **Deep Learning / Neural Models:** [PyTorch](https://pytorch.org/) (`torch.nn`, Tensor character embeddings)
- **Classical ML & Calibration:** [Scikit-learn](https://scikit-learn.org/) (`IsotonicRegression`, Feature Scalers), [XGBoost](https://xgboost.readthedocs.io/)
- **Computer Vision:** [OpenCV](https://opencv.org/) (`cv2.QRCodeDetector`, CLAHE contrast enhancement, multi-scale augmentation)
- **Data Engineering:** [Pandas](https://pandas.pydata.org/), [NumPy](https://numpy.org/), [TLDExtract](https://github.com/john-kurkowski/tldextract)

### Frontend
- **Framework:** Vanilla HTML5, Modern CSS3, ES6+ JavaScript
- **Serving:** Mounted directly via FastAPI `StaticFiles`
- **Aesthetics:** Apple/Linear-inspired dark glassmorphism, animated radar threat core, neon green signal highlights, soft pink secondary accents
- **Dependencies:** Zero external npm packages or build steps required

---

## 5. Project Directory Structure

```text
cyberguard/
│
├── README.md                      # Comprehensive project documentation
├── requirements.txt               # Verified Python runtime dependencies
├── .env.example                   # Environment configuration template
├── .gitignore                     # Git exclusion rules
├── run_cyberguard.bat             # 1-Click Windows launch script
│
├── cyberguard/                    # Message Phishing ML & Core API
│   ├── __init__.py
│   ├── api.py                     # FastAPI Hub, routes, and static mount
│   ├── clustering.py              # Semantic message clustering
│   ├── evaluate.py                # Message model evaluation metrics
│   ├── features.py                # 21-d Programmatic feature extractor
│   ├── model.py                   # CyberGuardHybridModel (Semantic + Features)
│   ├── risk_engine.py             # Isotonic risk calibration & threshold tiers
│   ├── train.py                   # Model training routines
│   └── xai.py                     # Dual-source model attribution & rules
│
├── url_intelligence/              # Direct URL & QR Code Intelligence
│   ├── __init__.py
│   ├── inference.py               # URLIntelligenceEngine (End-to-end evaluation)
│   ├── model.py                   # Hybrid 1D-CNN + MLP architecture
│   ├── preprocessing.py           # Canonicalization & root domain extraction
│   ├── tokenizer.py               # Character sequence tokenizer
│   ├── url_features.py            # 42-d Lexical, structural & TLD features
│   ├── qr/
│   │   └── decoder.py             # Multi-stage OpenCV QR vision decoder
│   ├── risk/
│   │   ├── calibration.py         # Probability calibration
│   │   ├── recommendation.py      # Action decision policy
│   │   └── risk_engine.py         # URL risk scoring
│   └── xai/
│       └── explainer.py           # Feature indicator explainability
│
├── saved_models/                  # Pre-trained production model bundles
│   ├── cyberguard_bundle.pt       # PyTorch weights, vectorizer, and scaler
│   └── url_intelligence_bundle.pkl # URL model weights, scaler, and calibrator
│
├── frontend/                      # Web user interface
│   ├── index.html                 # Semantic HTML structure & command dock
│   ├── css/
│   │   └── styles.css             # Glassmorphism, animations & design system
│   ├── js/
│   │   ├── api.js                 # API client with auto port discovery
│   │   ├── main.js                # Event orchestration & canvas nodes
│   │   └── ui.js                  # DOM management, risk gauge & history
│   └── samples/                   # Real QR sample images for live testing
│       ├── benign_sample.png      # Wikipedia benign QR code
│       └── phishing_sample.png    # Credential harvesting QR code
│
├── tests/                         # Automated test suites
│   ├── test_messages.py           # Message classification verification
│   ├── test_qr_decoder.py         # QR decoder augmentations test suite
│   ├── test_api_client.py         # End-to-end REST API verification suite
│   ├── evaluate_messages.py       # Detailed message benchmark runner
│   └── qr_samples/                # 10 diverse augmented test QR images
│
├── scripts/                       # Teacher-friendly helper scripts
│   ├── setup_windows.ps1          # Automated venv creation & pip install
│   └── run_windows.ps1            # Automated startup with port fallback
│
└── data/                          # Benchmark and validation datasets
    ├── train.csv
    ├── validation.csv
    ├── test_random.csv
    ├── test_qr_unseen.csv
    └── unified_url_clean.csv
```

---

## 6. Installation & Setup

### Prerequisites
- **Operating System:** Windows 10/11, macOS, or Linux
- **Python:** Python 3.10, 3.11, 3.12, or 3.13
- **Network:** Internet access for initial `pip install`

---

### Option A: 1-Click Automated Setup (Windows)

1. Open PowerShell in the project folder and run:
   ```powershell
   .\scripts\setup_windows.ps1
   ```
2. The script will automatically:
   - Verify your Python installation.
   - Create a clean `.venv` virtual environment.
   - Upgrade `pip` and install all packages from `requirements.txt`.

---

### Option B: Manual Setup (Windows / macOS / Linux)

1. **Clone or Extract Repository:**
   ```bash
   cd cyberguard-2-main
   ```

2. **Create a Virtual Environment:**
   ```bash
   python -m venv .venv
   ```

3. **Activate Virtual Environment:**
   - **Windows (PowerShell):**
     ```powershell
     .\.venv\Scripts\Activate.ps1
     ```
   - **Windows (Command Prompt):**
     ```cmd
     .venv\Scripts\activate.bat
     ```
   - **macOS / Linux:**
     ```bash
     source .venv/bin/activate
     ```

4. **Install Dependencies:**
   ```bash
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

---

## 7. Running CyberGuard

### Option A: 1-Click Launch (Windows)
Double-click:
```text
run_cyberguard.bat
```
*(Or run `.\scripts\run_windows.ps1` in PowerShell)*

This automatically detects available ports (8000 or 8001), starts the server, and launches your default web browser to `http://127.0.0.1:8000/`.

---

### Option B: Manual Terminal Launch
From the project root directory, run:
```bash
python -m uvicorn cyberguard.api:app --host 127.0.0.1 --port 8000
```

> **Note on Port Conflicts:**  
> If port `8000` is in use by another local service (e.g., Splunk or system daemons), run on port `8001`:
> ```bash
> python -m uvicorn cyberguard.api:app --host 127.0.0.1 --port 8001
> ```

Open your browser and navigate to:  
👉 **`http://127.0.0.1:8000/`** (or `http://127.0.0.1:8001/`)

---

## 8. Verification & Testing

CyberGuard includes dedicated standalone verification test suites. Run any of the following commands from the project root:

### 1. Test All API Endpoints End-to-End
Verifies `/health`, Message detection, URL detection, and QR multipart upload:
```bash
python tests/test_api_client.py
```
*Expected output: All 4 endpoints return HTTP 200 with calibrated inference.*

### 2. Test Message Model Phishing Detection
Runs diverse benign vs. phishing samples across Email, SMS, and Social channels:
```bash
python tests/test_messages.py
```

### 3. Test OpenCV Optical QR Decoder
Evaluates QR decoding across 10 augmented conditions (normal, rotated 90°, rotated 180°, low contrast, inverted, noisy, downscaled):
```bash
python tests/test_qr_decoder.py
```
*Expected output: 10/10 successful decodes (100.0% decode rate).*

---

## 9. How to Use the Interface

### 1. Message Intelligence
1. Navigate to the **MESSAGE** workspace tab.
2. Select the sub-channel: **EMAIL**, **SMS**, or **SOCIAL MEDIA**.
3. Paste message text or click one of the demo buttons:
   - `⚠️ Urgent Phishing`
   - `✓ Safe Message`
4. Click **ANALYZE MESSAGE**.
5. Inspect the calibrated risk score, severity badge, model indicators, and recommended action.

### 2. URL Intelligence
1. Navigate to the **URL** workspace tab.
2. Enter a full destination URL (e.g., `http://secure-login-apple.xyz/verify?token=92841`) or click `⚠️ Apple Phishing (.xyz)`.
3. Click **ANALYZE URL**.
4. The system inspects protocol security, domain entropy, TLD risk, and lexical indicators.

### 3. QR Threat Scanner
1. Navigate to the **QR CODE** workspace tab.
2. Drag and drop a QR code image (PNG, JPG, WEBP) or click `⚠️ Malicious QR` to load a pre-configured sample.
3. Click **ANALYZE QR**.
4. The laser scanning chamber visualizes decoding progress.
5. The extracted destination URL is displayed and seamlessly routed to the URL Intelligence Engine.

### 4. Audit History
1. Click **HISTORY** in the top navigation capsule.
2. Filter through past analyses using the pills: **ALL**, **MESSAGES**, **URLS**, or **QR CODES**.
3. Click **RE-INSPECT →** on any record to view its full threat report.
4. Click **COPY THREAT REPORT** to export a formatted summary to your clipboard.

---

## 10. Risk Scoring & Policy Mapping

The Risk Engine maps calibrated probabilities to standardized cybersecurity operational actions:

| Risk Score | Severity Tier | Operational Meaning | Recommended Action |
|:---:|:---:|:---|:---:|
| **0 – 24** | **LOW** | Clean signals, standard communication | `ALLOW` |
| **25 – 49** | **MEDIUM** | Ambiguous signals, proceed with caution | `FLAG_SUSPICIOUS (WARN)` |
| **50 – 79** | **HIGH** | Structural anomalies, unverified credentials | `BLOCK_LINK (BLOCK)` |
| **80 – 100** | **CRITICAL** | Confirmed credential theft or phishing indicators | `QUARANTINE` |

---

## 11. Backend API Reference

### Health Check
- **Endpoint:** `GET /health`
- **Response:**
  ```json
  {
    "status": "online",
    "message_module": "active",
    "url_module": "active",
    "url_bundle_loaded": true,
    "version": "2.0.0"
  }
  ```

### Message Detection
- **Endpoint:** `POST /api/v1/detect`
- **Payload:** `{"text": "URGENT: Verify account at http://bit.ly/sbi-acc", "channel": "SMS"}`
- **Response:** Risk score, calibrated probability, severity tier, indicators, suspicious tokens, recommendation.

### URL Detection
- **Endpoint:** `POST /predict_url` (or `/api/v1/detect/url`)
- **Payload:** `{"url": "http://secure-login-apple.xyz/verify?token=92841"}`
- **Response:** Risk score, classification (`malicious`/`benign`), lexical indicators, recommendation.

### QR Code Detection
- **Endpoint:** `POST /detect_qr` (or `/api/v1/detect/qr`)
- **Payload:** `multipart/form-data` with form field `file`
- **Response:** Decoded URL, payload type, URL intelligence risk analysis, indicators, action.

---

## 12. Troubleshooting & FAQ

1. **Port 8000 is occupied / returns 404:**
   - Some machines have local services (e.g. Splunk) bound to port 8000.
   - Simply start on port 8001:
     ```bash
     python -m uvicorn cyberguard.api:app --host 127.0.0.1 --port 8001
     ```
   - The frontend automatically auto-detects whether the backend is running on port 8000 or 8001!

2. **PyTorch CPU vs GPU:**
   - CyberGuard runs inference efficiently on CPU (`device = 'cpu'`) with sub-50ms latency. No dedicated GPU is required.

3. **`cv2` / OpenCV Headless Environments:**
   - If deploying to a headless Linux server without X11, replace `opencv-python` with `opencv-python-headless` in `requirements.txt`.

---

## 13. Academic / Hackathon Submission Note

- **Project:** CyberGuard — Digital Threat Intelligence
- **Event:** BPUT Hackathon
- **Focus:** AI-powered Phishing & Quishing Interception
- **Architecture Integrity:** Real ML inference, genuine optical QR decoding, and explainable AI attribution. No simulated results or mock data.