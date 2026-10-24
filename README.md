# CyberGuard AI

**AI-powered cyber threat detection, correlation, and response --- built
as a cybersecurity hackathon project.**

CyberGuard AI integrates multiple detection modules behind a unified
dashboard. It is designed to analyze suspicious messages and URLs,
detect digital impersonation, assess account-takeover signals, and
correlate results through a central service.

> **Project status:** Demonstration / hackathon project, not a
> production-ready security product. Some Command Center statistics and
> event cards are static demo data; see [Security notes and
> limitations](#security-notes-and-limitations).

## Features

-   **Phishing detection:** analyzes suspicious messages and URLs.
-   **Digital impersonation detection:** evaluates sender identity and
    message signals for possible impersonation.
-   **Account takeover (ATO) detection:** combines rule-based login
    signals and anomaly scoring.
-   **CyberGuard Sentinel:** routes analysis requests and correlates
    results from the detection modules.
-   **Streamlit dashboard:** provides a unified interface for analysis
    and service health.
-   **Dashboard authentication:** local user accounts with salted
    PBKDF2-SHA256 password hashes.
-   **Security event logging:** stores selected detection results in a
    local SQLite database.

## Architecture

``` text
Streamlit Dashboard :8501
          |
          v
CyberGuard Sentinel :8010
   |          |           |
   v          v           v
Phishing   Digital      Account
Detection  Impersonation Takeover
:8001      :8002         :8000
```

Sentinel routes requests to the appropriate module and can correlate
module results. The dashboard calls Sentinel and displays returned
analysis.

## Services and ports

  Service                         Port Health endpoint
  --------------------------- -------- --------------------------------
  Account Takeover API          `8000` `http://127.0.0.1:8000/health`
  Phishing Detection API        `8001` `http://127.0.0.1:8001/health`
  Digital Impersonation API     `8002` `http://127.0.0.1:8002/health`
  CyberGuard Sentinel           `8010` `http://127.0.0.1:8010/health`
  Streamlit Dashboard           `8501` `http://localhost:8501`

These are the local development ports currently used by the project.
Keep the services running while testing integrated analysis.

## Technology stack

-   Python
-   FastAPI and Uvicorn for REST APIs
-   Streamlit for the dashboard
-   Scikit-learn, NumPy, and Pandas for machine-learning and data
    processing
-   SQLite for local dashboard users and security event records
-   Requests for inter-service HTTP communication

## Repository layout

``` text
CYBERGUARD-AI/
├── 01-PHISHING-PILU/
│   └── Final-CYBERGUARD-main/
├── 02-DIGITAL-IMPERSONATION-ABHIJIT/
│   └── hackwins-main/
├── 03-YOU-ACCOUNT-TAKEOVER/
├── 04-CYBERGUARD-SENTINEL/
│   ├── app/
│   └── tests/
├── 05-CYBERGUARD-DASHBOARD/
│   ├── app.py
│   ├── app_header_test.py
│   ├── backend/
│   │   ├── auth.py
│   │   ├── database.py
│   │   ├── events.py
│   │   └── login.py
│   ├── pages/
│   │   └── 1_Command_Dashboard.py
│   └── seed_users.py
└── README.md
```

This is an abbreviated tree; modules may contain additional model,
dataset, test, and notebook files.

## Prerequisites

-   Python compatible with the dependencies used by each module
-   Git
-   Required Python packages for each module

Check each module for its dependency file. Some modules may use a shared
virtual environment in the current development setup. Do not commit
virtual environments.

## Run locally

### 1. Clone the repository

``` bash
git clone https://github.com/subham2306/CyberGuard.git
cd CyberGuard
```

### 2. Create a virtual environment

Example for Windows PowerShell:

``` powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Install the dependencies required by each module. If a module does not
include a dependency file, refer to its source code and project notes
for the required packages.

### 3. Start the APIs

Open a separate PowerShell terminal for each service. Run commands from
the repository root:

**Account Takeover API**

``` powershell
cd .\03-YOU-ACCOUNT-TAKEOVER
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

**Phishing Detection API**

``` powershell
cd .\01-PHISHING-PILU\Final-CYBERGUARD-main
python -m uvicorn cyberguard.api:app --host 127.0.0.1 --port 8001
```

**Digital Impersonation API**

``` powershell
cd .\02-DIGITAL-IMPERSONATION-ABHIJIT\hackwins-main
python -m uvicorn app.main:app --app-dir .\api --host 127.0.0.1 --port 8002
```

**CyberGuard Sentinel**

``` powershell
cd .\04-CYBERGUARD-SENTINEL
python -m uvicorn app.main:app --host 127.0.0.1 --port 8010
```

Activate the environment containing each module's dependencies before
starting its service.

### 4. Start the dashboard

In another terminal:

``` powershell
cd .\05-CYBERGUARD-DASHBOARD
streamlit run .\app.py
```

Open <http://localhost:8501>. The dashboard uses Sentinel at
`http://127.0.0.1:8010`; the detection modules and Sentinel must be
running for integrated analysis and health checks.

## Dashboard authentication setup

From the dashboard directory, initialize the local database and create
accounts interactively:

``` powershell
python .\seed_users.py
```

The script prompts for passwords and confirmation rather than requiring
passwords in source code. The local database is named
`cyberguard_dashboard.db`; it should remain untracked.

The setup script prompts to create accounts named `admin` and `user`
with `ADMIN` and `USER` roles. Use strong, unique passwords. The Command
Center page restricts access to users with the `ADMIN` role.

This is demo authentication. Review and harden session handling, rate
limiting, password recovery, and authorization before any deployment
beyond a trusted local environment.

## API overview

### Account Takeover API

-   `GET /health`
-   `POST /login`
-   `POST /mfa/verify`
-   `POST /session/create`
-   `POST /session/check`
-   `POST /session/revoke`
-   `GET /blocked-ips`
-   `GET /sessions`
-   `GET /session/statistics`

### Phishing Detection API

-   `GET /health`
-   `POST /api/v1/detect` --- analyze a message
-   `POST /predict_url` --- analyze a URL

### Digital Impersonation API

-   `GET /health`
-   The analysis request accepts sender, recipient, reply-to, date/time,
    subject, and message fields.

### CyberGuard Sentinel

-   `GET /health`
-   `POST /api/v1/analyze` --- route an analysis request
-   `POST /api/v1/correlate` --- correlate supplied module results

For exact request schemas and response fields, inspect the API schemas
and source code. FastAPI interactive documentation may be available at
`/docs` for each running service.

## Example requests

Check Sentinel health:

``` powershell
Invoke-RestMethod "http://127.0.0.1:8010/health"
```

Analyze a sample message through Sentinel:

``` powershell
$body = @{
    type = "message"
    text = "Urgent: verify your account using this suspicious link"
} | ConvertTo-Json

Invoke-RestMethod `
    -Uri "http://127.0.0.1:8010/api/v1/analyze" `
    -Method Post `
    -ContentType "application/json" `
    -Body $body
```

Only test messages, URLs, accounts, and systems you own or are
authorized to assess.

## Testing and verification

-   Check each service's `/health` endpoint before an integrated demo.
-   Test benign and suspicious samples in a controlled environment.
-   Review each module's test suite and evaluation files before making
    performance claims.
-   The Account Takeover module has a standalone end-to-end test script
    in its `tests` directory; run it from the ATO module directory
    according to that script.
-   A Python syntax check does not replace functional, integration, or
    security testing.

## Security notes and limitations

-   **Demonstration only:** Do not expose development services directly
    to the public internet.
-   **Local HTTP:** Current service URLs use loopback HTTP. Production
    deployments require secure transport and appropriate network
    controls.
-   **Secrets:** Keep API keys and passwords in environment variables or
    a secrets manager. Never commit `.env` files, credentials, tokens,
    private keys, or database files.
-   **Database:** The dashboard SQLite database contains user records
    and security event data. Protect it as sensitive information.
-   **Demo statistics:** Some Command Center KPI values, charts, and
    recent event cards are hard-coded demonstration values. They are not
    live historical detections. The event logger can record actual
    analysis results, but the overview must be wired to those records
    before it is described as live.
-   **Machine learning:** Model metrics depend on the dataset and
    threshold. Anomaly scores are not necessarily calibrated
    probabilities, and false positives can occur. Review evaluation
    reports before making accuracy or production-readiness claims.
-   **No guarantee of prevention:** The system supports detection and
    response decisions; it cannot guarantee every phishing attempt,
    impersonation attack, or account takeover will be detected or
    prevented.

## Project purpose

CyberGuard AI demonstrates how phishing detection, digital impersonation
detection, account takeover detection, and centralized threat
correlation can be integrated into a unified security workflow.

## License

No license is specified in this README. Add a `LICENSE` file that
reflects the intended reuse terms and any licenses required by
third-party code, models, and datasets before allowing redistribution.
