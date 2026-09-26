# 🛡️ ScamShield AI

> **AI-Powered Hybrid Scam Detection System**

ScamShield AI is a web-based security application that helps users identify potentially fraudulent or suspicious **messages, URLs, and screenshots**.

It combines **AI analysis, security rules, URL analysis, and OCR** to produce a final risk score and explain why a piece of content may be suspicious.

---

## 🚀 Features

### 📩 1. Message Scanner

Analyze suspicious:

* SMS messages
* WhatsApp messages
* Emails
* Social-media messages
* Other text content

ScamShield checks the message using:

* 🤖 AI analysis
* 🧠 Security rule engine
* 🔐 Sensitive-information detection
* ⚠️ Urgency/threat detection
* 🔗 Suspicious URL detection
* 💳 Financial/scam indicators

The result includes:

* Risk score
* Risk level
* Scam type
* Confidence
* Detection reasons
* Recommended actions
* Risk breakdown

---

### 🔗 2. URL Scanner

Users can submit a URL and ScamShield analyzes it for suspicious characteristics.

The URL scanner checks indicators such as:

* Suspicious domain patterns
* Phishing-related characteristics
* Suspicious TLDs
* URL structure
* Login/verification patterns
* Other security indicators

Example:

```text
https://example.com/login
```

The result provides:

```text
Risk Score
Risk Level
Domain
Detected Indicators
Recommendation
```

---

### 📸 3. Screenshot Scanner

Users can upload a screenshot of a suspicious message.

ScamShield uses **OCR (Optical Character Recognition)** to extract text from the image.

The extracted text is then analyzed using the same hybrid scam-detection system.

Pipeline:

```text
Screenshot
    ↓
OCR
    ↓
Extracted Text
    ↓
AI Analysis
    +
Rule Analysis
    ↓
Hybrid Risk Score
    ↓
Final Result
```

---

### 🧠 4. Hybrid Scam Detection

ScamShield combines two analysis layers:

```text
                 User Input
                     │
          ┌──────────┴──────────┐
          ↓                     ↓
     AI Analysis           Rule Engine
          │                     │
          │                     │
          └──────────┬──────────┘
                     ↓
              Hybrid Scoring
                     ↓
             Final Risk Score
                     ↓
          Risk Level + Explanation
```

The hybrid system helps combine AI-based understanding with deterministic security rules.

---

### 📊 5. Risk Breakdown

ScamShield explains the detected signals instead of only showing a score.

Example:

```text
🚨 OTP Request              +25
⚠️ Urgency / Pressure       +15
🚨 Account Threat            +20
🚨 Suspicious URL            +20
🚨 Possible Impersonation    +10
```

Each signal can include:

* Severity
* Score contribution
* Explanation

---

### 🛡️ 6. Safety Recommendations

After analysis, ScamShield provides practical recommendations such as:

* Do not click suspicious links.
* Do not share OTPs.
* Do not share passwords, PINs, or CVV numbers.
* Verify messages through official channels.
* Do not send money based only on unexpected messages.

---

### 🕘 7. Scan History

The backend also provides an optional SQLite-backed history foundation with configurable
retention. History routes are disabled unless `TRUSTED_AUTH_PROXY=true` is configured.
When enabled, a separately authenticated gateway must provide
`X-Authenticated-User`; this project never treats a client-supplied identity
header as authentication.

History can include:

* Message scans
* URL scans
* Screenshot scans
* Risk score
* Risk level
* Scan time

Users can also clear their scan history.

---

### 📊 8. Dashboard Statistics

The frontend displays:

* Total Scans
* Threats Detected
* Safe Results
* Last Risk Score

Example:

```text
Total Scans       12
Threats Detected   8
Safe Results       4
Last Risk Score   78
```

---

# 🏗️ Project Architecture

```text
ScamShield-AI/
│
├── backend/
│   ├── main.py
│   │
│   ├── services/
│   │   ├── ai_detector.py
│   │   ├── rule_engine.py
│   │   ├── risk_engine.py
│   │   ├── url_analyzer.py
│   │   ├── ocr_service.py
│   │   ├── history.py
│   │   └── reputation.py
│   │
│   ├── requirements.txt
│   └── .env
│
├── frontend/
│   └── index.html
│
├── README.md
└── .gitignore
```

> Your exact folder structure may be slightly different depending on your current implementation.

---

# ⚙️ Technologies Used

## Frontend

* HTML5
* CSS3
* JavaScript
* Fetch API
* LocalStorage
* Responsive UI

## Backend

* Python
* FastAPI
* Uvicorn

## AI

* Google Gemini API

## OCR

* Tesseract OCR
* Pytesseract

## Security Analysis

* Rule-based detection
* Hybrid AI + rule scoring
* URL analysis

---

# 🔌 Backend API

## Health Check

```http
GET /
```

Returns information about the API.

---

## Health Endpoint

```http
GET /health
```

Used to check whether the backend is running.

---

## Message Analysis

```http
POST /api/analyze
```

Request:

```json
{
  "message": "URGENT! Your bank account will be blocked. Send your OTP immediately."
}
```

The API returns:

```json
{
  "success": true,
  "message": "...",
  "ai_analysis": {},
  "rule_analysis": {},
  "final_analysis": {}
}
```

---

## URL Analysis

```http
POST /api/analyze-url
```

Request:

```json
{
  "url": "http://example.com/verify"
}
```

The response contains the URL risk score, risk level, domain and detected indicators.

---

## Screenshot Analysis

```http
POST /api/analyze-image
```

The endpoint accepts an uploaded image using `multipart/form-data`.

Processing:

```text
Image
 ↓
OCR
 ↓
Extracted Text
 ↓
Scam Analysis
 ↓
Final Result
```

---

# 🧮 Hybrid Risk Scoring

ScamShield combines AI analysis and rule-based analysis.

The system uses the following weights:

```text
AI Score   → 40% when AI is available
Rule Score → 60% when AI is available
```

Conceptually:

```text
Final Risk Score
=
(AI Score × 0.40)
+
(Rule Score × 0.60)
```

If the AI provider is unavailable, the response explicitly reports
`score_mode: "RULE_FALLBACK"` and uses an 85% rule / 15% fallback weighting.
This keeps the result bounded and makes the source of the score visible to
callers.

The resulting score is used to determine the final risk level.

Typical levels:

```text
0 – 39    LOW
40 – 69   MEDIUM
70 – 100  HIGH
```

---

# 🔎 Example Analysis

Input:

```text
URGENT! Your bank account will be blocked today.
Send your OTP immediately and click this link:
http://example.com/verify
```

Possible detected signals:

```text
Urgency / Pressure
OTP Request
Account Threat
Financial Information
Suspicious URL
Possible Impersonation
```

Example result:

```text
Risk Score: 78
Risk Level: HIGH

Scam Type:
Social Engineering / Threat/Pressure Scam

Confidence:
85%
```

---

# 🛠️ Installation

## 1. Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/ScamShield-AI.git
```

Move into the project:

```bash
cd ScamShield-AI
```

---

# 🐍 Backend Setup

Go to the backend:

```bash
cd backend
```

Create a virtual environment:

### Windows

```bash
python -m venv venv
```

Activate it:

```bash
venv\Scripts\activate
```

---

## Install Dependencies

```bash
pip install -r requirements.txt
```

If `pytesseract` is missing:

```bash
pip install pytesseract
```

If required:

```bash
pip install pillow
```

---

# 🔐 Environment Variables

Create a file:

```text
backend/.env
```

Add your Gemini API key:

```env
GEMINI_API_KEY=your_api_key_here
```

Additional deployment settings are documented in `backend/.env.example`,
including `CORS_ORIGINS`, `MAX_MESSAGE_LENGTH`, `MAX_UPLOAD_BYTES`,
`MAX_IMAGE_PIXELS`, `OCR_LANGUAGES`, `HISTORY_DB`, and
`HISTORY_RETENTION_DAYS`. Keep CORS origins explicit in production; wildcard
origins and browser-provided authentication are not supported.

⚠️ **Never upload your real API key to GitHub.**

Make sure `.env` is included in `.gitignore`.

---

# 🔤 Tesseract OCR Setup

Screenshot scanning requires Tesseract OCR.

Install Tesseract OCR on your system and make sure it is available to `pytesseract`.

If Windows cannot find Tesseract automatically, configure the Tesseract executable path in your OCR service.

Example:

```python
pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
```

Use the correct path for your computer.

---

# ▶️ Run the Backend

From the `backend` directory:

```bash
uvicorn main:app --reload
```

The backend should run at:

```text
http://127.0.0.1:8000
```

API documentation:

```text
http://127.0.0.1:8000/docs
```

---

# 🌐 Run the Frontend

Open the frontend `index.html` using a local development server.

For example, using VS Code Live Server:

```text
Right Click → Open with Live Server
```

The frontend communicates with:

```text
http://127.0.0.1:8000
```

---

# 🔗 API Configuration

The frontend contains:

```javascript
const API_BASE = "http://127.0.0.1:8000";
```

The APIs are:

```javascript
const MESSAGE_API = `${API_BASE}/api/analyze`;
const URL_API = `${API_BASE}/api/analyze-url`;
const IMAGE_API = `${API_BASE}/api/analyze-image`;
```

If the backend is deployed online, replace the local API address with the deployed backend URL.

---

# 📁 Important Files

| File                 | Purpose                   |
| -------------------- | ------------------------- |
| `main.py`            | FastAPI application       |
| `ai_detector.py`     | AI-based scam analysis    |
| `rule_engine.py`     | Rule-based detection      |
| `risk_engine.py` | Combines AI and rule scores |
| `url_analyzer.py`    | URL security analysis     |
| `ocr_service.py`     | Screenshot OCR            |
| `index.html`         | Frontend application      |
| `requirements.txt`   | Python dependencies       |
| `.env`               | API keys and secrets      |

---

# 🔒 Security Notes

ScamShield is a security-assistance tool and should not be treated as a perfect scam detector.

AI and rule-based systems can produce false positives or false negatives.

Users should verify suspicious messages through official channels.

Never expose API keys in:

* Frontend JavaScript
* GitHub repositories
* Screenshots
* Public configuration files

---

# 🚀 Future Improvements

Possible future features:

* 📧 Email analysis
* 📱 WhatsApp message import
* 🌐 Browser extension boundary (`/api/extension/*` is available now)
* 🔍 Domain reputation lookup
* 🗄️ Database-backed scan history
* 👤 User accounts
* 📈 Advanced analytics dashboard
* 🌍 Multi-language scam detection
* 🎙️ Voice scam detection
* 📱 Mobile application
* 🔔 Real-time scam alerts

---

# 🎯 Project Goal

The goal of ScamShield AI is to provide a simple and accessible tool that helps users recognize suspicious digital communication before they interact with it.

```text
See a suspicious message
          ↓
       Scan it
          ↓
   Understand the risk
          ↓
   See why it's suspicious
          ↓
      Take safer action
```

---

# 👨‍💻 Developer

**Vinith S.**

Computer Science & Engineering Student

Interested in:

* Python
* Web Development
* Artificial Intelligence
* Cybersecurity
* Software Engineering

---

# 📜 Disclaimer

ScamShield AI is developed for educational, research, and awareness purposes.

It does not guarantee that every scam, phishing attempt, malicious URL, or fraudulent message will be detected.

Always verify important communications through the organization's official website, application, or contact channel.
