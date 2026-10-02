# 🛡️ ScamShield AI


AI-Powered Hybrid Scam Detection System

ScamShield AI is a web-based security application designed to detect suspicious or fraudulent content in text messages, URLs, and screenshots. It combines rule-based detection, optional AI analysis, URL inspection, and OCR to evaluate risk and explain why a message or link may be suspicious.


The project includes a FastAPI backend, static frontend pages, a Google OAuth login flow, and a browser extension folder that extends the tool into a browsing workflow.



## 🚀 Key Features


### 1. Message Scanner


Analyze suspicious content such as:



- SMS messages

- WhatsApp messages

- Emails

- Social-media messages

- Other plain-text communications



Detection covers:



- AI-based analysis

- security rule engine evaluation

- sensitive-information detection

- urgency and threat detection

- suspicious URL detection

- financial scam indicators



The output includes:



- risk score

- risk level

- scam type

- confidence

- detection reasons

- recommended actions

- risk breakdown




### 2. URL Scanner


Users can submit a URL and ScamShield analyzes it for suspicious characteristics.


The URL scanner checks for:



- suspicious domain patterns

- phishing-related characteristics

- suspicious TLDs

- URL structure issues

- login/verification patterns

- unsafe or misleading brand impersonation



Example:


Plain text






```
https://example.com/login

```





Result includes:


Plain text






```
Risk Score
Risk Level
Domain
Detected Indicators
Recommendation

```






### 3. Screenshot Scanner


Users can upload a screenshot of a suspicious message.


ScamShield uses OCR to extract text from the image and then analyzes the extracted text with the same hybrid scam-detection system.


Processing flow:


Plain text






```
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






### 4. Hybrid Scam Detection


ScamShield combines multiple analysis layers:


Plain text






```
                 User Input
                     │
          ┌──────────┴──────────┐
          ↓                     ↓
     AI Analysis           Rule Engine
          │                     │
          └──────────┬──────────┘
                     ↓
              Hybrid Scoring
                     ↓
             Final Risk Score
                     ↓
          Risk Level + Explanation

```





This approach blends AI understanding with deterministic security rules for stronger detection and more explainable results.



### 5. Risk Breakdown


ScamShield explains why it flagged a message instead of returning only a score.


Example:


Plain text






```
🚨 OTP Request              +25
⚠️ Urgency / Pressure       +15
🚨 Account Threat            +20
🚨 Suspicious URL            +20
🚨 Possible Impersonation    +10

```





Each signal can include:



- severity

- score contribution

- explanation




### 6. Safety Recommendations


After analysis, ScamShield provides recommendations such as:



- do not click suspicious links

- do not share OTPs

- do not share passwords, PINs, or CVV numbers

- verify messages via official channels

- do not send money based only on unexpected communication




### 7. Scan History


The backend includes an optional SQLite-backed history foundation with configurable retention. History routes are gated by authentication requirements and are not fully exposed as a public client-side system unless the host environment is configured correctly.


History can include:



- message scans

- URL scans

- screenshot scans

- risk score

- risk level

- scan time



Users may also clear their scan history depending on runtime configuration.



### 8. Dashboard Statistics


The frontend can display summary statistics such as:



- total scans

- threats detected

- safe results

- last risk score



Example:


Plain text






```
Total Scans       12
Threats Detected   8
Safe Results       4
Last Risk Score   78

```






### 9. Browser Extension Support


The project includes an `extension/` folder that adds browser-based inspection support. This is a Chrome/Edge extension with:



- a manifest file

- background service worker

- content script

- side panel UI

- icon assets



This allows the user to inspect suspicious content directly from their browser and send it to the FastAPI backend for detection.



# 🏗️ Project Architecture


Plain text






```
ScamShield-AI/
├── backend/
│   ├── .env.example
│   ├── .gitignore
│   ├── Dockerfile
│   ├── README.md
│   ├── requirements.txt
│   ├── main.py
│   ├── evaluation_dataset.json
│   ├── test_ai.py
│   ├── test_api.py
│   ├── test_improvements.py
│   ├── test_ocr.py
│   ├── test_risk.py
│   ├── test_rules.py
│   ├── test_url.py
│   ├── test_scam.png
│   └── services/
│       ├── ai_detector.py
│       ├── history.py
│       ├── ocr_service.py
│       ├── reputation.py
│       ├── risk_engine.py
│       ├── rule_engine.py
│       └── url_analyzer.py
├── frontend/
│   ├── antigra.html
│   ├── index.html
│   └── login.html
├── extension/
│   ├── content.js
│   ├── manifest.json
│   ├── service-worker.js
│   ├── sidepanel/
│   │   ├── sidepanel.html
│   │   └── sidepanel.js
│   └── icons/
│       ├── icon-16.png
│       ├── icon-48.png
│       └── icon-128.png
├── .gitignore
├── README.md
└── .git

```






# ⚙️ Technologies Used


## Frontend



- HTML5

- CSS3

- JavaScript

- Fetch API

- LocalStorage

- Responsive UI

- Google Identity Services (login page)



## Backend



- Python

- FastAPI

- Uvicorn

- Pydantic

- Python multipart uploads

- Optional Google OAuth via Authlib



## AI



- Google Gemini API

- Optional AI enrichment for scam reasoning



## OCR



- Tesseract OCR

- Pytesseract

- Image preprocessing via Pillow



## Security Analysis



- Rule-based detection

- Hybrid AI + rule scoring

- URL analysis

- suspicious keyword and pattern detection




# 🔌 Backend API


## Health Check


Http






```
GET /

```





Returns information about the API or redirecting login entry page.



## Health Endpoint


Http






```
GET /health

```





Used to check whether the backend is running.



## Message Analysis


Http






```
POST /api/analyze

```





Request:


JSON






```
{
  "message": "URGENT! Your bank account will be blocked. Send your OTP immediately."
}

```





The API returns:


JSON






```
{
  "success": true,
  "message": "...",
  "ai_analysis": {},
  "rule_analysis": {},
  "final_analysis": {}
}

```






## URL Analysis


Http






```
POST /api/analyze-url

```





Request:


JSON






```
{
  "url": "http://example.com/verify"
}

```





The response contains the URL risk score, risk level, domain, indicators, and recommendation.



## Screenshot Analysis


Http






```
POST /api/analyze-image

```





The endpoint accepts an uploaded image using `multipart/form-data`.


Example flow:


Plain text






```
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






# 🧮 Hybrid Risk Scoring


ScamShield combines AI analysis and rule-based analysis.


The system uses the following weights:


Plain text






```
AI Score   → 40% when AI is available
Rule Score → 60% when AI is available

```





Conceptually:


Plain text






```
Final Risk Score
=
(AI Score × 0.40)
+
(Rule Score × 0.60)

```





If the AI provider is unavailable, the response reports fallback behavior and relies more heavily on the rule-based engine.


Typical levels:


Plain text






```
0 – 39    LOW
40 – 69   MEDIUM
70 – 100  HIGH

```






# 🔎 Example Analysis


Input:


Plain text






```
URGENT! Your bank account will be blocked today.
Send your OTP immediately and click this link:
http://example.com/verify

```





Possible detected signals:


Plain text






```
Urgency / Pressure
OTP Request
Account Threat
Financial Information
Suspicious URL
Possible Impersonation

```





Example result:


Plain text






```
Risk Score: 78
Risk Level: HIGH

Scam Type:
Social Engineering / Threat/Pressure Scam

Confidence:
85%

```






# 🧩 Extension Folder Details


The `extension/` folder brings ScamShield into the browser environment.


## Purpose


The extension allows users to inspect suspicious webpages, copied messages, or scam sources directly from the browser and send them to the backend for analysis.


## Included files


Plain text






```
extension/
├── content.js
├── manifest.json
├── service-worker.js
├── sidepanel/
│   ├── sidepanel.html
│   └── sidepanel.js
├── icons/
│   ├── icon-16.png
│   ├── icon-48.png
│   └── icon-128.png

```





## Functionality



- `manifest.json` — Chrome/Edge extension configuration

- `content.js` — runs on webpages and can inspect visible text or suspicious content

- `service-worker.js` — handles background extension logic and events

- `sidepanel/sidepanel.html` — UI for the browser side panel

- `sidepanel/sidepanel.js` — client logic for interaction and backend calls

- `icons/` — extension branding assets



## Local backend target


The extension is designed to communicate with the local backend on:


Plain text






```
http://127.0.0.1:8000

```





It is intended for local testing and browser-assisted scanning rather than production deployment.



# 🛠️ Installation


## 1. Clone the repository


Bash






```
git clone https://github.com/YOUR_USERNAME/ScamShield-AI.git

```





Move into the project:


Bash






```
cd ScamShield-AI

```






# 🐍 Backend Setup


Go to the backend:


Bash






```
cd backend

```





Create a virtual environment:


### Windows


Bash






```
python -m venv venv

```





Activate it:


Bash






```
venv\Scripts\activate

```






## Install Dependencies


Bash






```
pip install -r requirements.txt

```





If `pytesseract` is missing:


Bash






```
pip install pytesseract

```





If required:


Bash






```
pip install pillow

```






# 🔐 Environment Variables


Create a file:


Plain text






```
backend/.env

```





Add your Gemini API key and other values:


ENV






```
GEMINI_API_KEY=your_api_key_here
GOOGLE_CLIENT_ID=your_google_client_id_here.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your_google_client_secret_here
SECRET_KEY=scamshield_super_secure_quantum_key_2026
REDIRECT_URI=http://127.0.0.1:8000/auth/google/callback
FRONTEND_ORIGIN=http://127.0.0.1:8000

```





Additional settings are documented in `backend/.env.example`.


⚠️ Never upload your real API key or secrets to GitHub.



# 🔤 Tesseract OCR Setup


Screenshot scanning requires Tesseract OCR.


Install Tesseract OCR on your system and ensure it is available to `pytesseract`.


If Windows cannot find Tesseract automatically, configure the executable path in your OCR service.


Example:


Python






```
pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"

```






# ▶️ Run the Backend


From the `backend` directory:


Bash






```
uvicorn main:app --reload

```





The backend will run at:


Plain text






```
http://127.0.0.1:8000

```





API documentation:


Plain text






```
http://127.0.0.1:8000/docs

```






# 🌐 Run the Frontend


Open the frontend `index.html` using a local development server or serve it via the FastAPI backend.


For example, with VS Code Live Server:


Plain text






```
Right Click → Open with Live Server

```





The frontend communicates with:


Plain text






```
http://127.0.0.1:8000

```






# 🔗 API Configuration


The frontend contains:


JavaScript






```
const API_BASE = "http://127.0.0.1:8000";

```





The APIs are:


JavaScript






```
const MESSAGE_API = `${API_BASE}/api/analyze`;
const URL_API = `${API_BASE}/api/analyze-url`;
const IMAGE_API = `${API_BASE}/api/analyze-image`;

```





If the backend is deployed online, replace the local API address with the deployed backend URL.



# 📁 Important Files
























































| File | Purpose |
| --- | --- |
| `backend/main.py` | FastAPI application |
| `backend/services/ai_detector.py` | AI-based scam analysis |
| `backend/services/rule_engine.py` | Rule-based detection |
| `backend/services/risk_engine.py` | Combines AI and rule scores |
| `backend/services/url_analyzer.py` | URL security analysis |
| `backend/services/ocr_service.py` | Screenshot OCR |
| `frontend/index.html` | Main frontend app |
| `frontend/login.html` | Login screen |
| `extension/manifest.json` | Browser extension configuration |
| `backend/requirements.txt` | Python dependencies |
| `backend/.env.example` | Environment configuration |




# 🔒 Security Notes


ScamShield is a security-assistance tool and should not be treated as a perfect scam detector.


AI and rule-based systems can produce false positives or false negatives.


Users should verify suspicious messages through official channels.


Never expose API keys in:



- Frontend JavaScript

- GitHub repositories

- screenshots

- public configuration files




# 🚀 Future Improvements


Possible future features:



- 📧 Email analysis

- 📱 WhatsApp message import

- 🌐 Browser extension enhancement

- 🔍 Domain reputation lookup

- 🗄️ Database-backed scan history

- 👤 User accounts

- 📈 Advanced analytics dashboard

- 🌍 Multi-language scam detection

- 🎙️ Voice scam detection

- 📱 Mobile application

- 🔔 Real-time scam alerts




# 🎯 Project Goal


The goal of ScamShield AI is to provide a simple and accessible tool that helps users recognize suspicious digital communication before they interact with it.


Plain text






```
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






# 👨‍💻 Developer


**Vinith S.**


Computer Science & Engineering Student


Interested in:



- Python

- Web Development

- Artificial Intelligence

- Cybersecurity

- Software Engineering




# 📜 Disclaimer


ScamShield AI is developed for educational, research, and awareness purposes.


It does not guarantee that every scam, phishing attempt, malicious URL, or fraudulent message will be detected.


Always verify important communications through the organization's official website, application, or contact channel.


If you want, I can also give you:



- a shorter GitHub-style README

- a more professional project README

- a README with a visual architecture diagram and badges

- a version tailored for portfolio / final-year project presentation
