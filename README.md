# 🛡️ UPI / QR Payment Scam & Phishing Detector

A defensive cybersecurity web application built in Python and Streamlit that inspects **QR Code payment images**, **Payment URLs**, and **SMS/Messaging payment requests** before a user authorizes a transaction.

> **⚠️ Educational & Defensive Tool Disclaimer:**  
> This application is a static heuristic analysis tool designed for cybersecurity education and consumer awareness. It **never** initiates payments, collects banking credentials (UPI PINs/OTPs), or guarantees that a payment recipient is legitimate. Automated heuristic detection can produce both false positives and false negatives—always verify payment recipients independently through official banking channels.

---

## ✨ Key Features

### 1. 📸 QR Code Scanner & NPCI `upi://pay` URI Inspector (`modules/qr_scanner.py`)
* **Defense-in-Depth Image Validation:** Enforces upload size limits (5 MB default), verifies binary image headers via `Pillow`, and blocks decompression-bomb resolutions before processing.
* **Resilient Multi-Pass Decoding:** Uses a dual-engine setup (OpenCV native `cv2.QRCodeDetector` + optional `pyzbar` C wrapper) across 5 preprocessing passes (Original BGR, Grayscale, Padded Border, Otsu Thresholding, and 2x Cubic Upscaling).
* **NPCI UPI Deep-Link Parsing:** Extracts `pa` (Payee VPA), `pn` (Claimed Payee Name), `am` (Locked Amount), `mam` (Minimum Amount), `cu` (Currency), `tn` (Transaction Note), `mc` (Merchant Code), `tr` (Transaction Reference), and `sign` (Cryptographic Signature status).
* **QR Scam Heuristics:**
  * Flags **"Scan QR to Receive Money / Refund / Cashback"** bait (scanning a `upi://pay` QR code can *only* send money out).
  * Flags high-trust authority/bank names in the unverified `pn` display field (`SBI Refund`, `PM Cares`, `RBI`) paired with unverified VPAs.
  * Detects **Quishing** (QR codes that secretly point to `http://` or `https://` phishing websites or executable URI schemes like `javascript:`).

### 2. 🔗 Payment Link & Phishing URL Analyzer (`modules/url_analyzer.py`)
* **Air-Gapped Static Dissection:** Parses URLs via `urllib.parse` without visiting untrusted servers or following redirects.
* **SSRF & Internal Network Protection:** Detects `localhost`, loopback (`127.0.0.1`), RFC1918 private networks, and cloud metadata endpoints (`169.254.169.254`).
* **12 Phishing & Domain Spoofing Checks:**
  * Typosquatting, homoglyph substitution (`paytrn.com`, `ph0nepe.com`), and deceptive brand subdomains (`sbi-kyc.verify-login.xyz`).
  * Embedded URL credential tricks (`https://onlinesbi.sbi@evil.top`).
  * Internationalized Punycode domains (`xn--`), high-abuse TLDs (`.xyz`, `.top`, `.click`, `.loan`), URL shorteners (`bit.ly`, `tinyurl.com`), non-standard ports, and open-redirect parameters.
  * Optional **Google Safe Browsing API v4** integration when `GOOGLE_SAFE_BROWSING_API_KEY` is configured in `.env`.

### 3. 💬 Context-Aware SMS Scam Analyzer (`modules/sms_analyzer.py`)
* **Low False-Positive Context Engine:** Distinguishes between legitimate bank protective disclaimers (*"Never share your OTP or UPI PIN with anyone"*) and malicious credential harvesting (*"Share your 6-digit OTP to unblock your KYC"*).
* **Social Engineering Pattern Detection:**
  * OTP / UPI PIN / CVV / NetBanking password solicitation.
  * Remote-access screen-sharing traps (**AnyDesk**, **TeamViewer**, **QuickSupport**, unsolicited `.apk` downloads).
  * Fake KYC suspension, SIM block, and midnight electricity disconnection threats.
  * Personal 10-digit mobile numbers disguised as bank/utility customer care helplines.
  * Automatic extraction and static analysis of embedded URLs inside SMS messages.
* **XSS-Safe Visual Highlighting:** Escapes untrusted message text via `html.escape()` before highlighting flagged phrases in the UI.

### 4. ⚖️ Transparent Risk Scoring Engine (`modules/risk_engine.py`)
* **Deduplicated Weighted Scoring (0–100):** Groups indicators by rule code and underlying threat family (`CONCEPT_FAMILY_MAP`) so overlapping rules are never double-counted.
* **Heuristic Risk Categories:**
  * `0–24`: **Low** (`[OK / LOW RISK]`)
  * `25–49`: **Medium** (`[CAUTION / MEDIUM RISK]`)
  * `50–74`: **High** (`[WARNING / HIGH RISK]`)
  * `75–100`: **Critical** (`[DANGER / CRITICAL RISK]`)

### 5. 🔒 Privacy-by-Design Local SQLite History (`modules/storage.py`)
* Stores **only** anonymized scan metadata (`id`, `timestamp`, `input_type`, `risk_score`, `risk_category`, `indicator_count`, `top_indicator_code`).
* **Never** writes raw SMS content, full URLs, UPI IDs (`pa`), payee names, or uploaded images to disk.
* Includes a live sidebar opt-out toggle and one-click database wipe (`DELETE` + `VACUUM`).

---

## 🏗️ Project Architecture

```text
upi-scam-detector/
├── .streamlit/
│   └── config.toml            # Local server binding & dark fintech theme
├── assets/
│   └── logo.png               # Generated application shield icon
├── modules/
│   ├── __init__.py            # Core analyzer package initializer
│   ├── qr_scanner.py          # Image validation, dual-engine QR decoder & UPI parser
│   ├── url_analyzer.py        # Static URL parser, SSRF guard & brand spoof detector
│   ├── sms_analyzer.py        # Context-aware SMS social engineering analyzer
│   ├── risk_engine.py         # Deduplicated 0-100 risk scoring & safety recommendations
│   ├── report_generator.py    # Accessible UI risk cards & XSS-safe SMS highlighter
│   └── storage.py             # Privacy-first SQLite metadata history store
├── tests/
│   ├── __init__.py
│   ├── test_qr_scanner.py     # Synthetic QR & UPI URI unit tests
│   ├── test_url_analyzer.py   # Phishing URL, SSRF & lookalike domain unit tests
│   ├── test_sms_analyzer.py   # Scam SMS vs. legitimate bank alert unit tests
│   └── test_risk_engine.py    # Boundary, deduplication & privacy storage unit tests
├── .env.example               # Template for optional environment variables
├── .gitignore                 # Excludes .venv, .env, __pycache__, and *.db files
├── app.py                     # Main Streamlit web application
├── requirements.txt           # Pinned Python package dependencies
└── README.md                  # Project documentation
```

---

## 🚀 Setup & Installation (Windows / VS Code)

### Prerequisites
* **Python 3.10+** (Tested with Python 3.11–3.14 on Windows)
* **Visual Studio Code**

### 1. Clone the Repository & Open in VS Code
```powershell
git clone [https://github.com/](https://github.com/)<your-github-username>/upi-scam-detector.git
cd upi-scam-detector
code .
```

### 2. Create & Activate a Virtual Environment
```powershell
python -m venv .venv
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
.\.venv\Scripts\Activate.ps1
```

### 3. Install Dependencies
```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```
> **Windows QR Decoder Note:** This project works out-of-the-box on Windows using OpenCV's built-in `cv2.QRCodeDetector()`. If you also wish to enable the optional `pyzbar` C DLL on Windows, install the Microsoft Visual C++ 2013 Redistributable (x64) via `winget install Microsoft.VCRedist.2013.x64`.

### 4. (Optional) Configure Environment Variables
To run in 100% offline heuristic mode, no `.env` file is required. To enable optional Google Safe Browsing URL lookups:
```powershell
Copy-Item .env.example .env
# Edit .env and add your GOOGLE_SAFE_BROWSING_API_KEY
```

### 5. Run the Application
```powershell
python -m streamlit run app.py --server.address 127.0.0.1 --server.port 8501
```
Open **`http://127.0.0.1:8501`** in your web browser.

---

## 🧪 Running Automated Tests

Run the complete `pytest` suite (21 unit and integration tests across QR, URL, SMS, Risk Engine, and SQLite Privacy Storage):

```powershell
python -m pytest -v
```

---

## 📸 Screenshots Guide (For Your GitHub Portfolio)

To showcase your project visually on GitHub, capture screenshots of the following views (`Win + Shift + S` on Windows) and save them inside `assets/`:
1. **`assets/dashboard.png`**: Main "Digital Payment Security Center" showing the 3 feature cards and summary metrics.
2. **`assets/qr_analysis.png`**: QR Scanner decoding the synthetic *"Scan to Receive Refund"* scam QR code with Critical Risk (`100/100`) and parsed `upi://pay` fields.
3. **`assets/url_analysis.png`**: Link Analyzer dissecting `http://sbi-kyc-update.verify-account.xyz:8080/refund`.
4. **`assets/sms_analysis.png`**: SMS Analyzer highlighting suspicious phrases inside a fake KYC / OTP harvesting message.

---

## ⚠️ Known Limitations & Security Boundaries

1. **Static Heuristics vs. Verified Merchant Identity:** A score of `0` (Low Risk) only means no syntactic or heuristic scam patterns were triggered. A fraudster can still generate a technically clean QR code (`upi://pay?pa=impostor@okaxis&pn=ShopName`) and paste it over a real merchant's QR sticker. Users must always verify the registered banking name shown on their UPI app's final PIN screen.
2. **Offline URL Shortener Resolution:** To prevent Server-Side Request Forgery (SSRF) and avoid tipping off attacker servers with client beacons, the analyzer flags shortened URLs (`bit.ly`, `tinyurl.com`) statically rather than blindly following HTTP redirects.
3. **Evolving Social Engineering Language:** Rule-based regular expressions detect known coercion and phishing patterns in English/Hinglish, but novel phrasing or regional-script scams may evade static rules.

---

## 🚨 Emergency Cyber Fraud Reporting (India)
If money has been fraudulently debited or sensitive credentials were shared:
* **National Cyber Crime Helpline:** Call **`1930`** immediately.
* **Official Portal:** [https://cybercrime.gov.in](https://cybercrime.gov.in)