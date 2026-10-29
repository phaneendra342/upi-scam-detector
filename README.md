# 🛡️ SecurePay: UPI Fraud & Scam Detection Engine

[![Streamlit App](https://static.streamlit.io/badges/streamlit_badge_black_white.svg)](https://securepay-detector.streamlit.app)
[![Python Version](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code Style: Black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Tests](https://img.shields.io/badge/tests-pytest-brightgreen.svg)](https://pytest.org/)

**SecurePay** is a client-side, privacy-focused threat intelligence dashboard designed to detect malicious UPI payment requests, spoofed banking domains, phishing links, and deceptive SMS scams before monetary transactions occur.

---

## 🚀 Live Demonstration
The application is deployed and accessible on Streamlit Community Cloud:  
👉 **[securepay-detector.streamlit.app](https://securepay-detector.streamlit.app)**

---

## 🔍 Key Detection Engines

### 1. Payment Link & URL Analyzer
* **Static URL Parsing:** Dissects protocols, hostnames, ports, and subdomains without resolving or querying the target page directly.
* **Risk Vectors:** Identifies raw/private IP hosts (SSRF indicators), excessive subdomains, brand-impersonation lookalikes, punycode spoofing, and dangerous URL shortener redirection patterns.
* **Reputation Integration:** Supports optional Google Safe Browsing API lookup for external domain reputation verification.

### 2. QR Code Inspector
* **Dual-Engine Decoding:** Decodes images via `pyzbar` with fallback to `OpenCV` barcode/QR detection.
* **UPI Parameter Parsing:** Extracts and analyzes standard UPI scheme fields (`pa`, `pn`, `am`, `cu`, `mc`).
* **Threat Heuristics:** Flags fake refund lures, locked payment amounts, mismatched merchant categories, and deceptive payee VPAs.

### 3. SMS Scam Classifier
* **Heuristic NLP Tokenization:** Detects psychological manipulation patterns such as false urgency, account suspension threats, electricity cut-off notices, and reward baits.
* **Technical Extraction:** Dissects embedded telephone numbers, non-standard shortcodes, external APK download links, and credential harvesting traps.

### 4. Interactive Threat Intelligence Dashboard
* **Real-time Analytics:** Visualizes scan velocity and severity distribution using Plotly.
* **Privacy Safeguards:** Built with zero-logging principles; local SQLite database excludes sensitive personal data, tracking only anonymized scan metadata.
* **Review Queue:** Allows users to flag edge cases for false-positive auditing.

---

## 🛠️ Architecture & Tech Stack

* **Frontend:** Streamlit, Custom CSS Dark Theme
* **Data Visualization:** Plotly Graph Objects, Pandas
* **Image & Computer Vision:** OpenCV (headless), Pillow, PyZbar
* **Storage & Privacy:** SQLite3 (local metadata storage, strict exclusion of PII)
* **Testing:** PyTest automated test suite

---

## 📁 Repository Structure

```text
upi-scam-detector/
├── .streamlit/
│   └── config.toml          # Custom dark UI styling & color palette
├── assets/
│   └── logo.png             # UI brand identity
├── modules/
│   ├── __init__.py
│   ├── qr_scanner.py        # QR image decoding & UPI URI parsing
│   ├── report_generator.py  # Markdown / CSV audit trail reports
│   ├── risk_engine.py       # Heuristic scoring engine (0-100 scale)
│   ├── sms_analyzer.py      # Phishing SMS & urgency detector
│   ├── storage.py           # SQLite metadata & review queue
│   └── url_analyzer.py      # Domain dissection & heuristic analyzer
├── tests/
│   ├── test_qr_scanner.py
│   ├── test_risk_engine.py
│   ├── test_sms_analyzer.py
│   └── test_url_analyzer.py
├── .gitignore
├── app.py                   # Main Streamlit dashboard application
├── packages.txt             # Linux C dependencies (libzbar0, libgl1)
├── requirements.txt         # Production Python packages
└── README.md