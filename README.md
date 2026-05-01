# 🌱 EcoTrust Backend – Website Analyzer

## 📌 Overview

EcoTrust is a **Website Authenticity and Sustainability Verifier**.
This backend module focuses on analyzing websites for:

* 🔒 SSL Certificate Validation
* 🛡️ Security & Safety Checks
* 🌍 Sustainability Certification Verification
* ⚠️ Scam Detection Signals

Built using **Flask**, this backend provides REST APIs that integrate with the EcoTrust React frontend.

---

## 🚀 Features

### ✅ Website Analyzer

* Validates SSL certificates
* Checks HTTPS security
* Extracts domain information

### 🔐 Security Checks

* Google Safe Browsing API integration
* VirusTotal API scanning
* WHOIS lookup for domain authenticity

### 🌿 Sustainability Checker

* Scrapes website for certifications
* Verifies authenticity of eco-labels
* Generates sustainability score

### 🤖 AI Feedback

* Uses Gemini API for intelligent analysis and suggestions

---

## 🛠️ Tech Stack

* **Backend Framework:** Flask
* **Language:** Python
* **Libraries:**

  * `requests`
  * `beautifulsoup4`
  * `ssl`
  * `whois`
* **APIs Used:**

  * Google Safe Browsing API
  * VirusTotal API
  * WHOIS API
  * Gemini API

---

## 📂 Project Structure

```
ecotrust-backend/
│── app.py
│── routes/
│   ├── ssl_check.py
│   ├── safety_check.py
│   ├── sustainability.py
│── utils/
│   ├── scraper.py
│   ├── cert_utils.py
│── requirements.txt
│── README.md
```

---

## ⚙️ Installation & Setup

### 1️⃣ Clone the repository

```bash
git clone https://github.com/your-username/ecotrust-backend.git
cd ecotrust-backend
```

### 2️⃣ Create virtual environment

```bash
python -m venv venv
source venv/bin/activate   # (Linux/Mac)
venv\Scripts\activate      # (Windows)
```

### 3️⃣ Install dependencies

```bash
pip install -r requirements.txt
```

### 4️⃣ Add environment variables

Create a `.env` file:

```
GOOGLE_API_KEY=your_key
VIRUSTOTAL_API_KEY=your_key
WHOIS_API_KEY=your_key
GEMINI_API_KEY=your_key
```

### 5️⃣ Run the server

```bash
python app.py
```

Server will run on:

```
http://127.0.0.1:5000/
```

---

## 📡 API Endpoints

### 🔍 SSL & Security Check

**POST** `/analyze`

**Request:**

```json
{
  "url": "https://example.com"
}
```

**Response:**

```json
{
  "ssl_valid": true,
  "domain_age": "5 years",
  "safe": true,
  "threats": []
}
```

---

### 🌿 Sustainability Check

**POST** `/check_certifications`

**Request:**

```json
{
  "url": "https://example.com"
}
```

**Response:**

```json
{
  "certifications_found": ["ISO 14001"],
  "verified": true,
  "score": 78
}
```

---

## 🔗 Integration with Frontend

* Connect via **Axios POST requests**
* Ensure CORS is enabled in Flask:

```python
from flask_cors import CORS
CORS(app)
```

---

## 🧪 Testing

Use tools like:

* Postman
* Thunder Client
* Curl

---

## ⚠️ Limitations

* Certification scraping depends on website structure
* API rate limits (VirusTotal, Google Safe Browsing)
* WHOIS data may vary by domain

---

## 📌 Future Enhancements

* 🔍 ML-based scam detection
* 📊 Advanced sustainability scoring
* 🗄️ SAP HANA integration
* 📈 Dashboard analytics

---

## 👩‍💻 Author

**Vanshika Shukla**
B.Tech AI & ML

---

## 📜 License

This project is for educational and research purposes.

---
