# 🛡️ CyberDefence

CyberDefence is a cybersecurity web application designed to provide a centralized dashboard for detecting and monitoring common security threats. The application provides modules for **Phishing Detection, Network Scanning, Ransomware Monitoring, Incident Management, and Security Logs**.

## 🚀 Features

### 📧 Phishing Detection

* Analyse suspicious emails.
* Check sender, subject, and email body.
* Generate a phishing risk score.
* Classify emails as:

  * LOW RISK
  * SUSPICIOUS
  * HIGH RISK
* Store analysis history in the database.

### 🌐 Network Scanner

* Scan a target network or host.
* Identify available ports and services.
* Display network security results.
* Maintain scan results for later review.

### 🦠 Ransomware Monitoring

* Monitor directories for suspicious activity.
* Detect potentially dangerous file activity.
* Create security incidents.
* Track incident severity and status.
* Support incident response actions.

### 📋 Security Logs

* Maintain application and security logs.
* Record important system activities.
* View recent security events.
* Filter and retrieve logs through the API.

### 📊 Security Dashboard

* Centralized cybersecurity dashboard.
* Display security statistics.
* Show phishing, network, ransomware, and log information.

---

## 🛠️ Technologies Used

### Backend

* Python
* Flask
* Flask-CORS

### Frontend

* HTML
* CSS
* JavaScript

### Database

* SQLite

### API

* REST API

---

## 📁 Project Structure

```text
Cyber Defence/
│
├── app.py
├── cyber_defense.html
├── cyberdefense.db
│
├── cyber_db_network.sql
├── cyber_db_phishing.sql
├── cyber_db_ransomware.sql
│
├── requirements.txt
├── package.json
├── package-lock.json
└── README.md
```

---

## ⚙️ Installation

### 1. Clone the repository

```bash
git clone https://github.com/wasim76782/CyberDefence.git
```

### 2. Open the project

```bash
cd CyberDefence
```

### 3. Install Python dependencies

```bash
pip install flask flask-cors
```

Or, if `requirements.txt` is available:

```bash
pip install -r requirements.txt
```

---

## ▶️ Run the Application

Start the Flask server:

```bash
python app.py
```

The server will run on:

```text
http://127.0.0.1:5000
```

Open the application in your browser:

```text
http://localhost:5000
```

---

## 🔌 API Endpoints

### General

```text
GET /api/health
GET /api/overview
```

### Phishing

```text
POST /api/phishing/analyse
GET  /api/phishing/history
```

### Network

```text
POST /api/network/scan
GET  /api/network/results
```

### Ransomware

```text
POST /api/ransomware/monitor/start
POST /api/ransomware/monitor/stop
POST /api/ransomware/test
GET  /api/ransomware/incidents
```

### Logs

```text
GET /api/logs
```

---

## 🔄 Application Flow

```text
                    USER
                      │
                      ▼
             HTML Dashboard
                      │
                      ▼
                Flask REST API
                      │
        ┌─────────────┼─────────────┐
        │             │             │
        ▼             ▼             ▼
    Phishing       Network      Ransomware
    Detection       Scan         Monitoring
        │             │             │
        └─────────────┼─────────────┘
                      ▼
               SQLite Database
                      │
                      ▼
                Security Logs
                      │
                      ▼
                 Dashboard
```

---

## 🗄️ Database

The project uses **SQLite** for storing security-related information.

Main database:

```text
cyberdefense.db
```

SQL files:

```text
cyber_db_phishing.sql
cyber_db_network.sql
cyber_db_ransomware.sql
```

These files contain database structures and related data for the different security modules.

---

## 🧪 Testing the Phishing API

Example PowerShell request:

```powershell
Invoke-RestMethod `
  -Uri "http://localhost:5000/api/phishing/analyse" `
  -Method POST `
  -ContentType "application/json" `
  -Body '{"sender":"security@gmail.com","subject":"Urgent verify your account","body":"Click here to verify your password http://example.com"}'
```

Example response:

```json
{
    "status": "success",
    "score": 70,
    "verdict": "HIGH RISK",
    "reasons": [
        "urgent",
        "verify your account",
        "password",
        "click here",
        "HTTP link"
    ]
}
```

---

## 🎯 Project Objectives

* Detect common cybersecurity threats.
* Provide a centralized security dashboard.
* Monitor suspicious activities.
* Store security incidents and logs.
* Provide REST APIs for cybersecurity operations.
* Demonstrate practical implementation of cybersecurity concepts.

---

## 🔮 Future Improvements

* Machine Learning based phishing detection.
* Real-time network monitoring.
* Advanced ransomware detection.
* User authentication and role-based access.
* Email attachment scanning.
* IP reputation checking.
* Threat intelligence integration.
* Real-time notifications.
* Advanced security reports.

---

## 👨‍💻 Author

**Suraj Mahato**

CyberDefence — Cybersecurity Monitoring and Threat Detection Project.

---

## 📄 License

This project is intended for educational and demonstration purposes.
