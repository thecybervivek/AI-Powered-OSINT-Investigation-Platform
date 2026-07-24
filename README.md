# 🕵️ AI-Powered OSINT Investigation Platform

![Python](https://img.shields.io/badge/Python-3.13-blue?style=for-the-badge&logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-Backend-009688?style=for-the-badge&logo=fastapi)
![React](https://img.shields.io/badge/React-Frontend-61DAFB?style=for-the-badge&logo=react)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-Database-336791?style=for-the-badge&logo=postgresql)
![Docker](https://img.shields.io/badge/Docker-Container-2496ED?style=for-the-badge&logo=docker)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-In%20Development-orange?style=for-the-badge)
![Backend](https://img.shields.io/badge/Backend-Milestone%206%20Completed-success?style=for-the-badge)

> **A production-grade AI-powered Open Source Intelligence (OSINT) Investigation Platform** built with FastAPI, React, PostgreSQL, Docker, and AI integrations. The platform enables investigators, SOC analysts, penetration testers, threat intelligence teams, and cybersecurity professionals to collect, analyze, correlate, and generate intelligence reports from multiple OSINT sources through a modern web interface.

---

# 🎯 Project Objective

Build an enterprise-grade AI-powered OSINT Investigation Platform capable of collecting intelligence from multiple public sources while providing automated AI-assisted analysis, investigation history, risk assessment, and professional investigation reports.

The platform focuses on:

- Collecting publicly available intelligence
- Automating investigations
- AI-assisted intelligence analysis
- Evidence correlation
- Professional report generation
- Investigation history management
- Supporting cybersecurity professionals during investigations

---

# ✨ Features

## 🔍 Intelligence Collection

### ✅ Implemented

- Username Investigation
- Email Intelligence
- Domain Intelligence
- WHOIS Lookup
- DNS Enumeration
- IP Intelligence
- IP Reputation Analysis
- Geolocation Lookup
- URL Reputation Analysis
- IOC Classification
- File Intelligence
- File Metadata Extraction
- File Hashing (MD5, SHA1, SHA256)
- Investigation Timeline

### 🚧 Planned

- Phone Number Intelligence
- Reverse Image Search
- Social Media Enumeration
- Breach Intelligence
- Dark Web Intelligence
- Malware Intelligence
- Threat Feed Aggregation

---

## 🤖 AI Features

### 🚧 Planned

- AI Investigation Summary
- AI Threat Analysis
- AI Risk Assessment
- AI Evidence Correlation
- AI Report Generation
- AI Recommendations

---

## 📊 Dashboard *(Upcoming React Frontend)*

- Investigation Dashboard
- Investigation History
- Saved Reports
- User Dashboard
- Analytics
- Investigation Timeline
- Search History
- Recent Investigations

---

## 🔐 Security

### ✅ Implemented

- JWT Authentication
- Refresh Tokens
- Password Hashing (bcrypt)
- Protected APIs
- API Rate Limiting
- Input Validation
- Secure File Validation

### 🚧 Planned

- Role Based Access Control (RBAC)
- Email Verification
- Password Reset
- Audit Logs
- MFA Authentication

---

# 🛠️ Technology Stack

| Category | Technology |
|------------|----------------|
| Backend | FastAPI |
| Frontend | React |
| Database | PostgreSQL |
| Development Database | SQLite |
| ORM | SQLAlchemy |
| Database Migration | Alembic |
| Authentication | JWT |
| Password Security | bcrypt |
| API Documentation | Swagger UI |
| AI | OpenAI API *(Planned)* |
| Containerization | Docker |
| Version Control | Git + GitHub |

---

# 📂 Project Structure

```text
AI-Powered-OSINT-Investigation-Platform/

backend/
│
├── app/
│   ├── api/
│   ├── core/
│   ├── db/
│   ├── integrations/
│   ├── models/
│   ├── repositories/
│   ├── schemas/
│   ├── services/
│   ├── utils/
│   └── main.py
│
├── alembic/
├── tests/
├── requirements.txt
└── README.md
```

---

# 🚀 Current Development Roadmap

## ✅ Completed

### Project Foundation

- [x] Project Structure
- [x] FastAPI Backend Setup
- [x] SQLAlchemy Integration
- [x] Alembic Database Migration
- [x] PostgreSQL Support
- [x] SQLite Development Database
- [x] Git Version Control
- [x] GitHub Repository Setup

### Authentication

- [x] JWT Authentication
- [x] User Registration
- [x] User Login
- [x] Refresh Token
- [x] Protected Routes
- [x] Current User API
- [x] Logout API
- [x] Password Hashing

### OSINT Modules

- [x] Username Investigation
- [x] Email Intelligence
- [x] Domain Intelligence
- [x] WHOIS Lookup
- [x] DNS Enumeration
- [x] IP Intelligence
- [x] IP Reputation
- [x] URL Reputation Analysis
- [x] IOC Analysis
- [x] File Intelligence
- [x] Metadata Extraction
- [x] File Hashing
- [x] Investigation Timeline

### Security

- [x] API Rate Limiting
- [x] File Validation
- [x] Secure Upload Handling

---

## 🚧 Currently Working On

- [ ] Milestone 6 Part 2
- [ ] Advanced File Analysis
- [ ] AI Integration Preparation

---

## 📌 Upcoming Features

### AI Intelligence

- [ ] AI Report Generator
- [ ] AI Threat Analysis
- [ ] AI Evidence Correlation
- [ ] AI Risk Assessment
- [ ] AI Recommendations

### Intelligence Modules

- [ ] Phone Number Intelligence
- [ ] Reverse Image Search
- [ ] Social Media Enumeration
- [ ] Breach Intelligence
- [ ] Threat Intelligence
- [ ] Malware Intelligence

### Dashboard

- [ ] React Frontend
- [ ] Investigation Dashboard
- [ ] Saved Reports
- [ ] Search History
- [ ] Analytics
- [ ] Timeline Visualization

### Export

- [ ] PDF Reports
- [ ] CSV Export
- [ ] JSON Export
- [ ] DOCX Export

### Deployment

- [ ] Docker
- [ ] Docker Compose
- [ ] Nginx
- [ ] CI/CD Pipeline
- [ ] Cloud Deployment

---

# 🚀 Installation

```bash
git clone https://github.com/vivek-sh45/AI-Powered-OSINT-Investigation-Platform.git

cd AI-Powered-OSINT-Investigation-Platform

python -m venv .venv

source .venv/bin/activate
# Windows:
# .venv\Scripts\activate

pip install -r requirements.txt

alembic upgrade head

uvicorn backend.app.main:app --reload
```

---

# 📚 API Documentation

After starting the server:

**Swagger UI**

```
http://127.0.0.1:8000/docs
```

**ReDoc**

```
http://127.0.0.1:8000/redoc
```

---

# 📈 Project Status

| Phase | Status |
|----------|------------|
| Backend Setup | ✅ Completed |
| Authentication | ✅ Completed |
| Database Migration | ✅ Completed |
| PostgreSQL Integration | ✅ Completed |
| Core OSINT Modules | ✅ Completed |
| File Intelligence | ✅ Completed |
| API Documentation | ✅ Completed |
| AI Integration | 🚧 Planned |
| React Frontend | 🚧 Planned |
| Deployment | ⏳ Planned |

---

# 🎯 Target Users

- SOC Analysts
- Cybersecurity Analysts
- Threat Intelligence Analysts
- Digital Forensics Investigators
- Penetration Testers
- Incident Responders
- Bug Bounty Hunters
- Security Researchers
- Blue Team Professionals

---

# 📸 Screenshots

*(Screenshots will be added as development progresses.)*

---

# 🤝 Contributing

Contributions, feature requests, and suggestions are welcome.

If you'd like to contribute:

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Submit a Pull Request

---

# 📄 License

This project is licensed under the **MIT License**.

---

# 👤 Author

**Vivek Sharma**

**Cybersecurity Analyst | SOC | OSINT | Network Security | Threat Intelligence**

[![LinkedIn](https://img.shields.io/badge/LinkedIn-vivek--sharma--cybersec-0077B5?style=flat&logo=linkedin)](https://linkedin.com/in/vivek-sharma-cybersec)

[![GitHub](https://img.shields.io/badge/GitHub-vivek--sh45-181717?style=flat&logo=github)](https://github.com/vivek-sh45)

[![Email](https://img.shields.io/badge/Email-thecybervivek@gmail.com-D14836?style=flat&logo=gmail)](mailto:thecybervivek@gmail.com)

---

⭐ **If you find this project useful, consider giving it a star on GitHub!**
