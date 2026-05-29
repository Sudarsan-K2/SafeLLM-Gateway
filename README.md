# SafeLLM: Local AI Security Proxy

[![Status](https://img.shields.io/badge/Status-In--Development%20%2F%20Building-amber?style=for-the-badge&logo=github)](https://github.com/Sudarsan-K2/SafeLLM-Gateway)
[![Backend](https://img.shields.io/badge/Backend-FastAPI%20%2F%20Python-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Database](https://img.shields.io/badge/Database-SQLite%203-003B57?style=for-the-badge&logo=sqlite&logoColor=white)](https://sqlite.org/)
[![Security](https://img.shields.io/badge/Security-JWT%20%2B%20Bcrypt-000000?style=for-the-badge&logo=jsonwebtokens&logoColor=white)]()

> **A local, full-stack proxy middleware designed to intercept, audit, and sanitize sensitive files and text prompts before they are sent to third-party Cloud LLMs.**

---

## 🎯 Project Overview
As AI tools become more integrated into daily workflows, the risk of accidentally leaking sensitive data—like personal information, API keys, or internal passwords—into public LLM training sets has grown. 

**SafeLLM** is a personal project built to explore AI security and proxy architecture. It acts as a local middleware layer between the user and Google's Gemini API. Users interact with a custom UI to upload files or type prompts. Before any data leaves the local network, the SafeLLM backend scans the payload, strips away sensitive patterns (like emails and passwords), and forwards only the sanitized text to the cloud.

---

## 🛡️ Core Features Built

### 1. Database & Session Management
* Migrated from local browser storage to a server-side **SQLite 3** relational database.
* Stores isolated user chat histories and tracks when sensitive data was successfully redacted.

### 2. Authentication & API Security
* **JWT (JSON Web Tokens):** Implemented secure token-based authentication. The frontend attaches a Bearer token to every API request to verify identity.
* **Password Hashing:** Uses `bcrypt` to hash and salt user passwords, ensuring zero plaintext credentials are saved in the database.
* **Data Isolation:** Backend queries enforce strict user segregation (`WHERE user_email = ?`), ensuring users can only access their own data.

### 3. File Sandbox & Data Sanitization
* **File Ingestion:** Built a multipart file upload endpoint capable of reading `.txt`, `.py`, `.js`, `.json`, `.csv`, and `.log` files directly into local memory.
* **Security Guardrails:** Blocks dangerous executable formats (`.exe`, `.bat`, etc.) from being processed.
* **RegEx Scrubber:** Uses Regular Expressions to dynamically detect and redact high-risk patterns (like emails and passwords) before the payload is sent to the Gemini API.

---

## 📐 System Architecture

```text
┌────────────────────────────────────────────────────────┐
│                   CLIENT DASHBOARD                     │
│               HTML / Tailwind CSS / JS                 │
└───────────────────────────┬────────────────────────────┘
                            │
               (HTTPS + JWT Bearer Token)
                            ▼
┌────────────────────────────────────────────────────────┐
│                 FASTAPI PROXY ENGINE                   │
│                       (main.py)                        │
├────────────────────────────────────────────────────────┤
│  1. Token Verification                                 │
│  2. File Parsing & Memory Loading                      │
│  3. RegEx Pattern Sanitization (Scrubber)              │
└───────────────────────────┬────────────────────────────┘
                            │
              (Sanitized Prompts / Safe Code)
                            ▼
┌────────────────────────────────────────────────────────┐
│                   UPSTREAM SERVICES                    │
│      Google GenAI Client Engine (Gemini API)           │
└────────────────────────────────────────────────────────┘
```

---

## 🧬 Tech Stack
* **Frontend:** Vanilla JS, Tailwind CSS (via CDN), Lucide Icons
* **Backend:** `FastAPI` (Python), `Uvicorn` (ASGI Server)
* **Security:** `PyJWT` (Token generation), `bcrypt` (Password hashing)
* **Database:** `sqlite3` (Embedded relational database)
* **File Processing:** `python-multipart`

---

## 🚀 Active Roadmap

This project is currently in active development. Next steps include:

- [✅] JWT Security & User Authentication
- [✅] File Processing Sandbox & RegEx Scanner
- [ ] Migrate local storage from SQLite to PostgreSQL.
- [ ] Dockerize the application for easier deployment.
- [ ] Add an API Key scanner to detect leaked AWS/Google secrets in uploaded code.

---

## ⚙️ How to Run Locally

### 1. Setup Environment
```bash
git clone [https://github.com/Sudarsan-K2/SafeLLM-Gateway.git](https://github.com/Sudarsan-K2/SafeLLM-Gateway.git)
cd SafeLLM-Gateway
python -m venv venv
# On Windows:
.\venv\Scripts\activate
# On Mac/Linux:
source venv/bin/activate
```

### 2. Install Dependencies
```bash
pip install fastapi uvicorn google-genai python-dotenv bcrypt PyJWT email-validator python-multipart
```

### 3. Environment Variables
Create a `.env` file in the root directory:
```text
GEMINI_API_KEY=your_google_api_key_here
JWT_SECRET=your_custom_secret_key_here
```

### 4. Start the Server
```bash
uvicorn main:app --reload
```
Open `index.html` in your browser to log in and start testing!
```
