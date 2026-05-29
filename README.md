# SafeLLM Enterprise AI Proxy Gateway

[![Status](https://img.shields.io/badge/Status-In--Development%20%2F%20Building-amber?style=for-the-badge&logo=github)](https://github.com/Sudarsan-K2/SafeLLM-Gateway)
[![Backend](https://img.shields.io/badge/Backend-FastAPI%20%2F%20Python-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Database](https://img.shields.io/badge/Database-SQLite%203-003B57?style=for-the-badge&logo=sqlite&logoColor=white)](https://sqlite.org/)
[![Security](https://img.shields.io/badge/Security-JWT%20%2B%20Bcrypt-000000?style=for-the-badge&logo=jsonwebtokens&logoColor=white)]()

> **Enterprise Guardrail Engine:** A full-stack, local proxy server designed to protect corporate networks from data leaks by dynamically intercepting, auditing, and scrubbing sensitive files and prompt texts *before* they cross the firewall into third-party Cloud LLMs.

---

## 🎯 Project Overview & Core Mission
Many enterprises block access to public AI tools (like ChatGPT or Google Gemini) because employees accidentally copy-paste internal secrets, server passwords, financial details, or client PII (Personally Identifiable Information) into prompt windows. Once that data hits the public cloud, it could be used for training, triggering catastrophic corporate compliance violations.

**SafeLLM solves this.** It acts as an air-gapped intermediary middleware interface. Employees interact with a modern workspace, upload source code, or type queries. Behind the scenes, the SafeLLM engine strips away credentials, email records, and trackable patterns, replacing them with safe compliance markers. Only the sanitized "safe cargo" is securely passed up to Google Gemini's underlying models.

---

## 🛡️ Implemented Core Capabilities

### 🗃️ Phase 1: Persistent Secure Vault Ledger
* **State Management:** Migrated away from fragile browser-side session states into an isolated, server-managed SQLite 3 database relational layout.
* **Granular Tracking:** Maps distinct message historical nodes (`is_user`, `was_redacted_notice`) to cleanly preserve compliance reporting.

### 🔑 Phase 2: Cryptographic Identity Enforcement (The Lock)
* **JWT Passport Authentication:** Implemented JSON Web Token flows. The browser negotiates a temporary encrypted digital token which is attached to the authorization header of every operational API endpoint.
* **Password Hashing Protection:** Implemented zero-plaintext password handling via `bcrypt` internal salting routines to guarantee local credential sovereignty.
* **Session Multi-Tenancy Isolation:** Enforced strict backend database query segregation (`WHERE user_email = ?`) making chat sessions entirely secure and visible only to their authenticated owners.

### 🧳 Phase 3: Text & File Data Sandbox (The Cargo)
* **Multipart File Ingestion:** Configured a secure textual multi-format parser (`.txt`, `.py`, `.js`, `.json`, `.csv`, `.log`) running completely inside local machine memory buffers.
* **Binary Execution Shield:** Built structural extensions blocks protecting corporate micro-services by preventing runtime execution formats (`.exe`, `.bat`, `.sh`, `.msi`) from processing.
* **Real-Time Regular Expression Sanitizers:** Built inline pre-transit compliance filters targeting high-risk patterns (Emails, Phone Sequences, and Credit Card sequences) using strict pattern substitution masks.

---

## 📐 Enterprise Architecture Map

```text
┌────────────────────────────────────────────────────────┐
│                   CLIENT APPLICATION                   │
│         Tailwind CSS Dashboard UI (index.html)        │
└───────────────────────────┬────────────────────────────┘
                            │
              (Protected HTTPS + JWT Bearer Token)
                            ▼
┌────────────────────────────────────────────────────────┐
│              FASTAPI LOCAL PROXY ENGINE                │
│                       (main.py)                        │
├────────────────────────────────────────────────────────┤
│  [Auth Interceptor] ──► Validates JWT Tokens           │
│  [File Ingestor]    ──► Parses and decodes text streams │
│  [Scrubbing Engine] ──► RegEx Pattern Sanitization      │
└───────────────────────────┬────────────────────────────┘
                            │
               (Sanitized Prompts / Safe Text)
                            ▼
┌────────────────────────────────────────────────────────┐
│                   UPSTREAM SERVICES                    │
│      Google GenAI Client Engine (Gemini 2.5 Flash)     │
└────────────────────────────────────────────────────────┘