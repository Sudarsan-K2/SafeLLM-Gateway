import os
import re
import sqlite3
import datetime
import jwt
import bcrypt
from fastapi import FastAPI, HTTPException, Depends, Header, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from typing import Optional, List
from dotenv import load_dotenv
from google import genai
from google.genai import types

load_dotenv()

app = FastAPI(title="SafeLLM Enterprise Proxy Engine")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_FILE = "safellm.db"
JWT_SECRET = os.getenv("JWT_SECRET", "SUPER_SECRET_SECURITY_PASSPHRASE_KEY_12345")
JWT_ALGORITHM = "HS256"

# CORE DATABASE HARDENING: Map users to sessions
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    # Users Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
            password_hash TEXT
        )
    ''')
    # Updated Sessions Table (Linked to User Email)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            user_email TEXT,
            title TEXT,
            system_prompt TEXT,
            FOREIGN KEY(user_email) REFERENCES users(email) ON DELETE CASCADE
        )
    ''')
    # Messages Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT,
            text TEXT,
            is_user INTEGER,
            was_redacted_notice INTEGER,
            FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE CASCADE
        )
    ''')
    conn.commit()
    conn.close()

init_db()

client = genai.Client()

# Security Interceptor: Validates the incoming browser token
def get_current_user(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Access Denied: Missing cryptographic token.")
    
    token = authorization.split(" ")[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload["sub"] # Returns user email
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Session expired. Please log back in.")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid security token integrity.")

# Input Validation Schemes
class UserAuth(BaseModel):
    email: EmailStr
    password: str

class ChatRequest(BaseModel):
    message: str
    system_prompt: Optional[str] = None
    model: str = "gemini-2.5-flash"

class SessionCreate(BaseModel):
    id: str
    title: str
    system_prompt: str

# PII Scrubbing Rules
EMAIL_REGEX = r'[a-zA-Z0-9-_.]+@[a-zA-Z0-9-_.]+\.[a-zA-Z]{2,5}'
PHONE_REGEX = r'\+?\d{1,4}?[-.\s]?\(?\d{1,3}?\)?[-.\s]?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,9}'
CREDIT_CARD_REGEX = r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b'

def sanitize_prompt(text: str) -> tuple[str, bool]:
    sanitized = text
    modified = False
    if re.search(EMAIL_REGEX, sanitized):
        sanitized = re.sub(EMAIL_REGEX, "[REDACTED_EMAIL]", sanitized)
        modified = True
    if re.search(PHONE_REGEX, sanitized):
        sanitized = re.sub(PHONE_REGEX, "[REDACTED_PHONE]", sanitized)
        modified = True
    if re.search(CREDIT_CARD_REGEX, sanitized):
        sanitized = re.sub(CREDIT_CARD_REGEX, "[REDACTED_CARD]", sanitized)
        modified = True
    return sanitized, modified

# --- AUTHENTICATION ENDPOINTS ---
@app.post("/api/auth/register")
def register_user(user: UserAuth):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Hash password safely using bcrypt
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(user.password.encode('utf-8'), salt).decode('utf-8')
    
    try:
        cursor.execute("INSERT INTO users (email, password_hash) VALUES (?, ?)", (user.email, hashed))
        conn.commit()
        return {"status": "success", "message": "Identity verified and established."}
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="An account with this email already exists.")
    finally:
        conn.close()

@app.post("/api/auth/login")
def login_user(user: UserAuth):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash FROM users WHERE email = ?", (user.email,))
    row = cursor.fetchone()
    conn.close()
    
    if not row or not bcrypt.checkpw(user.password.encode('utf-8'), row[0].encode('utf-8')):
        raise HTTPException(status_code=401, detail="Invalid credential pairing.")
    
    # Mint a secure 24-hour token passport
    expiration = datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    token = jwt.encode({"sub": user.email, "exp": expiration}, JWT_SECRET, algorithm=JWT_ALGORITHM)
    
    return {"access_token": token, "email": user.email}

# --- GUARDED CORE PIPELINE ENDPOINTS ---
@app.get("/api/sessions")
def get_all_sessions(current_user: str = Depends(get_current_user)):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    # Filter strictly by who is logged in!
    cursor.execute("SELECT id, title, system_prompt FROM sessions WHERE user_email = ? ORDER BY rowid DESC", (current_user,))
    rows = cursor.fetchall()
    
    sessions_list = []
    for row in rows:
        cursor.execute("SELECT text, is_user, was_redacted_notice FROM messages WHERE session_id = ?", (row[0],))
        msg_rows = cursor.fetchall()
        messages = [{"text": m[0], "isUser": bool(m[1]), "wasRedactedNotice": bool(m[2])} for m in msg_rows]
        
        sessions_list.append({
            "id": row[0],
            "title": row[1],
            "systemPrompt": row[2],
            "messages": messages
        })
    conn.close()
    return sessions_list

@app.post("/api/sessions/create")
def create_session_db(payload: SessionCreate, current_user: str = Depends(get_current_user)):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO sessions (id, user_email, title, system_prompt) VALUES (?, ?, ?, ?)", 
                       (payload.id, current_user, payload.title, payload.system_prompt))
        conn.commit()
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        conn.close()
    return {"status": "success"}

@app.delete("/api/sessions/{session_id}")
def delete_session_db(session_id: str, current_user: str = Depends(get_current_user)):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    # Ensure they own the session before deleting
    cursor.execute("DELETE FROM sessions WHERE id = ? AND user_email = ?", (session_id, current_user))
    cursor.execute("DELETE FROM messages WHERE session_id = ?", (session_id,))
    conn.commit()
    conn.close()
    return {"status": "deleted"}

@app.post("/api/chat/{session_id}")
def chat_and_store(session_id: str, payload: ChatRequest, current_user: str = Depends(get_current_user)):
    try:
        clean_message, was_redacted = sanitize_prompt(payload.message)
        
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # Security sanity check: verify session owner
        cursor.execute("SELECT user_email FROM sessions WHERE id = ?", (session_id,))
        owner = cursor.fetchone()
        if not owner or owner[0] != current_user:
            conn.close()
            raise HTTPException(status_code=403, detail="Forbidden: Resource tampering detected.")
            
        cursor.execute("INSERT INTO messages (session_id, text, is_user, was_redacted_notice) VALUES (?, ?, ?, ?)",
                       (session_id, payload.message, 1, 0))
        
        cursor.execute("SELECT title FROM sessions WHERE id = ?", (session_id,))
        current_title = cursor.fetchone()
        if current_title and current_title[0] == "New Secure Chat":
            new_title = payload.message[:24] + "..." if len(payload.message) > 24 else payload.message
            cursor.execute("UPDATE sessions SET title = ?, system_prompt = ? WHERE id = ?", 
                           (new_title, payload.system_prompt, session_id))
        else:
            cursor.execute("UPDATE sessions SET system_prompt = ? WHERE id = ?", (payload.system_prompt, session_id))
        conn.commit()

        config = None
        if payload.system_prompt:
            config = types.GenerateContentConfig(system_instruction=payload.system_prompt)

        response = client.models.generate_content(
            model=payload.model,
            contents=clean_message,
            config=config
        )
        
        cursor.execute("INSERT INTO messages (session_id, text, is_user, was_redacted_notice) VALUES (?, ?, ?, ?)",
                       (session_id, response.text, 0, 1 if was_redacted else 0))
        conn.commit()
        conn.close()
        
        return {
            "success": True, 
            "reply": response.text,
            "was_redacted": was_redacted
        }
    
    except Exception as e:
        error_msg = str(e)
        if "429" in error_msg:
            error_msg = "Google API Tier Limit: 429 Quota Exceeded."
        raise HTTPException(status_code=400, detail=error_msg)
    
# --- PHASE 3: THE CARGO - SECURE FILE SANDBOX ENGINE ---
@app.post("/api/sandbox/upload")
async def secure_file_ingestion(
    file: UploadFile = File(...), 
    current_user: str = Depends(get_current_user)
):
    # Enterprise Security Guardrail: Block dangerous binary formats
    forbidden_extensions = [".exe", ".bat", ".sh", ".msi", ".vbs"]
    file_ext = os.path.splitext(file.filename)[1].lower()
    
    if file_ext in forbidden_extensions:
        raise HTTPException(status_code=400, detail="Security Violation: Executable scripts/binaries are barred from transit.")

    try:
        # Read file contents directly into local memory buffer
        contents = await file.read()
        raw_text = contents.decode("utf-8", errors="ignore")
        
        # Enforce local proxy scanning before anything goes to the cloud
        clean_text, was_redacted = sanitize_prompt(raw_text)
        
        return {
            "fileName": file.filename,
            "was_redacted": was_redacted,
            "extracted_content": clean_text
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Inbound Data Ingestion Failure: {str(e)}")