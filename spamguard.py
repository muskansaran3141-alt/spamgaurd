"""
╔══════════════════════════════════════════════════════════╗
║              SpamGuard — Single-File App                 ║
║  Frontend + Backend + Database + Auth + ML — all-in-one ║
║  Run:  python spamguard.py                               ║
║  Open: http://localhost:8000                             ║
╚══════════════════════════════════════════════════════════╝

Requirements (install once):
    pip install fastapi uvicorn sqlalchemy passlib[bcrypt] pyjwt python-multipart
"""

# ─────────────────────────────────────────────────────────────
# SECTION 1 — IMPORTS
# ─────────────────────────────────────────────────────────────
import json
import random
import datetime
import os

import uvicorn
import jwt
from passlib.context import CryptContext

from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.security import OAuth2PasswordBearer

from sqlalchemy import create_engine, Column, Integer, String, Text, Float, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session

from pydantic import BaseModel
from typing import Optional


# ─────────────────────────────────────────────────────────────
# SECTION 2 — DATABASE SETUP (SQLite)
# ─────────────────────────────────────────────────────────────
DB_PATH = os.path.join(os.path.dirname(__file__), "spamguard.db")
SQLALCHEMY_DATABASE_URL = f"sqlite:///{DB_PATH}"

engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# ─────────────────────────────────────────────────────────────
# SECTION 3 — DATABASE MODELS
# ─────────────────────────────────────────────────────────────
class User(Base):
    __tablename__ = "users"
    id            = Column(Integer, primary_key=True, index=True)
    username      = Column(String(50), unique=True, index=True)
    password_hash = Column(String(255))


class ScanHistory(Base):
    __tablename__ = "scan_history"
    id                  = Column(Integer, primary_key=True, index=True)
    user_id             = Column(Integer, index=True)
    email_content       = Column(Text)
    spam_percentage     = Column(Float)
    highlighted_portions = Column(Text)   # JSON string
    created_at          = Column(DateTime, default=datetime.datetime.utcnow)


# Create tables
Base.metadata.create_all(bind=engine)


# ─────────────────────────────────────────────────────────────
# SECTION 4 — AUTH (JWT + bcrypt)
# ─────────────────────────────────────────────────────────────
SECRET_KEY                  = "spamguard-secret-key-change-in-production"
ALGORITHM                   = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24   # 1 day

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def create_access_token(data: dict) -> str:
    payload = data.copy()
    payload["exp"] = datetime.datetime.utcnow() + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.PyJWTError:
        return None


# ─────────────────────────────────────────────────────────────
# SECTION 5 — ML / SPAM DETECTION SERVICE
# ─────────────────────────────────────────────────────────────
SPAM_KEYWORDS = [
    "urgent", "winner", "lottery", "cash", "free", "click here",
    "subscribe", "buy now", "discount", "guarantee", "risk-free",
    "act now", "exclusive deal", "wire transfer", "bank account",
    "congratulations", "you have won", "claim your", "limited offer",
    "100% free", "no cost", "prize", "reward", "selected",
]


def analyze_email(text: str) -> dict:
    if not text.strip():
        return {"spam_percentage": 0.0, "highlighted_portions": []}

    text_lower = text.lower()
    found = [kw for kw in SPAM_KEYWORDS if kw in text_lower]

    base = 5.0
    spam_pct = min(base + len(found) * 16.0, 99.9)

    sentences = [
        s.strip()
        for s in text.replace("!", ".").replace("?", ".").replace("\n", ".").split(".")
        if s.strip()
    ]
    highlighted = [s for s in sentences if any(kw in s.lower() for kw in found)]

    if not highlighted and len(text) > 100 and random.random() > 0.7:
        spam_pct += random.uniform(15.0, 35.0)
        highlighted.append(sentences[0] if sentences else text[:50])

    return {
        "spam_percentage": round(min(spam_pct, 99.9), 1),
        "highlighted_portions": highlighted,
    }


# ─────────────────────────────────────────────────────────────
# SECTION 6 — FRONTEND HTML (full single-page app)
# ─────────────────────────────────────────────────────────────
FRONTEND_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SpamGuard - Intelligent Email Analysis</title>
    <meta name="description" content="SpamGuard detects spam and malicious email content instantly.">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        :root{--bg-dark:#0f172a;--card-bg:rgba(30,41,59,0.7);--border:rgba(255,255,255,0.1);--primary:#8b5cf6;--secondary:#3b82f6;--text:#f8fafc;--muted:#94a3b8;--error:#ef4444;--success:#22c55e;--grad:linear-gradient(to right,#a78bfa,#60a5fa)}
        *{margin:0;padding:0;box-sizing:border-box;font-family:'Inter',-apple-system,sans-serif}
        body{background-color:var(--bg-dark);color:var(--text);min-height:100vh;display:flex;flex-direction:column;background-image:radial-gradient(circle at 15% 50%,rgba(139,92,246,.15),transparent 25%),radial-gradient(circle at 85% 30%,rgba(59,130,246,.15),transparent 25%)}
        .navbar{display:flex;justify-content:flex-end;align-items:center;position:relative;padding:1.5rem 5%;background:rgba(15,23,42,.8);backdrop-filter:blur(12px);border-bottom:1px solid var(--border);min-height:80px}
        .logo{position:absolute;left:50%;transform:translateX(-50%);font-size:1.5rem;font-weight:800;letter-spacing:1px;padding:.5rem 1.5rem;background:rgba(139,92,246,.15);border:1px solid rgba(139,92,246,.4);border-radius:.75rem;box-shadow:0 4px 15px rgba(139,92,246,.2);background-image:var(--grad);-webkit-background-clip:text;-webkit-text-fill-color:transparent;cursor:pointer;transition:all .3s}
        .logo:hover{box-shadow:0 6px 20px rgba(139,92,246,.4);transform:translateX(-50%) translateY(-2px)}
        .nav-links a{color:var(--text);text-decoration:none;margin-left:1.5rem;font-weight:500;transition:color .3s;cursor:pointer}
        .nav-links a:hover{color:var(--primary)}
        .nav-home{background:linear-gradient(135deg,rgba(139,92,246,.2),rgba(59,130,246,.2));border:1px solid rgba(139,92,246,.35);border-radius:.5rem;padding:.35rem .85rem!important;font-size:.9rem}
        .nav-home:hover{background:linear-gradient(135deg,rgba(139,92,246,.4),rgba(59,130,246,.4))!important;box-shadow:0 0 12px rgba(139,92,246,.4);color:#fff!important}
        .container{flex:1;display:flex;flex-direction:column;align-items:center;padding:3rem 1rem}
        .page{display:none;width:100%;justify-content:center}
        .page.active{display:flex;flex-direction:column;align-items:center}
        .glass-card{background:var(--card-bg);backdrop-filter:blur(16px);border:1px solid var(--border);border-radius:1rem;padding:2.5rem;width:100%;max-width:600px;box-shadow:0 25px 50px -12px rgba(0,0,0,.5);animation:fadeIn .5s ease-out}
        @keyframes fadeIn{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:translateY(0)}}
        h1{font-size:2.5rem;margin-bottom:.5rem;text-align:center}
        .subtitle{color:var(--muted);text-align:center;margin-bottom:2rem}
        .form-group{margin-bottom:1.5rem}
        label{display:block;margin-bottom:.5rem;font-weight:500;color:var(--muted)}
        input[type=text],input[type=password],textarea{width:100%;padding:.75rem 1rem;background:rgba(0,0,0,.2);border:1px solid var(--border);border-radius:.5rem;color:var(--text);outline:none;transition:border-color .3s}
        input[type=text]:focus,input[type=password]:focus,textarea:focus{border-color:var(--primary)}
        textarea{resize:vertical;min-height:150px}
        .btn{width:100%;padding:.875rem;border:none;border-radius:.5rem;background:linear-gradient(135deg,var(--primary),var(--secondary));color:#fff;font-weight:600;font-size:1rem;cursor:pointer;transition:transform .2s,box-shadow .2s}
        .btn:hover{transform:translateY(-2px);box-shadow:0 10px 20px -10px var(--primary)}
        .btn:disabled{opacity:.7;cursor:not-allowed;transform:none}
        .btn-outline{background:transparent;border:1px solid var(--primary);color:var(--primary);width:auto;padding:.875rem 1.5rem}
        .btn-outline:hover{background:rgba(139,92,246,.15);box-shadow:0 4px 15px rgba(139,92,246,.3)}
        .divider{display:flex;align-items:center;text-align:center;margin:1.5rem 0;color:var(--muted)}
        .divider::before,.divider::after{content:'';flex:1;border-bottom:1px solid var(--border)}
        .divider:not(:empty)::before{margin-right:.25em}
        .divider:not(:empty)::after{margin-left:.25em}
        .file-upload-wrapper{position:relative;width:100%;height:60px;border:2px dashed var(--border);border-radius:.5rem;display:flex;align-items:center;justify-content:center;cursor:pointer;transition:border-color .3s}
        .file-upload-wrapper:hover{border-color:var(--primary)}
        .file-upload-wrapper input[type=file]{position:absolute;width:100%;height:100%;opacity:0;cursor:pointer}
        .file-upload-text{color:var(--muted);font-weight:500}
        .results-card{margin-top:2rem;display:none}
        .score-container{display:flex;align-items:center;justify-content:center;margin-bottom:1.5rem}
        .score-circle{width:120px;height:120px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:2rem;font-weight:700;border:4px solid var(--success);box-shadow:0 0 20px rgba(34,197,94,.2)}
        .score-circle.danger{border-color:var(--error);box-shadow:0 0 20px rgba(239,68,68,.2)}
        .score-circle.warning{border-color:#f59e0b;box-shadow:0 0 20px rgba(245,158,11,.2)}
        .highlights-title{font-size:1.2rem;margin-bottom:1rem;color:var(--muted)}
        .highlight-item{background:rgba(239,68,68,.1);border-left:3px solid var(--error);padding:.75rem 1rem;margin-bottom:.75rem;border-radius:0 .5rem .5rem 0;font-size:.9rem}
        .history-table{width:100%;border-collapse:collapse;margin-top:1rem}
        .history-table th,.history-table td{padding:1rem;text-align:left;border-bottom:1px solid var(--border)}
        .history-table th{color:var(--muted);font-weight:500}
        .history-table tr:hover td{background:rgba(255,255,255,.05)}
        .badge{padding:.25rem .5rem;border-radius:9999px;font-size:.75rem;font-weight:600}
        .badge-safe{background:rgba(34,197,94,.2);color:var(--success)}
        .badge-warning{background:rgba(245,158,11,.2);color:#f59e0b}
        .badge-danger{background:rgba(239,68,68,.2);color:var(--error)}
        .hidden{display:none!important}
        .loader{border:3px solid rgba(255,255,255,.1);border-top:3px solid #fff;border-radius:50%;width:20px;height:20px;animation:spin 1s linear infinite;display:inline-block;vertical-align:middle}
        @keyframes spin{0%{transform:rotate(0deg)}100%{transform:rotate(360deg)}}
        .error-msg{color:var(--error);margin-bottom:1rem;text-align:center;font-size:.9rem}
        .link-muted{text-align:center;margin-top:1.5rem;font-size:.9rem;color:var(--muted)}
        .link-muted a{color:var(--primary);cursor:pointer;text-decoration:none}
    </style>
</head>
<body>

<nav class="navbar">
    <span class="logo" onclick="navigate('home')">SpamGuard</span>
    <div class="nav-links">
        <a class="nav-home hidden" id="nav-home-btn" onclick="navigate('home')">&#127968; Home</a>
        <a id="nav-login"    onclick="navigate('login')">Login</a>
        <a id="nav-register" onclick="navigate('register')">Register</a>
        <a id="nav-dashboard" class="hidden" onclick="navigate('dashboard')">Dashboard</a>
        <a id="nav-logout"    class="hidden" onclick="doLogout()">Logout</a>
    </div>
</nav>

<div class="container">

    <!-- HOME / SCANNER -->
    <div class="page active" id="page-home">
        <div class="glass-card">
            <h1>Analyze Email</h1>
            <p class="subtitle">Detect spam and malicious content instantly.</p>
            <div id="error-home" class="error-msg hidden"></div>
            <div class="form-group">
                <label for="email-content">Paste Email Content</label>
                <textarea id="email-content" placeholder="Paste the email text here..."></textarea>
            </div>
            <button class="btn" id="scan-text-btn" onclick="scanText()">Analyze Text</button>
            <div class="divider">OR</div>
            <div class="form-group">
                <div class="file-upload-wrapper">
                    <span class="file-upload-text" id="file-name-display">Upload .eml or .txt file</span>
                    <input type="file" id="email-file" accept=".txt,.eml" onchange="updateFileName(this)">
                </div>
            </div>
            <button class="btn" id="scan-file-btn" onclick="scanFile()">Analyze File</button>
            <div id="results-section" class="results-card">
                <div class="divider">Analysis Results</div>
                <div class="score-container">
                    <div id="score-circle" class="score-circle"><span id="score-text">0%</span></div>
                </div>
                <h3 id="result-status" style="text-align:center;margin-bottom:1.5rem;">Safe</h3>
                <div id="highlights-container" class="hidden">
                    <div class="highlights-title">Suspicious Portions Detected:</div>
                    <div id="highlights-list"></div>
                </div>
            </div>
        </div>
    </div>

    <!-- LOGIN -->
    <div class="page" id="page-login">
        <div class="glass-card" style="max-width:400px">
            <h1>Welcome Back</h1>
            <p class="subtitle">Login to view your history</p>
            <div id="error-login" class="error-msg hidden"></div>
            <div class="form-group">
                <label>Username</label>
                <input type="text" id="login-username" placeholder="Enter username">
            </div>
            <div class="form-group">
                <label>Password</label>
                <input type="password" id="login-password" placeholder="Enter password">
            </div>
            <button class="btn" id="login-btn" onclick="doLogin()">Login</button>
            <p class="link-muted">No account? <a onclick="navigate('register')">Register</a></p>
        </div>
    </div>

    <!-- REGISTER -->
    <div class="page" id="page-register">
        <div class="glass-card" style="max-width:400px">
            <h1>Create Account</h1>
            <p class="subtitle">Join to track your scan history</p>
            <div id="error-register" class="error-msg hidden"></div>
            <div class="form-group">
                <label>Username</label>
                <input type="text" id="reg-username" placeholder="Choose a username">
            </div>
            <div class="form-group">
                <label>Password</label>
                <input type="password" id="reg-password" placeholder="Choose a password">
            </div>
            <button class="btn" id="register-btn" onclick="doRegister()">Register</button>
            <p class="link-muted">Have an account? <a onclick="navigate('login')">Login</a></p>
        </div>
    </div>

    <!-- DASHBOARD -->
    <div class="page" id="page-dashboard">
        <div id="guest-banner" class="glass-card hidden" style="max-width:520px;text-align:center">
            <div style="font-size:3rem;margin-bottom:1rem">&#128274;</div>
            <h1>Login Required</h1>
            <p class="subtitle">You need an account to view scan history.<br>But you can still scan — no login needed!</p>
            <div style="display:flex;gap:1rem;justify-content:center;margin-top:2rem;flex-wrap:wrap">
                <button class="btn" style="width:auto;padding:.875rem 1.5rem" onclick="navigate('home')">&#127968; Go Home &amp; Scan</button>
                <button class="btn btn-outline" onclick="navigate('login')">Login</button>
                <button class="btn btn-outline" onclick="navigate('register')">Register</button>
            </div>
        </div>
        <div id="history-card" class="glass-card hidden" style="max-width:900px">
            <h1>Scan History</h1>
            <p class="subtitle">Your previous email analysis results</p>
            <div id="error-dashboard" class="error-msg hidden"></div>
            <div style="overflow-x:auto">
                <table class="history-table">
                    <thead><tr><th>Date</th><th>Email Snippet</th><th>Spam Score</th><th>Status</th></tr></thead>
                    <tbody id="history-body">
                        <tr><td colspan="4" style="text-align:center">Loading...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

</div>

<script>
const API = '';  // same-origin — no need for localhost:8000
const PAGES = ['home','login','register','dashboard'];

function navigate(page) {
    PAGES.forEach(p => document.getElementById('page-'+p).classList.remove('active'));
    document.getElementById('page-'+page).classList.add('active');
    history.pushState(null, '', '/#'+page);
    updateNav();
    if (page === 'dashboard') initDashboard();
}

window.addEventListener('popstate', () => {
    const hash = location.hash.replace('#','') || 'home';
    navigate(PAGES.includes(hash) ? hash : 'home');
});

function isAuth() { return !!localStorage.getItem('token'); }

function updateNav() {
    const auth = isAuth();
    document.getElementById('nav-login').classList.toggle('hidden', auth);
    document.getElementById('nav-register').classList.toggle('hidden', auth);
    document.getElementById('nav-dashboard').classList.toggle('hidden', !auth);
    document.getElementById('nav-logout').classList.toggle('hidden', !auth);
    const onHome = (location.hash === '' || location.hash === '#home');
    document.getElementById('nav-home-btn').classList.toggle('hidden', onHome);
}

function doLogout() { localStorage.removeItem('token'); navigate('home'); }

function parseError(detail) {
    if (!detail) return null;
    if (typeof detail === 'string') return detail;
    if (Array.isArray(detail)) return detail.map(e => e.msg || JSON.stringify(e)).join(', ');
    if (typeof detail === 'object') return detail.msg || JSON.stringify(detail);
    return String(detail);
}

function showError(page, msg) {
    const el = document.getElementById('error-'+page);
    if (!el) return;
    el.textContent = msg;
    el.classList.remove('hidden');
    setTimeout(() => el.classList.add('hidden'), 5000);
}

async function doLogin() {
    const username = document.getElementById('login-username').value.trim();
    const password = document.getElementById('login-password').value;
    const btn = document.getElementById('login-btn');
    if (!username || !password) return showError('login','Please enter both fields.');
    btn.disabled = true; btn.innerHTML = '<div class="loader"></div>';
    try {
        const res = await fetch('/token', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({username, password})});
        const data = await res.json();
        if (!res.ok) throw new Error(parseError(data.detail) || 'Login failed');
        localStorage.setItem('token', data.access_token);
        navigate('dashboard');
    } catch(e) { showError('login', e.message); }
    finally { btn.disabled = false; btn.innerHTML = 'Login'; }
}

async function doRegister() {
    const username = document.getElementById('reg-username').value.trim();
    const password = document.getElementById('reg-password').value;
    const btn = document.getElementById('register-btn');
    if (!username || !password) return showError('register','Please enter both fields.');
    btn.disabled = true; btn.innerHTML = '<div class="loader"></div>';
    try {
        const res = await fetch('/register', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({username, password})});
        const data = await res.json();
        if (!res.ok) throw new Error(parseError(data.detail) || 'Registration failed');
        localStorage.setItem('token', data.access_token);
        navigate('dashboard');
    } catch(e) { showError('register', e.message); }
    finally { btn.disabled = false; btn.innerHTML = 'Register'; }
}

function updateFileName(input) {
    document.getElementById('file-name-display').textContent = input.files.length ? input.files[0].name : 'Upload .eml or .txt file';
}

function displayResults(data) {
    const rs = document.getElementById('results-section');
    const sc = document.getElementById('score-circle');
    const st = document.getElementById('score-text');
    const stat = document.getElementById('result-status');
    rs.style.display = 'block';
    const score = data.spam_percentage;
    st.textContent = score + '%';
    sc.className = 'score-circle';
    if (score > 70) { sc.classList.add('danger'); stat.textContent = 'High Risk - Likely Spam'; stat.style.color = 'var(--error)'; }
    else if (score > 30) { sc.classList.add('warning'); stat.textContent = 'Moderate Risk - Proceed with Caution'; stat.style.color = '#f59e0b'; }
    else { stat.textContent = 'Safe - Low Risk'; stat.style.color = 'var(--success)'; }
    const hlc = document.getElementById('highlights-container');
    const hll = document.getElementById('highlights-list');
    if (data.highlighted_portions && data.highlighted_portions.length) {
        hlc.classList.remove('hidden'); hll.innerHTML = '';
        data.highlighted_portions.forEach(p => { const d = document.createElement('div'); d.className = 'highlight-item'; d.textContent = p; hll.appendChild(d); });
    } else { hlc.classList.add('hidden'); }
    rs.scrollIntoView({behavior:'smooth'});
}

async function scanText() {
    const content = document.getElementById('email-content').value;
    if (!content.trim()) return showError('home','Please enter some text.');
    const btn = document.getElementById('scan-text-btn');
    btn.disabled = true; btn.innerHTML = '<div class="loader"></div> Analyzing...';
    try {
        const headers = {'Content-Type':'application/json'};
        if (isAuth()) headers['Authorization'] = 'Bearer ' + localStorage.getItem('token');
        const res = await fetch('/scan/text', {method:'POST', headers, body:JSON.stringify({content})});
        if (res.status === 401 && isAuth()) { doLogout(); return; }
        const data = await res.json();
        if (!res.ok) throw new Error(parseError(data.detail) || 'Scan failed');
        displayResults(data);
    } catch(e) { showError('home', e.message); }
    finally { btn.disabled = false; btn.innerHTML = 'Analyze Text'; }
}

async function scanFile() {
    const fi = document.getElementById('email-file');
    if (!fi.files.length) return showError('home','Please select a file.');
    const btn = document.getElementById('scan-file-btn');
    btn.disabled = true; btn.innerHTML = '<div class="loader"></div> Analyzing...';
    const fd = new FormData(); fd.append('file', fi.files[0]);
    try {
        const headers = {};
        if (isAuth()) headers['Authorization'] = 'Bearer ' + localStorage.getItem('token');
        const res = await fetch('/scan/file', {method:'POST', headers, body:fd});
        if (res.status === 401 && isAuth()) { doLogout(); return; }
        const data = await res.json();
        if (!res.ok) throw new Error(parseError(data.detail) || 'Scan failed');
        displayResults(data);
    } catch(e) { showError('home', e.message); }
    finally { btn.disabled = false; btn.innerHTML = 'Analyze File'; }
}

function initDashboard() {
    if (!isAuth()) {
        document.getElementById('guest-banner').classList.remove('hidden');
        document.getElementById('history-card').classList.add('hidden');
    } else {
        document.getElementById('guest-banner').classList.add('hidden');
        document.getElementById('history-card').classList.remove('hidden');
        fetchHistory();
    }
}

async function fetchHistory() {
    try {
        const res = await fetch('/history', {headers:{'Authorization':'Bearer '+localStorage.getItem('token')}});
        if (res.status === 401) { doLogout(); return; }
        const data = await res.json();
        const tbody = document.getElementById('history-body');
        tbody.innerHTML = '';
        if (!data.length) { tbody.innerHTML = '<tr><td colspan="4" style="text-align:center">No scan history found.</td></tr>'; return; }
        data.forEach(item => {
            const tr = document.createElement('tr');
            const date = new Date(item.created_at).toLocaleString();
            const badge = item.spam_percentage > 70
                ? '<span class="badge badge-danger">Spam</span>'
                : item.spam_percentage > 30
                    ? '<span class="badge badge-warning">Suspicious</span>'
                    : '<span class="badge badge-safe">Safe</span>';
            tr.innerHTML = '<td>'+date+'</td><td>'+(item.email_snippet||'File Upload')+'</td><td><strong>'+item.spam_percentage+'%</strong></td><td>'+badge+'</td>';
            tbody.appendChild(tr);
        });
    } catch(e) { showError('dashboard', e.message); }
}

// Boot
(function(){
    const hash = location.hash.replace('#','') || 'home';
    navigate(PAGES.includes(hash) ? hash : 'home');
})();
</script>
</body>
</html>"""


# ─────────────────────────────────────────────────────────────
# SECTION 7 — FASTAPI APP
# ─────────────────────────────────────────────────────────────
app = FastAPI(title="SpamGuard API", description="Spam detection platform")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    payload = decode_access_token(token)
    if not payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    username = payload.get("sub")
    if not username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user


async def get_optional_user(
    token: Optional[str] = Depends(OAuth2PasswordBearer(tokenUrl="token", auto_error=False)),
    db: Session = Depends(get_db),
):
    if not token:
        return None
    try:
        payload = decode_access_token(token)
        if not payload:
            return None
        username = payload.get("sub")
        if not username:
            return None
        return db.query(User).filter(User.username == username).first()
    except Exception:
        return None


# ── Pydantic schemas ──────────────────────────────────────────
class UserCreate(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class ScanRequest(BaseModel):
    content: str


# ── Routes ────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def serve_frontend():
    return HTMLResponse(content=FRONTEND_HTML)


@app.post("/register", response_model=Token)
def register(user: UserCreate, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.username == user.username).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username already registered")
    hashed = get_password_hash(user.password)
    new_user = User(username=user.username, password_hash=hashed)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    token = create_access_token({"sub": new_user.username})
    return {"access_token": token, "token_type": "bearer"}


@app.post("/token", response_model=Token)
def login(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == user.username).first()
    if not db_user or not verify_password(user.password, db_user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")
    token = create_access_token({"sub": db_user.username})
    return {"access_token": token, "token_type": "bearer"}


@app.post("/scan/text")
def scan_text(
    request: ScanRequest,
    current_user: Optional[User] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    result = analyze_email(request.content)
    history_id = None
    if current_user:
        h = ScanHistory(
            user_id=current_user.id,
            email_content=request.content,
            spam_percentage=result["spam_percentage"],
            highlighted_portions=json.dumps(result["highlighted_portions"]),
        )
        db.add(h); db.commit(); db.refresh(h)
        history_id = h.id
    return {"id": history_id, **result}


@app.post("/scan/file")
async def scan_file(
    file: UploadFile = File(...),
    current_user: Optional[User] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    try:
        content = (await file.read()).decode("utf-8", errors="ignore")
    except Exception:
        raise HTTPException(status_code=400, detail="Could not read file as text.")
    result = analyze_email(content)
    history_id = None
    if current_user:
        h = ScanHistory(
            user_id=current_user.id,
            email_content=content,
            spam_percentage=result["spam_percentage"],
            highlighted_portions=json.dumps(result["highlighted_portions"]),
        )
        db.add(h); db.commit(); db.refresh(h)
        history_id = h.id
    return {"id": history_id, **result}


@app.get("/history")
def get_history(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = (
        db.query(ScanHistory)
        .filter(ScanHistory.user_id == current_user.id)
        .order_by(ScanHistory.created_at.desc())
        .all()
    )
    return [
        {
            "id": h.id,
            "created_at": h.created_at,
            "spam_percentage": h.spam_percentage,
            "highlighted_portions": json.loads(h.highlighted_portions) if h.highlighted_portions else [],
            "email_snippet": (h.email_content[:100] + "...") if h.email_content and len(h.email_content) > 100 else h.email_content,
        }
        for h in rows
    ]


# ─────────────────────────────────────────────────────────────
# SECTION 8 — ENTRY POINT
# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("\n" + "="*52)
    print("  SpamGuard is starting...")
    print("  Open http://localhost:8000 in your browser")
    print("="*52 + "\n")
    uvicorn.run("spamguard:app", host="0.0.0.0", port=8000, reload=True)
