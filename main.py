import os
import bcrypt
import psycopg2
import psycopg2.extras
import requests
from datetime import datetime, timedelta
from typing import Optional, List
from dotenv import load_dotenv
from jose import jwt, JWTError
from fastapi import FastAPI, Request, HTTPException, Depends, status, Body, BackgroundTasks
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer

# =========================
# ⚙️ INITIALIZATION
# =========================
load_dotenv()
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

templates = Jinja2Templates(directory="templates")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/admin/login")

# =========================
# 🔐 CONFIG
# =========================
DATABASE_URL = os.getenv("DATABASE_URL")
SECRET_KEY = os.getenv("SECRET_KEY") or "vantedgesecret777"
ALGORITHM = "HS256"

# Brevo Config
BREVO_API_KEY = os.getenv("BREVO_API_KEY")
SENDER_EMAIL = os.getenv("SENDER_EMAIL")

# =========================
# 🛠️ HELPERS & SECURITY
# =========================
def get_db():
    try:
        return psycopg2.connect(DATABASE_URL)
    except Exception as e:
        print("DB CONNECTION ERROR:", e)
        raise HTTPException(status_code=500, detail="Database connection failed")

def log_security_event(admin_id: int, target_id: Optional[int], action: str, details: str, ip: str):
    """System Audit Recorder: Writes to security_logs table."""
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO security_logs (admin_id, target_user_id, action_type, details, ip_address)
            VALUES (%s, %s, %s, %s, %s)
        """, (admin_id, target_id, action, details, ip))
        conn.commit()
    except Exception as e:
        print(f"AUDIT_LOG_ERROR: {e}")
    finally:
        cur.close(); conn.close()

def send_security_alert(to_email: str, username: str, ip_address: str):
    url = "https://api.brevo.com/v3/smtp/email"
    headers = {
        "accept": "application/json",
        "api-key": BREVO_API_KEY,
        "content-type": "application/json"
    }
    data = {
        "sender": {"name": "Vantedge Security", "email": SENDER_EMAIL},
        "to": [{"email": to_email}],
        "subject": "Security Alert: Unusual Login Detected 🛡️",
        "htmlContent": f"""
        <div style="background:#0a0a0a; color:white; padding:40px; font-family:sans-serif; border-radius:20px; border: 1px solid #00ffbb;">
            <h2 style="color:#00ffbb;">Unusual Login Activity</h2>
            <p>Hello {username}, a new login was detected from an unrecognized IP address.</p>
            <div style="background:rgba(255,255,255,0.05); padding:20px; border-radius:12px; margin: 20px 0;">
                <p style="margin:5px 0;"><b>User:</b> {username}</p>
                <p style="margin:5px 0;"><b>IP Address:</b> {ip_address}</p>
                <p style="margin:5px 0;"><b>Time:</b> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC</p>
            </div>
        </div>
        """
    }
    try:
        requests.post(url, json=data, headers=headers)
    except Exception as e:
        print(f"MAIL_ERROR: {e}")

def verify_password(plain_password, hashed_password):
    return bcrypt.checkpw(plain_password.encode(), hashed_password.encode())

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(hours=8)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_admin(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if str(payload.get("role")).upper() != "ADMIN":
            raise HTTPException(status_code=403, detail="Insufficient clearance.")
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Session expired.")

# =========================
# 🛡️ UI ROUTES
# =========================

@app.get("/")
async def login_page(request: Request):
    return templates.TemplateResponse(request=request, name="login.html")

@app.get("/admin")
async def admin_dashboard(request: Request):
    return templates.TemplateResponse(request=request, name="admin.html")

@app.get("/admin/security")
async def security_logs_page(request: Request):
    return templates.TemplateResponse(request=request, name="security_logs.html")

# =========================
# 🔑 AUTH API
# =========================

@app.post("/api/admin/login")
async def admin_login(request: Request, background_tasks: BackgroundTasks):
    data = await request.json()
    email, password = data.get("email"), data.get("password")
    
    x_forwarded = request.headers.get("X-Forwarded-For")
    client_ip = x_forwarded.split(",")[0] if x_forwarded else request.client.host

    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    
    try:
        cur.execute("SELECT id, username, email, password, user_type, failed_attempts, locked_until, login_ips FROM users WHERE email=%s", (email,))
        user = cur.fetchone()

        if not user:
            raise HTTPException(status_code=401, detail="Invalid credentials.")

        if user['locked_until'] and datetime.now() < user['locked_until']:
            raise HTTPException(status_code=403, detail="Account globally locked.")

        if not verify_password(password, user['password']):
            new_attempts = user['failed_attempts'] + 1
            cur.execute("UPDATE users SET failed_attempts=%s WHERE id=%s", (new_attempts, user['id']))
            conn.commit()
            raise HTTPException(status_code=401, detail=f"Attempt {new_attempts}/5.")

        if str(user['user_type']).upper() != "ADMIN":
            raise HTTPException(status_code=403, detail="Admin role required.")

        # IP Detection & Alert
        ip_history = user['login_ips'] or []
        if client_ip not in ip_history:
            background_tasks.add_task(send_security_alert, user['email'], user['username'], client_ip)

        cur.execute("""
            UPDATE users 
            SET failed_attempts = 0, locked_until = NULL, 
                login_ips = array_append(COALESCE(login_ips, '{}'), %s) 
            WHERE id = %s
        """, (client_ip, user['id']))
        conn.commit()

        token = create_access_token(data={"user_id": user['id'], "role": "ADMIN"})
        return {"access_token": token, "user_id": user['id']}
        
    finally:
        cur.close(); conn.close()

# =========================
# 🕵️ SECURITY AUDIT API
# =========================

@app.get("/api/admin/security-logs")
async def get_security_logs(admin_user=Depends(get_current_admin)):
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    try:
        cur.execute("""
            SELECT l.id, l.action_type, l.details, l.ip_address, l.created_at,
                   u1.username as admin_name, u2.username as target_name
            FROM security_logs l
            LEFT JOIN users u1 ON l.admin_id = u1.id
            LEFT JOIN users u2 ON l.target_user_id = u2.id
            ORDER BY l.created_at DESC LIMIT 100
        """)
        logs = cur.fetchall()
        return [{
            "id": l["id"],
            "admin_name": l["admin_name"] or "SYSTEM",
            "target_name": l["target_name"] or "GLOBAL",
            "action_type": l["action_type"],
            "details": l["details"],
            "ip_address": l["ip_address"],
            "created_at": l["created_at"].isoformat()
        } for l in logs]
    finally:
        cur.close(); conn.close()

# =========================
# 👥 USER MANAGEMENT API
# =========================

@app.get("/api/admin/users")
async def get_all_users(admin_user=Depends(get_current_admin)):
    conn = get_db(); cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    try:
        cur.execute("SELECT id, username, email, status, user_type, created_at, login_ips FROM users ORDER BY created_at DESC")
        users = cur.fetchall()
        return [{
            "id": u['id'], "username": u['username'], "email": u['email'],
            "status": u['status'] or "ACTIVE", "role": u['user_type'],
            "ip_history": u['login_ips'] or []
        } for u in users]
    finally:
        cur.close(); conn.close()

@app.post("/api/admin/toggle-status/{user_id}")
async def toggle_status(request: Request, user_id: int, admin_user=Depends(get_current_admin)):
    x_forwarded = request.headers.get("X-Forwarded-For")
    ip = x_forwarded.split(",")[0] if x_forwarded else request.client.host

    conn = get_db(); cur = conn.cursor()
    try:
        cur.execute("SELECT username, status FROM users WHERE id=%s", (user_id,))
        user = cur.fetchone()
        new_status = "DEACTIVATED" if user[1] == "ACTIVE" else "ACTIVE"
        
        cur.execute("UPDATE users SET status=%s WHERE id=%s", (new_status, user_id))
        conn.commit()

        log_security_event(admin_user['user_id'], user_id, f"STATUS_{new_status}", f"Set {user[0]} to {new_status}", ip)
        return {"new_status": new_status}
    finally:
        cur.close(); conn.close()

@app.post("/api/admin/change-role/{user_id}")
async def change_role(request: Request, user_id: int, data: dict = Body(...), admin_user=Depends(get_current_admin)):
    x_forwarded = request.headers.get("X-Forwarded-For")
    ip = x_forwarded.split(",")[0] if x_forwarded else request.client.host

    conn = get_db(); cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    try:
        cur.execute("SELECT password FROM users WHERE id=%s", (admin_user['user_id'],))
        admin_pass = cur.fetchone()[0]
        
        if not verify_password(data.get("password"), admin_pass):
            log_security_event(admin_user['user_id'], user_id, "AUTH_FAILURE", "Failed role change challenge", ip)
            raise HTTPException(status_code=401, detail="Invalid admin password.")

        new_role = data.get("new_role").upper()
        cur.execute("UPDATE users SET user_type=%s WHERE id=%s", (new_role, user_id))
        conn.commit()

        log_security_event(admin_user['user_id'], user_id, f"ROLE_{new_role}", f"Promoted target to {new_role}", ip)
        return {"message": "Success"}
    finally:
        cur.close(); conn.close()