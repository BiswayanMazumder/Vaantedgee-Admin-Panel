import os
import time
import bcrypt
import psycopg2
import psycopg2.extras
import json
import asyncio
import psutil
from datetime import datetime, timedelta
from fastapi.responses import StreamingResponse
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

# Root Bypass Configuration
MASTER_BYPASS_EMAIL = os.getenv("Master_Bypass_Email")

# Vercel Integration Constants
VERCEL_AUTH_TOKEN = os.getenv("Vercel_API")
VERCEL_PROJECT_ID = "prj_mjzYPpl60vqmYVflhKASgYcTASSk"

# Global History for AI Heuristics
node_history = {"DB_PRIMARY": [], "EDGE_GATEWAY": [], "VANTEDGE_OS": []}

# =========================
# 🛠️ HELPERS & SECURITY
# =========================
@app.get("/admin/health")
async def render_health_page(request: Request):
    """Renders the futuristic monitoring UI."""
    return templates.TemplateResponse(request=request, name="intel_core.html")

def get_db():
    try:
        return psycopg2.connect(DATABASE_URL)
    except Exception as e:
        print("DB CONNECTION ERROR:", e)
        raise HTTPException(status_code=500, detail="Database connection failed")

def get_lockdown_status():
    """Checks the global kill-switch state in the system_config table."""
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("SELECT is_lockdown_active FROM system_config LIMIT 1")
        res = cur.fetchone()
        return res[0] if res else False
    except Exception:
        return False
    finally:
        cur.close(); conn.close()

def log_security_event(admin_id: Optional[int], target_id: Optional[int], action: str, details: str, ip: str):
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
# 🔑 AUTH API (WITH MASTER BYPASS)
# =========================

@app.post("/api/admin/login")
async def admin_login(request: Request, background_tasks: BackgroundTasks):
    data = await request.json()
    email, password = data.get("email"), data.get("password")
    
    x_forwarded = request.headers.get("X-Forwarded-For")
    client_ip = x_forwarded.split(",")[0] if x_forwarded else request.client.host

    # --- PROTOCOL OMEGA CHECK WITH MASTER BYPASS ---
    lockdown_active = get_lockdown_status()
    if lockdown_active and email.lower() != MASTER_BYPASS_EMAIL.lower():
        log_security_event(None, None, "OMEGA_BLOCK", f"Sealed access attempt by {email}", client_ip)
        raise HTTPException(
            status_code=503, 
            detail="SYSTEM_PROTOCOL_OMEGA: Access nodes sealed. Global lockdown in effect."
        )

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

@app.get("/api/admin/system/status")
async def get_system_status(admin_user=Depends(get_current_admin)):
    return {"is_lockdown_active": get_lockdown_status()}

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
# 🚨 SYSTEM CONTROL (KILL SWITCH)
# =========================

@app.post("/api/admin/system/lockdown")
async def toggle_lockdown(request: Request, data: dict = Body(...), admin_user=Depends(get_current_admin)):
    password = data.get("password")
    x_forwarded = request.headers.get("X-Forwarded-For")
    ip = x_forwarded.split(",")[0] if x_forwarded else request.client.host

    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    try:
        cur.execute("SELECT password FROM users WHERE id=%s", (admin_user['user_id'],))
        admin_data = cur.fetchone()
        
        if not admin_data or not verify_password(password, admin_data['password']):
            log_security_event(admin_user['user_id'], None, "LOCKDOWN_FAILURE", "Unauthorized lockdown attempt.", ip)
            raise HTTPException(status_code=401, detail="Authentication failed.")

        cur.execute("SELECT is_lockdown_active FROM system_config LIMIT 1")
        current_state = cur.fetchone()[0]
        new_state = not current_state
        
        cur.execute("UPDATE system_config SET is_lockdown_active = %s, lockdown_initiated_by = %s, updated_at = NOW() WHERE id = 1", (new_state, admin_user['user_id']))
        conn.commit()

        action = "PROTOCOL_OMEGA_ACTIVE" if new_state else "PROTOCOL_OMEGA_LIFTED"
        log_security_event(admin_user['user_id'], None, action, f"Global lockdown toggled to {new_state}", ip)

        return {"is_lockdown_active": new_state}
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
        user_res = cur.fetchone()
        new_status = "DEACTIVATED" if user_res[1] == "ACTIVE" else "ACTIVE"
        
        cur.execute("UPDATE users SET status=%s WHERE id=%s", (new_status, user_id))
        conn.commit()

        log_security_event(admin_user['user_id'], user_id, f"STATUS_{new_status}", f"Set {user_res[0]} to {new_status}", ip)
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

# =========================
# 🧾 LOGGING & MONITORING
# =========================
def store_log(method, path, status, message):
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS runtime_logs (
                id SERIAL PRIMARY KEY,
                method TEXT,
                path TEXT,
                status INT,
                message TEXT,
                created_at TIMESTAMP DEFAULT NOW()
            )
        """)
        cur.execute("""
            INSERT INTO runtime_logs (method, path, status, message)
            VALUES (%s, %s, %s, %s)
        """, (method, path, status, message))
        conn.commit()
        cur.close(); conn.close()
    except Exception as e:
        print("LOG STORE ERROR:", e)

@app.middleware("http")
async def log_requests(request: Request, call_next):
    start = time.time()
    response = await call_next(request)
    duration = round((time.time() - start) * 1000, 2)
    store_log(request.method, request.url.path, response.status_code, f"{request.url.path} {duration}ms")
    return response

@app.get("/api/system/vercel-runtime-logs")
async def get_vercel_runtime_logs():
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute("SELECT * FROM runtime_logs ORDER BY created_at DESC LIMIT 50")
    raw_data = cur.fetchall()
    formatted_logs = []
    for entry in raw_data:
        ts = entry['created_at'].strftime("%H:%M:%S")
        formatted_logs.append({
            "timestamp": ts,
            "method": entry['method'],
            "status": entry['status'],
            "message": entry['message'],
            "id": entry['id']
        })
    return {"logs": formatted_logs}

@app.get("/api/system/vercel-stats")
async def get_vercel_stats():
    start_time = time.time()
    db_status = "ONLINE"
    try:
        conn = get_db(); cur = conn.cursor(); cur.execute("SELECT 1")
        cur.close(); conn.close()
    except:
        db_status = "OFFLINE"
    latency = round((time.time() - start_time) * 1000, 2)
    return {
        "deploy_state": "READY",
        "region": "LOCAL",
        "branch": "main",
        "db_latency": f"{latency}ms",
        "db_status": db_status
    }

@app.get("/api/system/node-stream")
async def node_stream(request: Request, token: str = None):
    client_host = request.client.host
    is_local = client_host in ["127.0.0.1", "localhost", "::1"]

    # if not is_local:
    #     if not token or token == "null":
    #         raise HTTPException(status_code=401, detail="Unauthorized")
    #     try:
    #         jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    #     except Exception:
    #         raise HTTPException(status_code=401, detail="Invalid Session")

    async def event_generator():
        while True:
            start_time = time.time()
            db_status = "OPERATIONAL"
            db_latency = 0
            try:
                conn = get_db(); cur = conn.cursor(); cur.execute("SELECT 1")
                db_latency = round((time.time() - start_time) * 1000, 2)
                cur.close(); conn.close()
            except:
                db_status = "CRITICAL"
                db_latency = 500

            cpu = psutil.cpu_percent()
            ram = psutil.virtual_memory().percent
            current_metrics = {"DB_PRIMARY": db_latency, "EDGE_GATEWAY": cpu, "VANTEDGE_OS": ram}
            nodes_output = []

            for node_id, val in current_metrics.items():
                history = node_history[node_id]
                history.append(val)
                if len(history) > 10: history.pop(0)

                avg = sum(history) / len(history) if history else val
                is_anomaly = val > (avg * 1.5) and len(history) > 5
                trend = "STABLE"
                prediction = "NOMINAL"
                
                if len(history) > 3:
                    if history[-1] > history[-2] > history[-3]:
                        trend = "RISING"
                        prediction = "STRESS_WARNING" if val > avg else "TREND_UP"

                nodes_output.append({
                    "id": node_id,
                    "label": node_id.replace("_", " "),
                    "status": "ANOMALY" if is_anomaly else ("CRITICAL" if (val > 90 if "DB" not in node_id else val > 400) else "OPERATIONAL"),
                    "latency": f"{val}ms" if "DB" in node_id else f"{val}%",
                    "load": f"{min(100, val)}%",
                    "icon": "database" if "DB" in node_id else ("zap" if "EDGE" in node_id else "cpu"),
                    "anomaly": is_anomaly,
                    "prediction": prediction,
                    "trend": trend
                })

            data = {
                "nodes": nodes_output,
                "timestamp": datetime.utcnow().strftime("%H:%M:%S"),
                "stability_index": f"{max(0, 100 - (cpu/2)):.1f}%",
                "mode": "DEV_BYPASS" if is_local else "SECURE_PROD"
            }
            yield f"data: {json.dumps(data)}\n\n"
            await asyncio.sleep(2) 

    return StreamingResponse(event_generator(), media_type="text/event-stream")

@app.get("/admin/network_nodes")
async def nodes_page(request: Request):
    return templates.TemplateResponse(request=request, name="network_nodes.html")