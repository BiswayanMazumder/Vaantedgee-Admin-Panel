import os
import bcrypt
import psycopg2
import psycopg2.extras
import requests
from datetime import datetime, timedelta
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

def send_security_alert(to_email: str, username: str, ip_address: str):
    """Triggers Brevo REST API for Unusual Login detection."""
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
            <p style="color:#666; font-size:12px; margin-top:20px;">
                If this was not you, please secure your account or contact support immediately.
            </p>
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
        raise HTTPException(status_code=401, detail="Session expired. Re-authenticate.")

# =========================
# 🛡️ UI ROUTES
# =========================

@app.get("/")
async def login_page(request: Request):
    return templates.TemplateResponse(request=request, name="login.html")

@app.get("/admin")
async def admin_dashboard(request: Request):
    return templates.TemplateResponse(request=request, name="admin.html")

# =========================
# 🔑 AUTH API (WITH GLOBAL LOCKOUT & BREVO ALERTS)
# =========================

@app.post("/api/admin/login")
async def admin_login(request: Request, background_tasks: BackgroundTasks):
    try:
        data = await request.json()
        email, password = data.get("email"), data.get("password")
        
        # Capture IP (Handles proxies)
        x_forwarded = request.headers.get("X-Forwarded-For")
        client_ip = x_forwarded.split(",")[0] if x_forwarded else request.client.host

        conn = get_db()
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        
        try:
            # 1. Fetch user data including lockout state and IP history
            cur.execute("SELECT id, username, email, password, user_type, failed_attempts, locked_until, login_ips FROM users WHERE email=%s", (email,))
            user = cur.fetchone()

            if not user:
                raise HTTPException(status_code=401, detail="Invalid credentials.")

            # 2. Global Lock Check
            if user['locked_until'] and datetime.now() < user['locked_until']:
                remaining_time = (user['locked_until'] - datetime.now()).total_seconds() / 60
                raise HTTPException(
                    status_code=403, 
                    detail=f"SECURITY_ALERT: Account globally locked. Retry in {int(remaining_time)} minutes."
                )

            # 3. Verify Password
            if not verify_password(password, user['password']):
                new_attempts = user['failed_attempts'] + 1
                if new_attempts >= 5:
                    lock_time = datetime.now() + timedelta(minutes=15)
                    cur.execute("UPDATE users SET failed_attempts=%s, locked_until=%s WHERE id=%s", (new_attempts, lock_time, user['id']))
                else:
                    cur.execute("UPDATE users SET failed_attempts=%s WHERE id=%s", (new_attempts, user['id']))
                conn.commit()
                raise HTTPException(status_code=401, detail=f"Invalid credentials. Attempt {new_attempts}/5.")

            # 4. Check Admin Clearance
            if str(user['user_type']).upper() != "ADMIN":
                raise HTTPException(status_code=403, detail="ACCESS DENIED: Admin role required.")

            # 5. UNUSUAL IP DETECTION
            ip_history = user['login_ips'] if user['login_ips'] else []
            if client_ip not in ip_history:
                # Dispatch alert in background task to not slow down login response
                background_tasks.add_task(send_security_alert, user['email'], user['username'], client_ip)

            # 6. Success - Reset Lockout state and append current IP to array
            cur.execute("""
                UPDATE users 
                SET failed_attempts = 0, 
                    locked_until = NULL, 
                    login_ips = array_append(COALESCE(login_ips, '{}'), %s) 
                WHERE id = %s
            """, (client_ip, user['id']))
            conn.commit()

            token = create_access_token(data={"user_id": user['id'], "role": "ADMIN"})
            return {"access_token": token, "user_id": user['id']}
            
        finally:
            cur.close()
            conn.close()

    except HTTPException as e:
        raise e
    except Exception as e:
        print(f"CRITICAL LOGIN ERROR: {str(e)}")
        raise HTTPException(status_code=500, detail="Mainframe update failed.")

# =========================
# 👥 USER MANAGEMENT API
# =========================

@app.get("/api/admin/users")
async def get_all_users(admin_user=Depends(get_current_admin)):
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    try:
        cur.execute("SELECT id, username, email, status, user_type, created_at, login_ips FROM users ORDER BY created_at DESC")
        users = cur.fetchall()
        return [{
            "id": u['id'],
            "username": u['username'],
            "email": u['email'],
            "status": u['status'] or "ACTIVE",
            "role": u['user_type'].capitalize() if u['user_type'] else "User", 
            "joined": u['created_at'].strftime("%Y-%m-%d") if u['created_at'] else "N/A",
            "ip_history": u['login_ips'] if u['login_ips'] else [] 
        } for u in users]
    finally:
        cur.close(); conn.close()

@app.post("/api/admin/toggle-status/{user_id}")
async def toggle_user_status(user_id: int, admin_user=Depends(get_current_admin)):
    if int(user_id) == int(admin_user['user_id']):
        raise HTTPException(status_code=400, detail="Self-deactivation restricted.")

    conn = get_db(); cur = conn.cursor()
    try:
        cur.execute("SELECT status FROM users WHERE id=%s", (user_id,))
        res = cur.fetchone()
        new_status = "DEACTIVATED" if res[0] == "ACTIVE" else "ACTIVE"
        cur.execute("UPDATE users SET status=%s WHERE id=%s", (new_status, user_id))
        conn.commit()
        return {"new_status": new_status}
    finally:
        cur.close(); conn.close()

@app.post("/api/admin/change-role/{user_id}")
async def change_user_role(user_id: int, data: dict = Body(...), admin_user=Depends(get_current_admin)):
    admin_password = data.get("password")
    new_role = str(data.get("new_role")).capitalize()

    if int(user_id) == int(admin_user['user_id']):
        raise HTTPException(status_code=400, detail="Self-demotion restricted.")

    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    try:
        cur.execute("SELECT password FROM users WHERE id=%s", (admin_user['user_id'],))
        admin_data = cur.fetchone()
        
        if not admin_data or not verify_password(admin_password, admin_data['password']):
            raise HTTPException(status_code=401, detail="Security challenge failed.")

        cur.execute("UPDATE users SET user_type=%s WHERE id=%s", (new_role, user_id))
        conn.commit()
        return {"message": f"Clearance updated to {new_role}"}
    finally:
        cur.close(); conn.close()