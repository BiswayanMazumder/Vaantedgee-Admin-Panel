import os
import bcrypt
import psycopg2
import psycopg2.extras
from datetime import datetime, timedelta
from dotenv import load_dotenv
from jose import jwt, JWTError
from fastapi import FastAPI, Request, HTTPException, Depends, status, Body
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

# =========================
# 🛠️ HELPERS & SECURITY
# =========================
def get_db():
    try:
        return psycopg2.connect(DATABASE_URL)
    except Exception as e:
        print("DB ERROR:", e)
        raise HTTPException(status_code=500, detail="Database connection failed")

def verify_password(plain_password, hashed_password):
    return bcrypt.checkpw(plain_password.encode(), hashed_password.encode())

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(hours=8)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_admin(token: str = Depends(oauth2_scheme)):
    """Validates JWT and ensures the requester is an ADMIN."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        # Check role as uppercase for security consistency
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
# 🔑 AUTH API
# =========================

@app.post("/api/admin/login")
async def admin_login(request: Request):
    data = await request.json()
    email, password = data.get("email"), data.get("password")

    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    try:
        cur.execute("SELECT id, password, user_type FROM users WHERE email=%s", (email,))
        user = cur.fetchone()

        if not user or not verify_password(password, user['password']):
            raise HTTPException(status_code=401, detail="Invalid credentials.")

        # Case-insensitive check for Admin login
        if str(user['user_type']).upper() != "ADMIN":
            raise HTTPException(status_code=403, detail="ACCESS DENIED: Admin role required.")

        token = create_access_token(data={"user_id": user['id'], "role": "ADMIN"})
        return {"access_token": token, "user_id": user['id']}
    finally:
        cur.close(); conn.close()

# =========================
# 👥 USER MANAGEMENT API
# =========================

@app.get("/api/admin/users")
async def get_all_users(admin_user=Depends(get_current_admin)):
    """Fetches users including their Admin/User role status."""
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    try:
        cur.execute("SELECT id, username, email, status, user_type, created_at FROM users ORDER BY created_at DESC")
        users = cur.fetchall()
        return [{
            "id": u['id'],
            "username": u['username'],
            "email": u['email'],
            "status": u['status'] or "ACTIVE",
            # Normalize for UI while keeping value consistent
            "role": u['user_type'].capitalize() if u['user_type'] else "User", 
            "joined": u['created_at'].strftime("%Y-%m-%d") if u['created_at'] else "N/A"
        } for u in users]
    finally:
        cur.close(); conn.close()

@app.post("/api/admin/toggle-status/{user_id}")
async def toggle_user_status(user_id: int, admin_user=Depends(get_current_admin)):
    if int(user_id) == int(admin_user['user_id']):
        raise HTTPException(status_code=400, detail="Self-deactivation is restricted.")

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
    """High-privilege role shift with self-demotion protection."""
    admin_password = data.get("password")
    raw_role = data.get("new_role") 

    # ✨ Convert to Capitalized case (Admin / User) instead of ALL CAPS
    new_role = str(raw_role).capitalize()

    # 🛡️ SELF-DEMOTION BLOCK (CRITICAL)
    if int(user_id) == int(admin_user['user_id']):
        raise HTTPException(
            status_code=400, 
            detail="CRITICAL_ERROR: Self-demotion restricted."
        )

    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    try:
        # Re-verify password...
        cur.execute("SELECT password FROM users WHERE id=%s", (admin_user['user_id'],))
        admin_data = cur.fetchone()
        
        if not admin_data or not verify_password(admin_password, admin_data['password']):
            raise HTTPException(status_code=401, detail="Security challenge failed. Incorrect password.")

        # Update target user with the capitalized role
        cur.execute("UPDATE users SET user_type=%s WHERE id=%s", (new_role, user_id))
        conn.commit()
        return {"message": f"Clearance updated to {new_role}"}
    finally:
        cur.close(); conn.close()