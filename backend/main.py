import os, hashlib, uuid
from datetime import datetime
from enum import Enum
from fastapi import FastAPI, Depends, HTTPException, Query, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from fastapi.staticfiles import StaticFiles
from sqlalchemy import Column, Integer, String, Float, Enum as SqlEnum, DateTime, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from jose import jwt

# Настройка путей и БД
UPLOAD_DIR = "/app/uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user_admin:password@db:5432/antisnow_db")
SECRET_KEY = "SECRET_SECRET_123" 
ALGORITHM = "HS256"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

class UserRole(str, Enum):
    user = "user"
    cleaner = "cleaner"
    admin = "admin"

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    role = Column(SqlEnum(UserRole), default=UserRole.user)

class SnowReport(Base):
    __tablename__ = "reports"
    id = Column(Integer, primary_key=True, index=True)
    lat = Column(Float); lon = Column(Float)
    snow_type = Column(String)
    status = Column(String, default="pending") 
    photo_url = Column(String, nullable=True)
    done_photo_url = Column(String, nullable=True)
    author_email = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# Раздача статики (фото)
app.mount("/static_uploads", StaticFiles(directory=UPLOAD_DIR), name="static_uploads")

def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        user = db.query(User).filter(User.email == email).first()
        if user is None: raise HTTPException(status_code=401)
        return user
    except: raise HTTPException(status_code=401)

# API: Метки
@app.get("/api/reports")
def get_reports(db: Session = Depends(get_db)):
    return db.query(SnowReport).order_by(SnowReport.created_at.desc()).all()

@app.post("/api/reports")
async def create_report(lat: float=Form(...), lon: float=Form(...), snow_type: str=Form(...), file: UploadFile=File(None), db: Session=Depends(get_db), u: User=Depends(get_current_user)):
    p_url = None
    if file:
        fname = f"{uuid.uuid4().hex}.jpg"
        with open(os.path.join(UPLOAD_DIR, fname), "wb") as buf:
            buf.write(await file.read())
        p_url = f"/static_uploads/{fname}"
    
    new_rep = SnowReport(lat=lat, lon=lon, snow_type=snow_type, photo_url=p_url, author_email=u.email)
    db.add(new_rep); db.commit(); return {"ok": True}

@app.post("/api/reports/{r_id}/done")
async def mark_done(r_id: int, file: UploadFile=File(None), db: Session=Depends(get_db), u: User=Depends(get_current_user)):
    rep = db.query(SnowReport).filter(SnowReport.id == r_id).first()
    if file:
        fname = f"done_{uuid.uuid4().hex}.jpg"
        with open(os.path.join(UPLOAD_DIR, fname), "wb") as buf:
            buf.write(await file.read())
        rep.done_photo_url = f"/static_uploads/{fname}"
    rep.status = "cleaned"
    rep.updated_at = datetime.utcnow()
    db.commit(); return {"ok": True}

@app.delete("/api/reports/{r_id}")
def delete_report(r_id: int, db: Session=Depends(get_db), u: User=Depends(get_current_user)):
    if u.role != UserRole.admin: raise HTTPException(403)
    db.query(SnowReport).filter(SnowReport.id == r_id).delete()
    db.commit(); return {"ok": True}

# API: Пользователи и Админка
@app.post("/api/auth/register")
def register(email:str=Query(...), password:str=Query(...), db:Session=Depends(get_db)):
    is_first = db.query(User).count() == 0
    role = UserRole.admin if is_first else UserRole.user
    hashed = hashlib.sha256(password.encode()).hexdigest()
    db.add(User(email=email, hashed_password=hashed, role=role))
    db.commit(); return {"ok": True}

@app.post("/api/auth/login")
def login(form: OAuth2PasswordRequestForm=Depends(), db: Session=Depends(get_db)):
    u = db.query(User).filter(User.email == form.username).first()
    hp = hashlib.sha256(form.password.encode()).hexdigest()
    if not u or u.hashed_password != hp: raise HTTPException(401)
    token = jwt.encode({"sub": u.email, "role": u.role.value}, SECRET_KEY, ALGORITHM)
    return {"access_token": token, "token_type": "bearer", "role": u.role.value, "email": u.email}

@app.get("/api/admin/users")
def list_users(db: Session=Depends(get_db), u: User=Depends(get_current_user)):
    if u.role != UserRole.admin: raise HTTPException(403)
    return db.query(User).all()

@app.put("/api/admin/users/{u_id}/role")
def change_role(u_id: int, data: dict, db: Session=Depends(get_db), u: User=Depends(get_current_user)):
    if u.role != UserRole.admin: raise HTTPException(403)
    db.query(User).filter(User.id == u_id).update({"role": data['role']})
    db.commit(); return {"ok": True}