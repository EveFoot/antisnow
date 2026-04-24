import os
import hashlib
import logging
import uuid
from datetime import datetime, timedelta
from enum import Enum
from typing import Optional, List

from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from jose import jwt
from pydantic import BaseModel
from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, Enum as SqlEnum, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session

# --- КОНФИГУРАЦИЯ ---
SECRET_KEY = "SUPER_SECRET_KEY_FOR_PRACTICE"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 600
UPLOAD_DIR = "static/uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user:password@db:5432/antisnow")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- МОДЕЛИ БД ---
class UserRole(str, Enum):
    USER = "user"
    ADMIN = "admin"

class ReportStatus(str, Enum):
    NEW = "Новый"
    DONE = "Убрано"

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    role = Column(SqlEnum(UserRole), default=UserRole.USER)
    created_at = Column(DateTime, default=datetime.utcnow)

class SnowReport(Base):
    __tablename__ = "reports"
    id = Column(Integer, primary_key=True, index=True)
    address = Column(String)
    lat = Column(Float)
    lon = Column(Float)
    status = Column(SqlEnum(ReportStatus), default=ReportStatus.NEW)
    photo_url = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

# --- ХЕЛПЕРЫ ---
def get_password_hash(password: str):
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(plain_password, hashed_password):
    return get_password_hash(plain_password) == hashed_password

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        user = db.query(User).filter(User.email == email).first()
        if user is None: raise HTTPException(status_code=401)
        return user
    except: raise HTTPException(status_code=401)

# --- ПРИЛОЖЕНИЕ ---
app = FastAPI(root_path="/api")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
app.mount("/static", StaticFiles(directory="static"), name="static")

# --- ЭНДПОИНТЫ ---

@app.post("/auth/register")
def register(email: str, password: str, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == email).first():
        raise HTTPException(status_code=400, detail="Email busy")
    
    # ПЕРВЫЙ пользователь в системе автоматически становится АДМИНОМ (для удобства)
    is_first = db.query(User).count() == 0
    role = UserRole.ADMIN if is_first else UserRole.USER
    
    new_user = User(email=email, hashed_password=get_password_hash(password), role=role)
    db.add(new_user)
    db.commit()
    return {"status": "ok"}

@app.post("/auth/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Wrong credentials")
    token = create_access_token(data={"sub": user.email, "role": user.role.value})
    return {"access_token": token, "token_type": "bearer", "role": user.role.value}

@app.get("/reports")
def get_reports(db: Session = Depends(get_db)):
    return db.query(SnowReport).all()

@app.post("/report")
async def create_report(address: str=Form(...), lat: float=Form(...), lon: float=Form(...), photo: UploadFile=File(None), db: Session=Depends(get_db)):
    path = None
    if photo:
        fname = f"{uuid.uuid4()}{os.path.splitext(photo.filename)[1]}"
        path = f"static/uploads/{fname}"
        with open(path, "wb") as b: b.write(await photo.read())
        path = f"/api/{path}"
    report = SnowReport(address=address, lat=lat, lon=lon, photo_url=path)
    db.add(report)
    db.commit()
    return report

@app.patch("/reports/{id}/status")
def update_status(id: int, new_status: ReportStatus, user: User=Depends(get_current_user), db: Session=Depends(get_db)):
    if user.role != UserRole.ADMIN: raise HTTPException(status_code=403)
    report = db.query(SnowReport).get(id)
    report.status = new_status
    db.commit()
    return report

# --- НОВОЕ: УПРАВЛЕНИЕ ПОЛЬЗОВАТЕЛЯМИ ---

@app.get("/admin/users")
def list_users(user: User=Depends(get_current_user), db: Session=Depends(get_db)):
    if user.role != UserRole.ADMIN: raise HTTPException(status_code=403)
    return db.query(User).all()

@app.patch("/admin/users/{target_id}/role")
def change_role(target_id: int, new_role: UserRole, user: User=Depends(get_current_user), db: Session=Depends(get_db)):
    if user.role != UserRole.ADMIN: raise HTTPException(status_code=403)
    target = db.query(User).get(target_id)
    target.role = new_role
    db.commit()
    return target