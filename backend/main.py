import os
import hashlib
import logging
from datetime import datetime, timedelta
from enum import Enum

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt
from pydantic import BaseModel
from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, Enum as SqlEnum, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session

# --- НАСТРОЙКИ ---
SECRET_KEY = "SUPER_SECRET_KEY_FOR_PRACTICE"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 600

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user:password@db:5432/antisnow")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- МОДЕЛИ БД ---
class UserRole(str, Enum):
    USER = "user"
    CLEANER = "cleaner"
    ADMIN = "admin"

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
    status = Column(String, default="Новый")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    creator_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    cleaner_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    cleaner_note = Column(String, nullable=True)

Base.metadata.create_all(bind=engine)

# --- ХЕЛПЕРЫ (БЕЗ BCRYPT) ---
def get_password_hash(password: str):
    # Используем SHA-256 — это просто, надежно и не ломается
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

# --- ПРИЛОЖЕНИЕ ---
app = FastAPI(root_path="/api")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

@app.post("/auth/register")
def register(email: str, password: str, role: UserRole = UserRole.USER, db: Session = Depends(get_db)):
    try:
        db_user = db.query(User).filter(User.email == email).first()
        if db_user:
            raise HTTPException(status_code=400, detail="Email busy")
        
        new_user = User(
            email=email, 
            hashed_password=get_password_hash(password),
            role=role
        )
        db.add(new_user)
        db.commit()
        return {"status": "success", "message": f"User {email} created"}
    except Exception as e:
        db.rollback()
        logger.error(f"Error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/auth/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Wrong email or password")
    
    token = create_access_token(data={"sub": user.email, "role": user.role.value})
    return {"access_token": token, "token_type": "bearer", "role": user.role.value}

@app.get("/reports")
def get_reports(db: Session = Depends(get_db)):
    return db.query(SnowReport).all()

@app.post("/report")
def create_report(address: str, lat: float, lon: float, db: Session = Depends(get_db)):
    new_report = SnowReport(address=address, lat=lat, lon=lon)
    db.add(new_report)
    db.commit()
    db.refresh(new_report)
    return new_report