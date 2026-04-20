import os
import logging
from datetime import datetime, timedelta
from enum import Enum
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, Enum as SqlEnum, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session

# --- ЛОГИРОВАНИЕ ---
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- КОНФИГУРАЦИЯ ---
SECRET_KEY = "SUPER_SECRET_KEY_FOR_PRACTICE"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 600

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user:password@db:5432/antisnow")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

# --- МОДЕЛИ БАЗЫ ДАННЫХ (SQLAlchemy) ---
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

# Автоматическое создание таблиц
Base.metadata.create_all(bind=engine)

# --- СХЕМЫ ДАННЫХ (Pydantic) ---
class Token(BaseModel):
    access_token: str
    token_type: str
    role: str

# --- ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ---
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_password_hash(password):
    # Принудительно превращаем в string и берем первые 72 байта
    pwd_str = str(password)[:71] 
    return pwd_context.hash(pwd_str)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# --- ИНИЦИАЛИЗАЦИЯ APP ---
app = FastAPI(root_path="/api")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- ЭНДПОИНТЫ ---

@app.post("/auth/register")
def register(email: str, password: str, role: UserRole = UserRole.USER, db: Session = Depends(get_db)):
    try:
        # Логируем, что пришло (увидим в docker logs)
        logger.info(f"Registering email: {email}, password_len: {len(password)}")
        
        db_user = db.query(User).filter(User.email == email).first()
        if db_user:
            raise HTTPException(status_code=400, detail="Email already registered")
        
        # Используем нашу обновленную функцию
        new_user = User(
            email=email, 
            hashed_password=get_password_hash(password),
            role=role
        )
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        return {"status": "success", "message": f"User {email} created"}
    except Exception as e:
        db.rollback()
        logger.error(f"REGISTER ERROR: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

@app.post("/auth/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    
    access_token = create_access_token(data={"sub": user.email, "role": user.role.value})
    return {
        "access_token": access_token, 
        "token_type": "bearer", 
        "role": user.role.value
    }

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