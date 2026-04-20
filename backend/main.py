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

# Папка для хранения фото
UPLOAD_DIR = "static/uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user:password@db:5432/antisnow")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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
    photo_url = Column(String, nullable=True) # Путь к фото
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

# Создаем таблицы
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

# Защита эндпоинтов (нужна роль админа для смены статуса)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(status_code=401, detail="Could not validate credentials")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None: raise credentials_exception
    except Exception: raise credentials_exception
    
    user = db.query(User).filter(User.email == email).first()
    if user is None: raise credentials_exception
    return user

# --- ПРИЛОЖЕНИЕ ---
app = FastAPI(root_path="/api")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# Раздаем статику (фото)
app.mount("/static", StaticFiles(directory="static"), name="static")

# --- СХЕМЫ ОТВЕТОВ ---
class UserOut(BaseModel):
    id: int
    email: str
    role: UserRole
    class Config: from_attributes = True

class ReportOut(BaseModel):
    id: int
    address: str
    lat: float
    lon: float
    status: ReportStatus
    photo_url: Optional[str]
    class Config: from_attributes = True

# --- ЭНДПОИНТЫ ---

@app.post("/auth/register", response_model=UserOut)
def register(email: str, password: str, role: UserRole = UserRole.USER, db: Session = Depends(get_db)):
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
    db.refresh(new_user)
    return new_user

@app.post("/auth/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Wrong email or password")
    
    token = create_access_token(data={"sub": user.email, "role": user.role.value})
    return {"access_token": token, "token_type": "bearer", "role": user.role.value}

@app.get("/reports", response_model=List[ReportOut])
def get_reports(db: Session = Depends(get_db)):
    return db.query(SnowReport).all()

# Создание заявки (теперь с ФОТО и Form)
@app.post("/report", response_model=ReportOut)
async def create_report(
    address: str = Form(...),
    lat: float = Form(...),
    lon: float = Form(...),
    photo: Optional[UploadFile] = File(None),
    db: Session = Depends(get_db)
):
    final_photo_path = None
    
    # Сохраняем фото, если оно есть
    if photo:
        file_extension = os.path.splitext(photo.filename)[1]
        unique_filename = f"{uuid.uuid4()}{file_extension}"
        final_photo_path = f"{UPLOAD_DIR}/{unique_filename}"
        
        with open(final_photo_path, "wb") as buffer:
            content = await photo.read()
            buffer.write(content)
        
        # Ссылка, которую будет использовать фронтенд
        final_photo_path = f"/api/static/uploads/{unique_filename}"

    new_report = SnowReport(
        address=address, 
        lat=lat, 
        lon=lon,
        photo_url=final_photo_path
    )
    db.add(new_report)
    db.commit()
    db.refresh(new_report)
    return new_report

# PATCH: Смена статуса (Только для АДМИНА)
@app.patch("/reports/{report_id}/status", response_model=ReportOut)
def update_report_status(
    report_id: int,
    new_status: ReportStatus,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Only admins can change status")
    
    report = db.query(SnowReport).filter(SnowReport.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    report.status = new_status
    db.commit()
    db.refresh(report)
    return report