import os
import uuid
from datetime import datetime
from enum import Enum
from typing import List, Optional

from fastapi import FastAPI, Depends, HTTPException, status, File, UploadFile, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, ForeignKey, Enum as SQLEnum
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship

from passlib.context import CryptContext
from jose import JWTError, jwt

# --- НАСТРОЙКИ ---
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./antisnow.db")
SECRET_KEY = os.getenv("SECRET_KEY", "super-secret-key-change-me")
ALGORITHM = "HS256"

# Создание папки для загрузки фото
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# --- БАЗА ДАННЫХ ---
engine = create_engine(
    DATABASE_URL, 
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- МОДЕЛИ ДАННЫХ ---
class UserRole(str, Enum):
    user = "user"
    cleaner = "cleaner"
    admin = "admin"

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(SQLEnum(UserRole), default=UserRole.user, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    reports = relationship("SnowReport", back_populates="author")

class SnowReport(Base):
    __tablename__ = "snow_reports"

    id = Column(Integer, primary_key=True, index=True)
    lat = Column(Float, nullable=False)
    lon = Column(Float, nullable=False)
    snow_type = Column(String, nullable=False)
    description = Column(String, nullable=True)
    photo_url = Column(String, nullable=True)
    done_photo_url = Column(String, nullable=True)
    status = Column(String, default="pending")  # pending, cleaned, verified
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user_id = Column(Integer, ForeignKey("users.id"))
    author = relationship("User", back_populates="reports")

Base.metadata.create_all(bind=engine)

# --- АВТОРИЗАЦИЯ И ХЕШИРОВАНИЕ ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict):
    to_encode = data.copy()
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# --- FASTAPI APP ---
app = FastAPI(title="AntiSnow API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/uploads", StaticFiles(directory=UPLOAD_DIR), name="uploads")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Неверный токен авторизации",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db.query(User).filter(User.email == email).first()
    if user is None:
        raise credentials_exception
    return user

# --- ЭНДПОИНТЫ АВТОРИЗАЦИИ ---

@app.post("/api/auth/register")
def register(email: str, password: str, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email уже зарегистрирован")
    
    is_first = db.query(User).count() == 0
    role = UserRole.admin if is_first else UserRole.user

    new_user = User(
        email=email,
        hashed_password=get_password_hash(password),
        role=role
    )
    db.add(new_user)
    db.commit()
    return {"ok": True, "message": "Пользователь успешно зарегистрирован"}

@app.post("/api/auth/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Неверный email или пароль")
    
    token = create_access_token(data={"sub": user.email})
    return {
        "access_token": token, 
        "token_type": "bearer", 
        "role": user.role.value, 
        "email": user.email
    }

# --- ЭНДПОИНТЫ ОТЧЕТОВ ---

@app.get("/api/reports")
def get_reports(db: Session = Depends(get_db)):
    reports = db.query(SnowReport).all()
    return [
        {
            "id": r.id,
            "lat": r.lat,
            "lon": r.lon,
            "snow_type": r.snow_type,
            "description": r.description,
            "photo_url": r.photo_url,
            "done_photo_url": r.done_photo_url,
            "status": r.status,
            "created_at": r.created_at.isoformat() if r.created_at else None
        }
        for r in reports
    ]

@app.post("/api/reports")
async def create_report(
    lat: float = Form(...),
    lon: float = Form(...),
    snow_type: str = Form(...),
    description: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None),
    db: Session = Depends(get_db),
    u: User = Depends(get_current_user)
):
    photo_url = None
    if file:
        ext = file.filename.split(".")[-1] if "." in file.filename else "jpg"
        fname = f"{uuid.uuid4().hex}.{ext}"
        fpath = os.path.join(UPLOAD_DIR, fname)
        with open(fpath, "wb") as f:
            f.write(await file.read())
        photo_url = f"/uploads/{fname}"

    rep = SnowReport(
        lat=lat,
        lon=lon,
        snow_type=snow_type,
        description=description,
        photo_url=photo_url,
        user_id=u.id
    )
    db.add(rep)
    db.commit()
    return {"ok": True}

@app.patch("/api/reports/{r_id}/status")
def update_report_status(
    r_id: int, 
    status: str, 
    db: Session = Depends(get_db), 
    u: User = Depends(get_current_user)
):
    if not u or u.role not in [UserRole.admin, UserRole.cleaner]:
        raise HTTPException(status_code=403, detail="Недостаточно прав")
    
    rep = db.query(SnowReport).filter(SnowReport.id == r_id).first()
    if not rep:
        raise HTTPException(status_code=404, detail="Отчет не найден")
        
    rep.status = status
    rep.updated_at = datetime.utcnow()
    db.commit()
    return {"ok": True, "status": rep.status}

@app.post("/api/reports/{r_id}/done")
async def report_done(
    r_id: int, 
    file: UploadFile = File(...), 
    db: Session = Depends(get_db), 
    u: User = Depends(get_current_user)
):
    if u.role not in [UserRole.cleaner, UserRole.admin]:
        raise HTTPException(status_code=403, detail="Недостаточно прав")
        
    rep = db.query(SnowReport).filter(SnowReport.id == r_id).first()
    if not rep:
        raise HTTPException(status_code=404, detail="Отчет не найден")

    ext = file.filename.split(".")[-1] if "." in file.filename else "jpg"
    fname = f"done_{uuid.uuid4().hex}.{ext}"
    fpath = os.path.join(UPLOAD_DIR, fname)
    with open(fpath, "wb") as f:
        f.write(await file.read())

    rep.done_photo_url = f"/uploads/{fname}"
    rep.status = "cleaned"
    rep.updated_at = datetime.utcnow()
    db.commit()
    return {"ok": True}

@app.delete("/api/reports/{r_id}")
def delete_report(
    r_id: int, 
    db: Session = Depends(get_db), 
    u: User = Depends(get_current_user)
):
    if u.role != UserRole.admin:
        raise HTTPException(status_code=403, detail="Требуются права администратора")
    
    rep = db.query(SnowReport).filter(SnowReport.id == r_id).first()
    if not rep:
        raise HTTPException(status_code=404, detail="Отчет не найден")

    db.delete(rep)
    db.commit()
    return {"ok": True}

# --- АДМИН-ПАНЕЛЬ ---

@app.get("/api/admin/users")
def get_users(db: Session = Depends(get_db), u: User = Depends(get_current_user)):
    if u.role != UserRole.admin:
        raise HTTPException(status_code=403, detail="Требуются права администратора")
    users = db.query(User).all()
    return [{"id": usr.id, "email": usr.email, "role": usr.role.value} for usr in users]

@app.patch("/api/admin/users/{u_id}/role")
def update_user_role(
    u_id: int, 
    new_role: UserRole, 
    db: Session = Depends(get_db), 
    u: User = Depends(get_current_user)
):
    if u.role != UserRole.admin:
        raise HTTPException(status_code=403, detail="Требуются права администратора")
    
    target_user = db.query(User).filter(User.id == u_id).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")

    target_user.role = new_role
    db.commit()
    return {"ok": True}