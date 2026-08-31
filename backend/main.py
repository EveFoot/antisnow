import os
import shutil
from typing import List, Optional
from datetime import datetime, timedelta

from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from passlib.context import CryptContext
from jose import JWTError, jwt

# --- НАСТРОЙКИ ---
SECRET_KEY = "antisnow_secret_key_super_secure"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:postgres@db:5432/antisnow")

# Инициализация БД
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Настройка шифрования паролей
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

app = FastAPI(title="AntiSnow API")

# Разрешаем CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Создаем папку uploads для хранения загруженных фотографий
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)
app.mount("/uploads", StaticFiles(directory=UPLOAD_DIR), name="uploads")


# --- МОДЕЛИ БАЗЫ ДАННЫХ ---
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, default="user")  # 'user' или 'admin'


class SnowReport(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True)
    lat = Column(Float, nullable=False)
    lon = Column(Float, nullable=False)
    snow_type = Column(String, nullable=False)
    description = Column(String, nullable=True)
    photo_url = Column(String, nullable=True)
    status = Column(String, default="Новая")  # 'Новая', 'В работе', 'Выполнено'
    created_at = Column(DateTime, default=datetime.utcnow)
    user_id = Column(Integer, nullable=True)


Base.metadata.create_all(bind=engine)


# --- PYDANTIC СХЕМЫ ---
class UserRegister(BaseModel):
    email: EmailStr
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str
    role: str
    email: str


class ReportResponse(BaseModel):
    id: int
    lat: float
    lon: float
    snow_type: str
    description: Optional[str]
    photo_url: Optional[str]
    status: str
    created_at: datetime

    class Config:
        from_attributes = True


# --- ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ---
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    pwd_bytes = plain_password.encode('utf-8')[:72]
    return pwd_context.verify(pwd_bytes.decode('utf-8', errors='ignore'), hashed_password)


def get_password_hash(password: str) -> str:
    # Ограничение 72 байта исключает падение модуля bcrypt
    pwd_bytes = password.encode('utf-8')[:72]
    return pwd_context.hash(pwd_bytes.decode('utf-8', errors='ignore'))


def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Не удалось валидировать токен авторизации",
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
def register(data: UserRegister, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.email == data.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Пользователь с таким Email уже зарегистрирован")

    # Автоматически делаем первому пользователю роль admin
    is_first_user = db.query(User).count() == 0
    role = "admin" if is_first_user else "user"

    new_user = User(
        email=data.email,
        hashed_password=get_password_hash(data.password),
        role=role
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"message": "Успешная регистрация", "role": new_user.role}


@app.post("/api/auth/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Неверный Email или пароль")

    access_token = create_access_token(data={"sub": user.email, "role": user.role})
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "role": user.role,
        "email": user.email
    }


# --- ЭНДПОИНТЫ МЕТОК И ОТЧЕТОВ ---
@app.get("/api/reports", response_model=List[ReportResponse])
def get_reports(db: Session = Depends(get_db)):
    return db.query(SnowReport).order_by(SnowReport.created_at.desc()).all()


@app.post("/api/reports", response_model=ReportResponse)
def create_report(
    lat: float = Form(...),
    lon: float = Form(...),
    snow_type: str = Form(...),
    description: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    photo_url = None
    if file:
        file_filename = f"{datetime.utcnow().timestamp()}_{file.filename}"
        file_path = os.path.join(UPLOAD_DIR, file_filename)
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        photo_url = f"/uploads/{file_filename}"

    report = SnowReport(
        lat=lat,
        lon=lon,
        snow_type=snow_type,
        description=description,
        photo_url=photo_url,
        user_id=current_user.id
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    return report


# --- АДМИН ЭНДПОИНТЫ ---
@app.patch("/api/reports/{report_id}/status")
def update_report_status(
    report_id: int,
    status: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Доступ разрешен только администраторам")

    report = db.query(SnowReport).filter(SnowReport.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Отчет не найден")

    report.status = status
    db.commit()
    return {"message": "Статус обновлен"}


@app.delete("/api/reports/{report_id}")
def delete_report(
    report_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Доступ разрешен только администраторам")

    report = db.query(SnowReport).filter(SnowReport.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Отчет не найден")

    db.delete(report)
    db.commit()
    return {"message": "Отчет удален"}