from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, Enum as SqlEnum, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
import os
from datetime import datetime
from enum import Enum
from passlib.context import CryptContext

# 1. Настройки БД
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user:password@db:5432/antisnow")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# 2. Контекст для хеширования паролей
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# 3. Роли пользователей
class UserRole(str, Enum):
    USER = "user"
    CLEANER = "cleaner"
    ADMIN = "admin"

# 4. Модели таблиц
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
    
    # Связи (Foreign Keys)
    creator_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    cleaner_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    cleaner_note = Column(String, nullable=True)

# Создаем таблицы в базе
Base.metadata.create_all(bind=engine)

# 5. Инициализация FastAPI
app = FastAPI(root_path="/api")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Зависимость для БД
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# 6. Хелперы
def get_password_hash(password):
    return pwd_context.hash(password)

# 7. Эндпоинты

@app.post("/auth/register")
def register(email: str, password: str, role: UserRole = UserRole.USER, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email уже зарегистрирован")
    
    new_user = User(
        email=email, 
        hashed_password=get_password_hash(password),
        role=role
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"message": "Пользователь создан", "id": new_user.id, "role": new_user.role}

@app.get("/reports")
def get_reports(db: Session = Depends(get_db)):
    return db.query(SnowReport).all()

@app.post("/report")
def create_report(address: str, lat: float, lon: float, db: Session = Depends(get_db)):
    # Пока создаем без creator_id (добавим, когда внедрим логин и токены)
    new_report = SnowReport(address=address, lat=lat, lon=lon)
    db.add(new_report)
    db.commit()
    db.refresh(new_report)
    return new_report