from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, Enum as SqlEnum
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
import os
from datetime import datetime
from enum import Enum
from passlib.context import CryptContext

# Настройки БД
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user:password@db:5432/antisnow")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Модель данных
class SnowReport(Base):
    __tablename__ = "reports"
    id = Column(Integer, primary_key=True, index=True)
    address = Column(String)
    lat = Column(Float)
    lon = Column(Float)
    status = Column(String, default="Новый")

# Создаем таблицы
Base.metadata.create_all(bind=engine)

app = FastAPI(root_path="/api")

# Разрешаем запросы с фронтенда
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

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


# 1. Контекст для хеширования паролей
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# 2. Роли пользователей
class UserRole(str, Enum):
    USER = "user"       # Обычный житель
    CLEANER = "cleaner" # Служба уборки
    ADMIN = "admin"     # Администратор

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
    
    # Новые поля для времени и ролей
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Кто создал и кто убрал (связи)
    creator_id = Column(Integer, ForeignKey("users.id"))
    cleaner_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    
    # Текстовое описание от уборщика
    cleaner_note = Column(String, nullable=True)

    from fastapi import HTTPException

# Хелперы для паролей
def get_password_hash(password):
    return pwd_context.hash(password)

@app.post("/auth/register")
def register(email: str, password: str, role: UserRole = UserRole.USER, db: Session = Depends(get_db)):
    # Проверка, есть ли такой email
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
    return {"message": "Пользователь создан", "id": new_user.id}