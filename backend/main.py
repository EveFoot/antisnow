import os, hashlib, uuid
from datetime import datetime, timedelta
from enum import Enum
from typing import Optional, List

from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from jose import jwt
from sqlalchemy import Column, Integer, String, Float, DateTime, Enum as SqlEnum, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session

# --- КОНФИГУРАЦИЯ ---
SECRET_KEY = "SUPER_SECRET_KEY_FOR_PRACTICE"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 600
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user_admin:password@db:5432/antisnow_db")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- МОДЕЛИ ДАННЫХ ---
class UserRole(str, Enum):
    user = "user"
    cleaner = "cleaner"
    admin = "admin"

class ReportStatus(str, Enum):
    new = "Новый"
    done = "Убрано"

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    role = Column(SqlEnum(UserRole), default=UserRole.user)

class SnowReport(Base):
    __tablename__ = "reports"
    id = Column(Integer, primary_key=True, index=True)
    address = Column(String)
    lat = Column(Float)
    lon = Column(Float)
    status = Column(SqlEnum(ReportStatus), default=ReportStatus.new)
    photo_url = Column(String, nullable=True)

Base.metadata.create_all(bind=engine)

# --- НАСТРОЙКА ПРИЛОЖЕНИЯ ---
app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# --- ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ---
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
        if not user: raise HTTPException(status_code=401)
        return user
    except: raise HTTPException(status_code=401)

# --- ЭНДПОИНТЫ ПОЛЬЗОВАТЕЛЕЙ ---

@app.post("/auth/register")
def register(email: str, password: str, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == email).first():
        raise HTTPException(status_code=400, detail="Email уже занят")
    
    # Первый зарегистрированный становится админом автоматически
    is_first = db.query(User).count() == 0
    role = UserRole.admin if is_first else UserRole.user
    
    hashed = hashlib.sha256(password.encode()).hexdigest()
    new_user = User(email=email, hashed_password=hashed, role=role)
    db.add(new_user)
    db.commit()
    return {"status": "ok"}

@app.post("/auth/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form_data.username).first()
    hashed = hashlib.sha256(form_data.password.encode()).hexdigest()
    if not user or user.hashed_password != hashed:
        raise HTTPException(status_code=401, detail="Неверный логин или пароль")
    
    token_data = {
        "sub": user.email, 
        "role": user.role.value, 
        "exp": datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    }
    token = jwt.encode(token_data, SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token": token, "token_type": "bearer", "role": user.role.value, "user_id": user.id}

# --- ЭНДПОИНТЫ МЕТОК (REPORTS) ---

@app.get("/reports")
def get_reports(db: Session = Depends(get_db)):
    return db.query(SnowReport).all()

@app.post("/report")
async def create_report(address: str=Form(...), lat: float=Form(...), lon: float=Form(...), photo: UploadFile=File(None), db: Session=Depends(get_db)):
    path = None
    if photo:
        fname = f"{uuid.uuid4()}{os.path.splitext(photo.filename)[1]}"
        fdir = "static/uploads"
        os.makedirs(fdir, exist_ok=True)
        with open(f"{fdir}/{fname}", "wb") as buffer:
            buffer.write(await photo.read())
        path = f"/api/static/uploads/{fname}"
    
    report = SnowReport(address=address, lat=lat, lon=lon, photo_url=path)
    db.add(report)
    db.commit()
    return {"status": "created"}

@app.patch("/reports/{id}/status")
def update_status(id: int, new_status: ReportStatus, user: User=Depends(get_current_user), db: Session=Depends(get_db)):
    # И админ, и уборщик могут менять статус заявки
    if user.role not in [UserRole.admin, UserRole.cleaner]:
        raise HTTPException(status_code=403, detail="Только уборщик или админ могут менять статус")
    
    report = db.query(SnowReport).get(id)
    if not report:
        raise HTTPException(status_code=404, detail="Заявка не найдена")
    
    report.status = new_status
    db.commit()
    return {"status": "updated"}

# --- ЭНДПОИНТЫ АДМИНИСТРАТОРА ---

@app.get("/admin/users")
def list_users(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if user.role != UserRole.admin:
        raise HTTPException(status_code=403, detail="Доступ запрещен")
    return db.query(User).all()

@app.patch("/admin/users/{target_id}/role")
def change_role(target_id: int, new_role: UserRole, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if user.role != UserRole.admin:
        raise HTTPException(status_code=403, detail="Доступ запрещен")
    
    target = db.query(User).get(target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    
    target.role = new_role
    db.commit()
    return {"status": "role_updated"}