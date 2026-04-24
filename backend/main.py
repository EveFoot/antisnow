import os
import hashlib
import uuid
from enum import Enum
from fastapi import FastAPI, Depends, HTTPException, Query, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from sqlalchemy import Column, Integer, String, Float, Enum as SqlEnum, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from jose import jwt

# --- НАСТРОЙКИ БАЗЫ ---
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user_admin:password@db:5432/antisnow_db")
engine = create_engine(DATABASE_URL)
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
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    role = Column(SqlEnum(UserRole), default=UserRole.user)

class SnowReport(Base):
    __tablename__ = "reports"
    id = Column(Integer, primary_key=True, index=True)
    lat = Column(Float)
    lon = Column(Float)
    snow_type = Column(String)
    status = Column(String, default="pending") 
    photo_url = Column(String, nullable=True)

# Инициализация таблиц
Base.metadata.create_all(bind=engine)

# root_path="/api" — это заставляет FastAPI знать, что он работает за прокси Nginx
app = FastAPI(title="AntiSnow API", root_path="/api")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Папка для загрузки фото
UPLOAD_DIR = "uploads"
if not os.path.exists(UPLOAD_DIR):
    os.makedirs(UPLOAD_DIR)

# Монтируем статику (внутри контейнера это /app/uploads)
app.mount("/static_uploads", StaticFiles(directory=UPLOAD_DIR), name="static_uploads")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- ЭНДПОИНТЫ МЕТОК ---

@app.get("/reports")
def get_reports(db: Session = Depends(get_db)):
    return db.query(SnowReport).all()

@app.post("/reports")
async def create_report(
    lat: float = Form(...), 
    lon: float = Form(...), 
    snow_type: str = Form(...),
    file: UploadFile = File(None), 
    db: Session = Depends(get_db)
):
    path = None
    if file:
        file_ext = file.filename.split('.')[-1]
        fname = f"{uuid.uuid4()}.{file_ext}"
        file_location = os.path.join(UPLOAD_DIR, fname)
        with open(file_location, "wb") as buffer:
            buffer.write(await file.read())
        # Путь, который будет доступен через Nginx
        path = f"/api/static_uploads/{fname}"
    
    new_report = SnowReport(lat=lat, lon=lon, snow_type=snow_type, photo_url=path)
    db.add(new_report)
    db.commit()
    return {"ok": True}

# --- ЭНДПОИНТЫ АВТОРИЗАЦИИ ---

@app.post("/auth/register")
def register(email: str = Query(...), password: str = Query(...), db: Session = Depends(get_db)):
    # Если пользователей нет, первый становится админом
    role = UserRole.admin if db.query(User).count() == 0 else UserRole.user
    hashed = hashlib.sha256(password.encode()).hexdigest()
    
    # Проверка на существование
    existing_user = db.query(User).filter(User.email == email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")
        
    db.add(User(email=email, hashed_password=hashed, role=role))
    db.commit()
    return {"ok": True}

@app.post("/auth/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form_data.username).first()
    hashed = hashlib.sha256(form_data.password.encode()).hexdigest()
    
    if not user or user.hashed_password != hashed:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # СЕКРЕТ должен быть в .env в реальности
    token = jwt.encode({"sub": user.email, "role": user.role.value}, "SECRET", algorithm="HS256")
    return {"access_token": token, "token_type": "bearer", "role": user.role.value}

# --- АДМИН-ПАНЕЛЬ ---

@app.get("/admin/users")
def get_users(db: Session = Depends(get_db)):
    return db.query(User).all()

@app.put("/admin/users/{user_id}/role")
async def update_role(user_id: int, data: dict, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Получаем новую роль из JSON body: {"role": "cleaner"}
    if 'role' in data:
        user.role = data['role']
        db.commit()
        return {"ok": True}
    raise HTTPException(status_code=400, detail="Role not provided")

@app.get("/")
def health():
    return {"status": "ok", "message": "AntiSnow API is running"}