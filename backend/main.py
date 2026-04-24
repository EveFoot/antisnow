import os, hashlib, uuid
from datetime import datetime, timedelta
from enum import Enum
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Form, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import Column, Integer, String, Float, Enum as SqlEnum, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from jose import jwt

# --- CONFIG ---
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user_admin:password@db:5432/antisnow_db")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

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

Base.metadata.create_all(bind=engine)

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

# --- ROUTES ---

# Тестовый путь, чтобы проверить связь
@app.get("/ping")
@app.get("/api/ping")
def ping():
    return {"status": "pong"}

@app.post("/auth/register")
@app.post("/api/auth/register")
def register(email: str = Query(...), password: str = Query(...), db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == email).first():
        raise HTTPException(status_code=400, detail="Email busy")
    
    # Считаем юзеров: если 0, то первый будет admin
    user_count = db.query(User).count()
    role = UserRole.admin if user_count == 0 else UserRole.user
    
    hashed = hashlib.sha256(password.encode()).hexdigest()
    new_user = User(email=email, hashed_password=hashed, role=role)
    db.add(new_user)
    db.commit()
    return {"status": "ok", "role": role}

@app.post("/auth/login")
@app.post("/api/auth/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form_data.username).first()
    hashed = hashlib.sha256(form_data.password.encode()).hexdigest()
    if not user or user.hashed_password != hashed:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = jwt.encode({
        "sub": user.email, 
        "role": user.role.value, 
        "exp": datetime.utcnow() + timedelta(minutes=600)
    }, "SECRET", algorithm="HS256")
    
    return {"access_token": token, "token_type": "bearer", "role": user.role.value, "user_email": user.email}