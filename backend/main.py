import os, hashlib, uuid
from datetime import datetime
from enum import Enum
from fastapi import FastAPI, Depends, HTTPException, Query, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from fastapi.staticfiles import StaticFiles
from sqlalchemy import Column, Integer, String, Float, Enum as SqlEnum, DateTime, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from jose import jwt, JWTError

# Настройки
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user_admin:password@db:5432/antisnow_db")
SECRET_KEY = "SECRET_SECRET_123" 
ALGORITHM = "HS256"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

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
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

Base.metadata.create_all(bind=engine)

app = FastAPI(title="AntiSnow API", root_path="/api")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

UPLOAD_DIR = "uploads"
if not os.path.exists(UPLOAD_DIR): os.makedirs(UPLOAD_DIR)
app.mount("/static_uploads", StaticFiles(directory=UPLOAD_DIR), name="static_uploads")

def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None: raise HTTPException(401)
    except JWTError: raise HTTPException(401)
    user = db.query(User).filter(User.email == email).first()
    if user is None: raise HTTPException(401)
    return user

@app.get("/reports")
def get_reports(db: Session = Depends(get_db)):
    return db.query(SnowReport).all()

@app.post("/reports")
async def create_report(
    lat: float = Form(...), lon: float = Form(...), snow_type: str = Form(...),
    file: UploadFile = File(None), db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user) 
):
    path = None
    if file:
        fname = f"{uuid.uuid4()}.{file.filename.split('.')[-1]}"
        with open(os.path.join(UPLOAD_DIR, fname), "wb") as b: b.write(await file.read())
        path = f"/api/static_uploads/{fname}"
    db.add(SnowReport(lat=lat, lon=lon, snow_type=snow_type, photo_url=path))
    db.commit()
    return {"ok": True}

@app.post("/auth/register")
def register(email: str = Query(...), password: str = Query(...), db: Session = Depends(get_db)):
    role = UserRole.admin if db.query(User).count() == 0 else UserRole.user
    hashed = hashlib.sha256(password.encode()).hexdigest()
    db.add(User(email=email, hashed_password=hashed, role=role))
    db.commit()
    return {"ok": True}

@app.post("/auth/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or user.hashed_password != hashlib.sha256(form_data.password.encode()).hexdigest():
        raise HTTPException(401)
    token = jwt.encode({"sub": user.email, "role": user.role.value}, SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token": token, "token_type": "bearer", "role": user.role.value}

@app.get("/admin/users")
def get_users(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if current_user.role != UserRole.admin: raise HTTPException(403)
    return db.query(User).all()

@app.put("/admin/users/{u_id}/role")
def change_role(u_id: int, data: dict, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if current_user.role != UserRole.admin: raise HTTPException(403)
    user = db.query(User).filter(User.id == u_id).first()
    user.role = data['role']
    db.commit()
    return {"ok": True}