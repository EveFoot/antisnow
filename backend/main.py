import os, hashlib, uuid
from enum import Enum
from fastapi import FastAPI, Depends, HTTPException, Query, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from sqlalchemy import Column, Integer, String, Float, Enum as SqlEnum, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from pydantic import BaseModel
from jose import jwt

# --- DATABASE ---
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user_admin:password@db:5432/antisnow_db")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- MODELS ---
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
    status = Column(String, default="pending") # "pending" или "cleaned"
    photo_url = Column(String, nullable=True)

class ReportCreate(BaseModel):
    lat: float
    lon: float
    snow_type: str

class RoleUpdate(BaseModel):
    role: UserRole

Base.metadata.create_all(bind=engine)

# --- APP ---
app = FastAPI(docs_url="/docs", openapi_url="/openapi.json", root_path="/api")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# Раздаем папку с фото как статику
UPLOAD_DIR = "uploads"
if not os.path.exists(UPLOAD_DIR): os.makedirs(UPLOAD_DIR)
app.mount("/static_uploads", StaticFiles(directory=UPLOAD_DIR), name="static_uploads")

def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

# --- ROUTES ---
@app.get("/reports")
def get_reports(db: Session = Depends(get_db)):
    return db.query(SnowReport).all()

@app.post("/reports")
def create_report(report: ReportCreate, db: Session = Depends(get_db)):
    new_report = SnowReport(lat=report.lat, lon=report.lon, snow_type=report.snow_type)
    db.add(new_report)
    db.commit()
    db.refresh(new_report)
    return new_report

# Эндпоинт для уборщика: загрузка фото и смена статуса
@app.post("/cleaner/reports/{report_id}/done")
async def mark_as_done(report_id: int, file: UploadFile = File(...), db: Session = Depends(get_db)):
    report = db.query(SnowReport).filter(SnowReport.id == report_id).first()
    if not report: raise HTTPException(status_code=404)
    
    # Сохраняем файл
    file_ext = file.filename.split(".")[-1]
    filename = f"{uuid.uuid4()}.{file_ext}"
    file_path = os.path.join(UPLOAD_DIR, filename)
    
    with open(file_path, "wb") as buffer:
        buffer.write(await file.read())
    
    report.status = "cleaned"
    report.photo_url = f"/api/static_uploads/{filename}"
    db.commit()
    return {"status": "success"}

@app.delete("/admin/reports/{report_id}")
def delete_report(report_id: int, db: Session = Depends(get_db)):
    report = db.query(SnowReport).filter(SnowReport.id == report_id).first()
    if not report: raise HTTPException(status_code=404)
    db.delete(report)
    db.commit()
    return {"status": "deleted"}

@app.post("/auth/register")
def register(email: str = Query(...), password: str = Query(...), db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == email).first():
        raise HTTPException(status_code=400, detail="Email busy")
    role = UserRole.admin if db.query(User).count() == 0 else UserRole.user
    hashed = hashlib.sha256(password.encode()).hexdigest()
    db.add(User(email=email, hashed_password=hashed, role=role))
    db.commit()
    return {"status": "ok", "role": role}

@app.post("/auth/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form_data.username).first()
    hashed = hashlib.sha256(form_data.password.encode()).hexdigest()
    if not user or user.hashed_password != hashed: raise HTTPException(status_code=401)
    token = jwt.encode({"sub": user.email, "role": user.role.value}, "SECRET", algorithm="HS256")
    return {"access_token": token, "token_type": "bearer", "role": user.role.value}

@app.get("/admin/users")
def get_users(db: Session = Depends(get_db)):
    return db.query(User).all()

@app.put("/admin/users/{user_id}/role")
def update_user_role(user_id: int, role_data: RoleUpdate, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user: raise HTTPException(status_code=404)
    user.role = role_data.role
    db.commit()
    return {"status": "success"}