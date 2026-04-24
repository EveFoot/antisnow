import os, hashlib, uuid
from enum import Enum
from fastapi import FastAPI, Depends, HTTPException, Query, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from sqlalchemy import Column, Integer, String, Float, Enum as SqlEnum, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from jose import jwt

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

class SnowReport(Base):
    __tablename__ = "reports"
    id = Column(Integer, primary_key=True, index=True)
    lat = Column(Float)
    lon = Column(Float)
    snow_type = Column(String)
    status = Column(String, default="pending") 
    photo_url = Column(String, nullable=True)

Base.metadata.create_all(bind=engine)
app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

UPLOAD_DIR = "uploads"
if not os.path.exists(UPLOAD_DIR): os.makedirs(UPLOAD_DIR)
app.mount("/static_uploads", StaticFiles(directory=UPLOAD_DIR), name="static_uploads")

def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

# --- МЕТКИ ---

@app.get("/reports")
def get_reports(db: Session = Depends(get_db)):
    return db.query(SnowReport).all()

@app.post("/reports")
async def create_report(
    lat: float = Form(...), lon: float = Form(...), snow_type: str = Form(...),
    file: UploadFile = File(None), db: Session = Depends(get_db)
):
    path = None
    if file:
        fname = f"{uuid.uuid4()}.{file.filename.split('.')[-1]}"
        with open(os.path.join(UPLOAD_DIR, fname), "wb") as b: b.write(await file.read())
        path = f"/api/static_uploads/{fname}"
    db.add(SnowReport(lat=lat, lon=lon, snow_type=snow_type, photo_url=path))
    db.commit()
    return {"ok": True}

@app.post("/cleaner/reports/{report_id}/done")
async def mark_as_done(report_id: int, file: UploadFile = File(None), db: Session = Depends(get_db)):
    report = db.query(SnowReport).filter(SnowReport.id == report_id).first()
    if not report: raise HTTPException(404)
    if file:
        fname = f"{uuid.uuid4()}.{file.filename.split('.')[-1]}"
        with open(os.path.join(UPLOAD_DIR, fname), "wb") as b: b.write(await file.read())
        report.photo_url = f"/api/static_uploads/{fname}"
    report.status = "cleaned"
    db.commit()
    return {"ok": True}

@app.post("/admin/reports/{report_id}/verify")
def verify_report(report_id: int, db: Session = Depends(get_db)):
    report = db.query(SnowReport).filter(SnowReport.id == report_id).first()
    if report: report.status = "verified"
    db.commit()
    return {"ok": True}

@app.delete("/admin/reports/{report_id}")
def delete_report(report_id: int, db: Session = Depends(get_db)):
    db.query(SnowReport).filter(SnowReport.id == report_id).delete()
    db.commit()
    return {"ok": True}

# --- ПОЛЬЗОВАТЕЛИ ---

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
    hashed = hashlib.sha256(form_data.password.encode()).hexdigest()
    if not user or user.hashed_password != hashed: raise HTTPException(401)
    token = jwt.encode({"sub": user.email, "role": user.role.value}, "SECRET", algorithm="HS256")
    return {"access_token": token, "token_type": "bearer", "role": user.role.value}

@app.get("/admin/users")
def get_users(db: Session = Depends(get_db)):
    return db.query(User).all()

@app.put("/admin/users/{user_id}/role")
async def update_role(user_id: int, data: dict, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if user: user.role = data['role']
    db.commit()
    return {"ok": True}