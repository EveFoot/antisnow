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
from jose import jwt

# 1. ПОДГОТОВКА ОКРУЖЕНИЯ
UPLOAD_DIR = "/app/uploads"
if not os.path.exists(UPLOAD_DIR):
    os.makedirs(UPLOAD_DIR, exist_ok=True)

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user_admin:password@db:5432/antisnow_db")
SECRET_KEY = "SECRET_SECRET_123" 
ALGORITHM = "HS256"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

# 2. МОДЕЛИ
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
    lat = Column(Float); lon = Column(Float)
    snow_type = Column(String)
    status = Column(String, default="pending") 
    photo_url = Column(String, nullable=True)
    done_photo_url = Column(String, nullable=True)
    author_email = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

# 3. РОУТЫ API
@app.get("/api/reports")
def get_reports(db: Session = Depends(get_db)):
    return db.query(SnowReport).order_by(SnowReport.created_at.desc()).all()

@app.post("/api/reports")
async def create_report(lat: float=Form(...), lon: float=Form(...), snow_type: str=Form(...), file: UploadFile=File(None), db: Session=Depends(get_db)):
    p_url = None
    if file:
        fname = f"b_{uuid.uuid4().hex}.jpg"
        fpath = os.path.join(UPLOAD_DIR, fname)
        with open(fpath, "wb") as buf:
            buf.write(await file.read())
        p_url = f"/static_uploads/{fname}"
    
    rep = SnowReport(lat=lat, lon=lon, snow_type=snow_type, photo_url=p_url)
    db.add(rep); db.commit(); return {"ok": True}

@app.post("/api/reports/{r_id}/done")
async def mark_done(r_id: int, file: UploadFile=File(None), db: Session=Depends(get_db)):
    rep = db.query(SnowReport).filter(SnowReport.id == r_id).first()
    if not rep: raise HTTPException(404)
    if file:
        fname = f"a_{uuid.uuid4().hex}.jpg"
        with open(os.path.join(UPLOAD_DIR, fname), "wb") as buf:
            buf.write(await file.read())
        rep.done_photo_url = f"/static_uploads/{fname}"
    rep.status = "cleaned"
    rep.updated_at = datetime.utcnow()
    db.commit(); return {"ok": True}

@app.post("/api/auth/register")
def register(email:str=Query(...), password:str=Query(...), db:Session=Depends(get_db)):
    role = UserRole.admin if db.query(User).count() == 0 else UserRole.user
    hashed = hashlib.sha256(password.encode()).hexdigest()
    db.add(User(email=email, hashed_password=hashed, role=role))
    db.commit(); return {"ok": True}

@app.post("/api/auth/login")
def login(form: OAuth2PasswordRequestForm=Depends(), db: Session=Depends(get_db)):
    u = db.query(User).filter(User.email == form.username).first()
    if not u or u.hashed_password != hashlib.sha256(form.password.encode()).hexdigest():
        raise HTTPException(401)
    token = jwt.encode({"sub": u.email, "role": u.role.value}, SECRET_KEY, ALGORITHM)
    return {"access_token": token, "role": u.role.value, "email": u.email}

@app.get("/api/admin/users")
def list_users(db: Session=Depends(get_db)):
    return db.query(User).all()

@app.delete("/api/reports/{r_id}")
def delete_rep(r_id: int, db: Session=Depends(get_db)):
    db.query(SnowReport).filter(SnowReport.id == r_id).delete()
    db.commit(); return {"ok": True}

# ВАЖНО: Монтируем статику ПОСЛЕ всех API роутов
app.mount("/static_uploads", StaticFiles(directory=UPLOAD_DIR), name="static_uploads")