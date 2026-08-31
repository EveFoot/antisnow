import os, hashlib, uuid
from datetime import datetime
from enum import Enum
from typing import Optional
from fastapi import FastAPI, Depends, HTTPException, Query, UploadFile, File, Form, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy import Column, Integer, String, Float, Enum as SqlEnum, DateTime, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from jose import jwt, JWTError

UPLOAD_DIR = "/app/uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user_admin:password@db:5432/antisnow_db")
SECRET_KEY = "FINAL_PROD_KEY_2026" 
ALGORITHM = "HS256"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# auto_error=False позволяет не падать с 401/500, если заголовок Authorization отсутствует или невалиден
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)

class UserRole(str, Enum):
    user = "user"
    cleaner = "cleaner"
    admin = "admin"

class StatusUpdate(BaseModel):
    status: str

class SnowReport(Base):
    __tablename__ = "reports"
    id = Column(Integer, primary_key=True, index=True)
    lat = Column(Float)
    lon = Column(Float)
    snow_type = Column(String)
    description = Column(String, nullable=True)
    status = Column(String, default="pending") # pending, cleaned, verified
    photo_url = Column(String, nullable=True)
    done_photo_url = Column(String, nullable=True)
    author_email = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    role = Column(SqlEnum(UserRole), default=UserRole.user)

Base.metadata.create_all(bind=engine)

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

app.mount("/static_uploads", StaticFiles(directory=UPLOAD_DIR), name="static_uploads")

def get_db():
    db = SessionLocal()
    try: 
        yield db
    finally: 
        db.close()

def get_current_user(token: Optional[str] = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    if not token:
        return None
    try:
        p = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = p.get("sub")
        if email is None:
            return None
        return db.query(User).filter(User.email == email).first()
    except JWTError:
        return None
    except Exception:
        return None

@app.get("/api/reports")
def get_reports(db: Session = Depends(get_db)):
    return db.query(SnowReport).order_by(SnowReport.created_at.desc()).all()

@app.post("/api/reports")
async def create(
    lat: float = Form(...), 
    lon: float = Form(...), 
    snow_type: str = Form(...), 
    description: str = Form(None), 
    file: UploadFile = File(None), 
    db: Session = Depends(get_db), 
    u: Optional[User] = Depends(get_current_user)
):
    p_url = None
    if file and hasattr(file, 'filename') and file.filename:
        try:
            fname = f"{uuid.uuid4().hex}_{file.filename}"
            path = os.path.join(UPLOAD_DIR, fname)
            content = await file.read()
            if content:
                with open(path, "wb") as b: 
                    b.write(content)
                p_url = f"/static_uploads/{fname}"
        except Exception as e:
            print(f"Error saving file: {e}")
            p_url = None
    
    author_email = u.email if u else "Guest"
    
    rep = SnowReport(
        lat=lat, 
        lon=lon, 
        snow_type=snow_type, 
        description=description, 
        photo_url=p_url, 
        author_email=author_email
    )
    db.add(rep)
    db.commit()
    return {"ok": True}

@app.post("/api/reports/{r_id}/done")
async def mark_done(r_id: int, file: UploadFile = File(None), db: Session = Depends(get_db)):
    rep = db.query(SnowReport).filter(SnowReport.id == r_id).first()
    if not rep:
        raise HTTPException(status_code=404, detail="Отчет не найден")
    if file and hasattr(file, 'filename') and file.filename:
        fname = f"done_{uuid.uuid4().hex}_{file.filename}"
        path = os.path.join(UPLOAD_DIR, fname)
        content = await file.read()
        with open(path, "wb") as b: 
            b.write(content)
        rep.done_photo_url = f"/static_uploads/{fname}"
    rep.status = "cleaned"
    rep.updated_at = datetime.utcnow()
    db.commit()
    return {"ok": True}

@app.patch("/api/reports/{r_id}/status")
def update_report_status(r_id: int, data: StatusUpdate, db: Session = Depends(get_db), u: Optional[User] = Depends(get_current_user)):
    if not u or u.role not in [UserRole.admin, UserRole.cleaner]:
        raise HTTPException(status_code=403, detail="Недостаточно прав")
    
    rep = db.query(SnowReport).filter(SnowReport.id == r_id).first()
    if not rep:
        raise HTTPException(status_code=404, detail="Отчет не найден")
        
    rep.status = data.status
    rep.updated_at = datetime.utcnow()
    db.commit()
    return {"ok": True, "status": rep.status}

@app.post("/api/reports/{r_id}/verify")
def verify_report(r_id: int, db: Session = Depends(get_db), u: Optional[User] = Depends(get_current_user)):
    if not u or u.role != UserRole.admin: 
        raise HTTPException(403)
    rep = db.query(SnowReport).filter(SnowReport.id == r_id).first()
    if not rep:
        raise HTTPException(status_code=404, detail="Отчет не найден")
    rep.status = "verified"
    db.commit()
    return {"ok": True}

@app.delete("/api/reports/{r_id}")
def delete_rep(r_id: int, db: Session = Depends(get_db), u: Optional[User] = Depends(get_current_user)):
    if not u or u.role != UserRole.admin: 
        raise HTTPException(403)
    db.query(SnowReport).filter(SnowReport.id == r_id).delete()
    db.commit()
    return {"ok": True}

@app.post("/api/auth/register")
def reg(email: str = Query(...), password: str = Query(...), db: Session = Depends(get_db)):
    role = UserRole.admin if db.query(User).count() == 0 else UserRole.user
    db.add(User(email=email, hashed_password=hashlib.sha256(password.encode()).hexdigest(), role=role))
    db.commit()
    return {"ok": True}

@app.post("/api/auth/login")
def login(f: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    u = db.query(User).filter(User.email == f.username).first()
    if not u or u.hashed_password != hashlib.sha256(f.password.encode()).hexdigest(): 
        raise HTTPException(401)
    t = jwt.encode({"sub": u.email, "role": u.role.value}, SECRET_KEY, ALGORITHM)
    return {"access_token": t, "role": u.role.value, "email": u.email}

@app.get("/api/admin/users")
def get_users(db: Session = Depends(get_db), u: Optional[User] = Depends(get_current_user)):
    if not u or u.role != UserRole.admin: 
        raise HTTPException(403)
    return db.query(User).all()

@app.patch("/api/admin/users/{u_id}/role")
def change_role(u_id: int, new_role: UserRole, db: Session = Depends(get_db), u: Optional[User] = Depends(get_current_user)):
    if not u or u.role != UserRole.admin: 
        raise HTTPException(403)
    target = db.query(User).filter(User.id == u_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    target.role = new_role
    db.commit()
    return {"ok": True}