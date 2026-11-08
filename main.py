import os, uuid, hashlib, shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Depends
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from passlib.context import CryptContext
from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey, Text
from sqlalchemy.orm import declarative_base, sessionmaker, Session

ROOT = Path(__file__).resolve().parent.parent
DATA = Path(os.getenv("DATA_DIR", ROOT / "data"))
UPLOADS = DATA / "uploads"
UPLOADS.mkdir(parents=True, exist_ok=True)
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{DATA / 'vaultshare.db'}")
SECRET_KEY = os.getenv("SECRET_KEY", "CHANGE_THIS_DEVELOPMENT_SECRET_BEFORE_DEPLOYING")
ALGORITHM = "HS256"

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()
pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2 = OAuth2PasswordBearer(tokenUrl="/api/login")

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(30), default="user")
    created_at = Column(DateTime, default=datetime.utcnow)

class Document(Base):
    __tablename__ = "documents"
    id = Column(String(36), primary_key=True)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    filename = Column(String(255), nullable=False)
    stored_name = Column(String(255), nullable=False)
    sha256 = Column(String(64), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class Share(Base):
    __tablename__ = "shares"
    id = Column(Integer, primary_key=True)
    document_id = Column(String(36), ForeignKey("documents.id"), nullable=False)
    recipient_email = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)
app = FastAPI(title="VaultShare API")
app.mount("/static", StaticFiles(directory=ROOT / "app" / "static"), name="static")

def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def current_user(token: str = Depends(oauth2), db: Session = Depends(db_session)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        uid = int(payload["sub"])
    except (JWTError, KeyError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    user = db.query(User).filter(User.id == uid).first()
    if not user:
        raise HTTPException(status_code=401, detail="Account not found")
    return user

@app.get("/")
def home():
    return FileResponse(ROOT / "app" / "static" / "index.html")

@app.post("/api/register")
def register(email: str = Form(...), password: str = Form(...), db: Session = Depends(db_session)):
    email = email.strip().lower()
    if len(password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")
    if db.query(User).filter(User.email == email).first():
        raise HTTPException(409, "An account with that email already exists")
    user = User(email=email, password_hash=pwd.hash(password), role="user")
    db.add(user); db.commit()
    return {"message": "Account created. You can now sign in."}

@app.post("/api/login")
def login(email: str = Form(...), password: str = Form(...), db: Session = Depends(db_session)):
    user = db.query(User).filter(User.email == email.strip().lower()).first()
    if not user or not pwd.verify(password, user.password_hash):
        raise HTTPException(401, "Incorrect email or password")
    token = jwt.encode({"sub": str(user.id), "exp": datetime.now(timezone.utc) + timedelta(hours=12)}, SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token": token, "token_type": "bearer", "email": user.email}

@app.get("/api/me")
def me(user: User = Depends(current_user)):
    return {"email": user.email, "role": user.role}

@app.post("/api/documents")
async def upload_document(file: UploadFile = File(...), user: User = Depends(current_user), db: Session = Depends(db_session)):
    if not file.filename:
        raise HTTPException(400, "Choose a file")
    doc_id = str(uuid.uuid4())
    stored = doc_id + ".bin"
    path = UPLOADS / stored
    digest = hashlib.sha256()
    with path.open("wb") as out:
        while chunk := await file.read(1024 * 1024):
            digest.update(chunk); out.write(chunk)
    doc = Document(id=doc_id, owner_id=user.id, filename=Path(file.filename).name, stored_name=stored, sha256=digest.hexdigest())
    db.add(doc); db.commit()
    return {"id": doc.id, "filename": doc.filename, "sha256": doc.sha256}

@app.get("/api/documents")
def list_documents(user: User = Depends(current_user), db: Session = Depends(db_session)):
    docs = db.query(Document).filter(Document.owner_id == user.id).order_by(Document.created_at.desc()).all()
    return [{"id": d.id, "filename": d.filename, "sha256": d.sha256, "created_at": d.created_at.isoformat()} for d in docs]

@app.get("/api/documents/{doc_id}/verify")
def verify_document(doc_id: str, user: User = Depends(current_user), db: Session = Depends(db_session)):
    doc = db.query(Document).filter(Document.id == doc_id, Document.owner_id == user.id).first()
    if not doc: raise HTTPException(404, "Document not found")
    path = UPLOADS / doc.stored_name
    if not path.exists(): raise HTTPException(404, "Stored file is missing")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return {"filename": doc.filename, "valid": digest == doc.sha256, "expected_sha256": doc.sha256, "actual_sha256": digest}

@app.get("/api/documents/{doc_id}/download")
def download_document(doc_id: str, user: User = Depends(current_user), db: Session = Depends(db_session)):
    doc = db.query(Document).filter(Document.id == doc_id, Document.owner_id == user.id).first()
    if not doc: raise HTTPException(404, "Document not found")
    path = UPLOADS / doc.stored_name
    if not path.exists(): raise HTTPException(404, "Stored file is missing")
    return FileResponse(path, filename=doc.filename)

@app.post("/api/documents/{doc_id}/share")
def share_document(doc_id: str, recipient_email: str = Form(...), user: User = Depends(current_user), db: Session = Depends(db_session)):
    doc = db.query(Document).filter(Document.id == doc_id, Document.owner_id == user.id).first()
    if not doc: raise HTTPException(404, "Document not found")
    share = Share(document_id=doc_id, recipient_email=recipient_email.strip().lower())
    db.add(share); db.commit()
    return {"message": "Share invitation recorded. Recipient access links are not yet implemented."}

@app.get("/api/audit")
def audit(user: User = Depends(current_user), db: Session = Depends(db_session)):
    docs = db.query(Document).filter(Document.owner_id == user.id).order_by(Document.created_at.desc()).all()
    return [{"action": "Uploaded document", "filename": d.filename, "timestamp": d.created_at.isoformat()} for d in docs]
