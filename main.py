from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import sessionmaker,Session
from sqlalchemy.ext.declarative import declarative_base
from typing import Optional,List
from passlib.context import CryptContext
from pydantic import BaseModel  # Import Pydantic's BaseModel

app = FastAPI()

DATABASE_URL = "mysql://root@localhost/fast_db"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    username = Column(String, unique=True, index=True)
    password = Column(String)

Base.metadata.create_all(bind=engine)

# Buat fungsi hash untuk password
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password):
    return pwd_context.hash(password)

# Fungsi untuk verifikasi password
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# Buat model Pydantic untuk data registrasi
class UserCreate(BaseModel):
    name: str
    username: str
    password: str

# Endpoint untuk registrasi
@app.post("/register/")
def register(user: UserCreate):
    db = SessionLocal()
    db_user = db.query(User).filter(User.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username sudah ada")
    hashed_password = hash_password(user.password)
    db_user = User(name=user.name, username=user.username, password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)  # Me-refresh objek untuk mendapatkan id yang baru saja dibuat
    db.close()
    return {"message": "Data created successfully", "data": {"id": db_user.id, "name": db_user.name, "username": db_user.username}}


# Buat model Pydantic untuk data login
class UserLogin(BaseModel):
    username: str
    password: str

# Endpoint untuk login
@app.post("/login/")
def login(user: UserLogin):
    db = SessionLocal()
    db_user = db.query(User).filter(User.username == user.username).first()
    db.close()
    if not db_user or not verify_password(user.password, db_user.password):
        raise HTTPException(status_code=401, detail="Login gagal")
    return {"message": "Login successfully", "data": {"id": db_user.id, "username": db_user.username}}

# Model Pydantic untuk data pengguna dalam respons
class UserBase(BaseModel):
    id: int
    name: str
    username: str

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
