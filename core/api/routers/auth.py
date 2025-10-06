from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from jose import jwt
from datetime import datetime, timedelta
from samokoder.core.db.session import get_db
from samokoder.core.db.models.user import User
from samokoder.core.config import get_config

router = APIRouter()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/token")

class UserInDB(User):
    hashed_password: str

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

def get_user(db: Session, username: str):
    return db.query(User).filter(User.email == username).first()

class Token(BaseModel):
    access_token: str
    token_type: str

@router.post("/auth/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = get_user(db, form_data.username)
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Invalid credentials")
    
    config = get_config()
    payload = {"sub": user.email, "exp": datetime.utcnow() + timedelta(days=7)}
    token = jwt.encode(payload, config.secret_key, algorithm="HS256")
    return {"access_token": token, "token_type": "bearer"}

@router.post("/auth/register")
def register(user_data: dict, db: Session = Depends(get_db)):
    hashed = pwd_context.hash(user_data["password"])
    user = User(email=user_data["email"], hashed_password=hashed, tier=User.Tier.FREE)
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"id": user.id, "email": user.email}
