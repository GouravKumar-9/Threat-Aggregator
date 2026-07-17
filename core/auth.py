import os
from datetime import datetime, timedelta, timezone
import jwt
from passlib.context import CryptContext
import pyotp
from fastapi import Request, HTTPException, Security
from fastapi.security import APIKeyCookie
import core.database as db
from dotenv import load_dotenv

load_dotenv()

# Setup password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT settings
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "super-secret-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 1 day

# Cookie setup
cookie_sec = APIKeyCookie(name="session_token", auto_error=False)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def decode_access_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def generate_mfa_secret():
    return pyotp.random_base32()

def get_mfa_uri(username: str, secret: str):
    return pyotp.totp.TOTP(secret).provisioning_uri(
        name=username,
        issuer_name="ThreatAggregator"
    )

def verify_mfa_code(secret: str, code: str):
    totp = pyotp.totp.TOTP(secret)
    return totp.verify(code)

async def get_current_user(request: Request):
    """
    FastAPI dependency to extract and verify the session token from cookies.
    """
    token = request.cookies.get("session_token")
    if not token:
        # Also check Authorization header as a fallback for pure API clients
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
            
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
        
    payload = decode_access_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Token expired or invalid")
        
    username = payload.get("sub")
    if not username:
        raise HTTPException(status_code=401, detail="Invalid token payload")
        
    # Check if MFA is pending
    if payload.get("mfa_pending"):
        raise HTTPException(status_code=403, detail="MFA verification required")
        
    user = db.get_user_by_username(username)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
        
    return user
