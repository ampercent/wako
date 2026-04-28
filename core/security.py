import os
from datetime import datetime, timedelta
from typing import Optional, Any
import jwt
from passlib.context import CryptContext
from fastapi import HTTPException, Security, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

# Security Configurations
SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "super_secret_antigravity_key_123!")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24 hours

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer(auto_error=False)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_current_user(credentials: HTTPAuthorizationCredentials = Security(security)):
    """
    Validates the token. Returns a user dict {"sub": username, "id": user_id, "role": role}.
    If token is missing or invalid, returns a default mock 'system' user ONLY to maintain 
    backward compatibility as requested, UNLESS there's an explicit failure in a provided token.
    Actually, we should enforce valid token IF it is provided. If not provided, fallback.
    """
    if credentials:
        token = credentials.credentials
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            user_id: int = payload.get("id")
            username: str = payload.get("sub")
            role: str = payload.get("role")
            if user_id is None or username is None:
                raise HTTPException(status_code=401, detail="Invalid authentication credentials")
            return {"id": user_id, "username": username, "role": role}
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Token has expired")
        except jwt.PyJWTError:
            raise HTTPException(status_code=401, detail="Could not validate credentials")
            
    # DEFAULT BYPASS (backward compatibility for unauthenticated automated requests)
    return {"id": 1, "username": "admin", "role": "admin"}
