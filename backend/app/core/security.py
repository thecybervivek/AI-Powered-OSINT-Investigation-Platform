import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from jose import JWTError, jwt
from passlib.context import CryptContext
from backend.app.core.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
def hash_password(password: str) -> str: return pwd_context.hash(password)
def verify_password(plain_password: str, hashed_password: str) -> bool: return pwd_context.verify(plain_password, hashed_password)
def hash_jti(jti: str) -> str: return hashlib.sha256(jti.encode("utf-8")).hexdigest()

def _claims(data: dict, token_type: str, expires: timedelta, jti: str | None = None) -> dict:
    now = datetime.now(timezone.utc)
    payload = data.copy(); payload.update({"iat": now, "exp": now + expires, "type": token_type,
        "iss": settings.JWT_ISSUER, "aud": settings.JWT_AUDIENCE, "jti": jti or secrets.token_urlsafe(24)})
    return payload

def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    return jwt.encode(_claims(data, "access", expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)), settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)

def create_refresh_token(data: dict, *, jti: str | None = None) -> tuple[str, str, datetime]:
    token_jti = jti or secrets.token_urlsafe(32); expires = datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    payload = _claims(data, "refresh", timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS), token_jti)
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM), token_jti, expires

def decode_token(token: str):
    try:
        return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.JWT_ALGORITHM], issuer=settings.JWT_ISSUER, audience=settings.JWT_AUDIENCE)
    except JWTError:
        return None

def get_user_id(token: str):
    payload = decode_token(token); return payload.get("sub") if payload else None
def is_refresh_token(token: str) -> bool:
    payload = decode_token(token); return bool(payload and payload.get("type") == "refresh")
def is_access_token(token: str) -> bool:
    payload = decode_token(token); return bool(payload and payload.get("type") == "access")
