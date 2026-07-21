from datetime import datetime
from datetime import timedelta
from datetime import timezone

from jose import JWTError
from jose import jwt

from passlib.context import CryptContext

from backend.app.core.config import settings


# ==========================================================
# Password Hashing
# ==========================================================

pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
)


def hash_password(password: str) -> str:

    return pwd_context.hash(password)


def verify_password(
    plain_password: str,
    hashed_password: str,
) -> bool:

    return pwd_context.verify(
        plain_password,
        hashed_password,
    )


# ==========================================================
# JWT Token
# ==========================================================

def create_access_token(
    data: dict,
    expires_delta: timedelta | None = None,
) -> str:

    to_encode = data.copy()

    if expires_delta:

        expire = datetime.now(
            timezone.utc,
        ) + expires_delta

    else:

        expire = datetime.now(
            timezone.utc,
        ) + timedelta(
            minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES,
        )

    to_encode.update(
        {
            "exp": expire,
            "type": "access",
        }
    )

    return jwt.encode(
        to_encode,
        settings.SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )


def create_refresh_token(
    data: dict,
) -> str:

    expire = datetime.now(
        timezone.utc,
    ) + timedelta(
        days=settings.REFRESH_TOKEN_EXPIRE_DAYS,
    )

    payload = data.copy()

    payload.update(
        {
            "exp": expire,
            "type": "refresh",
        }
    )

    return jwt.encode(
        payload,
        settings.SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )


# ==========================================================
# Decode Token
# ==========================================================

def decode_token(
    token: str,
):

    try:

        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[
                settings.JWT_ALGORITHM,
            ],
        )

        return payload

    except JWTError:

        return None


# ==========================================================
# Helpers
# ==========================================================

def get_user_id(
    token: str,
):

    payload = decode_token(token)

    if payload is None:

        return None

    return payload.get("sub")


def is_refresh_token(
    token: str,
) -> bool:

    payload = decode_token(token)

    if payload is None:

        return False

    return payload.get("type") == "refresh"


def is_access_token(
    token: str,
) -> bool:

    payload = decode_token(token)

    if payload is None:

        return False

    return payload.get("type") == "access"