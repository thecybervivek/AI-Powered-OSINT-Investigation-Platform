from fastapi import Depends
from fastapi import HTTPException
from fastapi import status

from fastapi.security import OAuth2PasswordBearer

from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.core.security import decode_token
from backend.app.db.database import get_db
from backend.app.models.user import User
from backend.app.models.user import UserRole


oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/api/v1/login",
)


# ==========================================================
# Current User
# ==========================================================

def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials.",
        headers={
            "WWW-Authenticate": "Bearer",
        },
    )

    payload = decode_token(token)
    if payload is None or payload.get("type") != "access" or not payload.get("sub"):
        raise credentials_exception
    user_id = payload["sub"]

    user = (
        db.query(User)
        .filter(User.id == user_id)
        .first()
    )

    if user is None:
        raise credentials_exception

    if not user.is_active:

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user.",
        )

    return user


# ==========================================================
# Active User
# ==========================================================

def require_active_user(
    current_user: User = Depends(get_current_user),
) -> User:

    if not current_user.is_active:

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user.",
        )

    return current_user


# ==========================================================
# Admin User
# ==========================================================

def require_admin(
    current_user: User = Depends(get_current_user),
) -> User:

    if current_user.role != UserRole.ADMIN:

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required.",
        )

    return current_user


# ==========================================================
# Super User
# ==========================================================

def require_superuser(
    current_user: User = Depends(get_current_user),
) -> User:

    if not current_user.is_superuser:

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Superuser access required.",
        )

    return current_user