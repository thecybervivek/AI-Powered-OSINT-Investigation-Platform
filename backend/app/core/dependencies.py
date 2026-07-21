from jose import JWTError
from jose import jwt

from fastapi import Depends
from fastapi import HTTPException
from fastapi import status

from fastapi.security import OAuth2PasswordBearer

from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.db.database import get_db
from backend.app.models.user import User


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

    try:

        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[
                settings.JWT_ALGORITHM,
            ],
        )

        user_id = payload.get("sub")

        token_type = payload.get("type")

        if user_id is None:
            raise credentials_exception

        if token_type != "access":
            raise credentials_exception

    except JWTError:

        raise credentials_exception

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

    if str(current_user.role).lower() != "admin":

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