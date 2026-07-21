from fastapi import APIRouter
from fastapi import Depends
from fastapi import HTTPException
from fastapi import status
from fastapi.security import OAuth2PasswordRequestForm

from sqlalchemy.orm import Session

from backend.app.core.dependencies import get_current_user
from backend.app.db.database import get_db
from backend.app.models.user import User
from backend.app.schemas.user import AccessTokenResponse
from backend.app.schemas.user import RefreshTokenRequest
from backend.app.schemas.user import Token
from backend.app.schemas.user import UserCreate
from backend.app.schemas.user import UserResponse
from backend.app.services.auth_service import AuthService

router = APIRouter()


# ==========================================================
# Register
# ==========================================================

@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
)
def register(
    user: UserCreate,
    db: Session = Depends(get_db),
):

    try:

        created_user = AuthService.register(
            db,
            user,
        )

        return created_user

    except ValueError as error:

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(error),
        )


# ==========================================================
# Login
# ==========================================================

@router.post(
    "/login",
    response_model=Token,
)
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):

    user = AuthService.authenticate(
        db,
        form_data.username,
        form_data.password,
    )

    if user is None:

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
        )

    return AuthService.create_tokens(user)


# ==========================================================
# Get Current User
# ==========================================================

@router.get(
    "/me",
    response_model=UserResponse,
)
def read_current_user(
    current_user: User = Depends(get_current_user),
):

    return current_user


# ==========================================================
# Refresh Token
# ==========================================================

@router.post(
    "/refresh",
    response_model=AccessTokenResponse,
)
def refresh_token(
    request: RefreshTokenRequest,
    db: Session = Depends(get_db),
):

    access_token = AuthService.refresh_access_token(
        db,
        request.refresh_token,
    )

    if access_token is None:

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token.",
        )

    return AccessTokenResponse(
        access_token=access_token,
    )


# ==========================================================
# Logout
# ==========================================================

@router.post(
    "/logout",
)
def logout(
    current_user: User = Depends(get_current_user),
):

    return {
        "success": True,
        "message": "Logged out successfully. Please remove your access and refresh tokens from the client.",
    }