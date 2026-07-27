from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.core.dependencies import get_current_user
from backend.app.core.rate_limit import limiter
from backend.app.db.database import get_db
from backend.app.models.user import User
from backend.app.schemas.user import AccessTokenResponse, UserCreate, UserResponse
from backend.app.services.auth_service import AuthService

router = APIRouter()


def _set_refresh_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=settings.REFRESH_COOKIE_NAME,
        value=token,
        max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
        httponly=True,
        secure=settings.REFRESH_COOKIE_SECURE,
        samesite=settings.REFRESH_COOKIE_SAMESITE,
        path=settings.REFRESH_COOKIE_PATH,
    )


def _clear_refresh_cookie(response: Response) -> None:
    response.delete_cookie(
        key=settings.REFRESH_COOKIE_NAME,
        path=settings.REFRESH_COOKIE_PATH,
        secure=settings.REFRESH_COOKIE_SECURE,
        httponly=True,
        samesite=settings.REFRESH_COOKIE_SAMESITE,
    )


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit(settings.RATE_LIMIT_REGISTER)
def register(request: Request, user: UserCreate, db: Session = Depends(get_db)):
    try:
        return AuthService.register(db, user)
    except ValueError:
        # Do not reveal whether email or username already exists.
        raise HTTPException(status_code=400, detail="Registration could not be completed.")


@router.post("/login", response_model=AccessTokenResponse)
@limiter.limit(settings.RATE_LIMIT_LOGIN)
def login(request: Request, response: Response, form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = AuthService.authenticate(db, form_data.username, form_data.password)
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid username or password.")
    tokens = AuthService.create_tokens(db, user)
    _set_refresh_cookie(response, tokens.refresh_token)
    return AccessTokenResponse(access_token=tokens.access_token, token_type=tokens.token_type)


@router.get("/me", response_model=UserResponse)
def read_current_user(current_user: User = Depends(get_current_user)):
    return current_user


@router.post("/refresh", response_model=AccessTokenResponse)
@limiter.limit(settings.RATE_LIMIT_REFRESH)
def refresh_token(request: Request, response: Response, db: Session = Depends(get_db)):
    refresh = request.cookies.get(settings.REFRESH_COOKIE_NAME)
    if not refresh:
        raise HTTPException(status_code=401, detail="Invalid refresh session.")
    tokens = AuthService.refresh_tokens(db, refresh)
    if tokens is None:
        _clear_refresh_cookie(response)
        raise HTTPException(status_code=401, detail="Invalid refresh session.")
    _set_refresh_cookie(response, tokens.refresh_token)
    return AccessTokenResponse(access_token=tokens.access_token, token_type=tokens.token_type)


@router.post("/logout")
def logout(request: Request, response: Response, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    refresh = request.cookies.get(settings.REFRESH_COOKIE_NAME)
    if refresh:
        AuthService.revoke_refresh_token(db, refresh, current_user.id)
    _clear_refresh_cookie(response)
    return {"success": True, "message": "Logged out successfully."}
