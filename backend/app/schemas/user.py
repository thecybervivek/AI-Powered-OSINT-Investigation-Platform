from datetime import datetime

from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import EmailStr
from pydantic import Field

from backend.app.models.user import UserRole


# ==========================================================
# Base Schema
# ==========================================================

class UserBase(BaseModel):

    full_name: str = Field(
        min_length=2,
        max_length=150,
    )

    username: str = Field(
        min_length=3,
        max_length=50,
    )

    email: EmailStr


# ==========================================================
# Create User
# ==========================================================

class UserCreate(UserBase):

    password: str = Field(
        min_length=8,
        max_length=128,
    )


# ==========================================================
# Login
# ==========================================================

class UserLogin(BaseModel):

    username: str

    password: str


# ==========================================================
# Update User
# ==========================================================

class UserUpdate(BaseModel):

    full_name: str | None = None

    email: EmailStr | None = None

    password: str | None = Field(
        default=None,
        min_length=8,
    )


# ==========================================================
# User Response
# ==========================================================

class UserResponse(UserBase):

    model_config = ConfigDict(
        from_attributes=True,
    )

    id: str

    role: UserRole

    is_active: bool

    is_verified: bool

    is_superuser: bool

    created_at: datetime

    updated_at: datetime


# ==========================================================
# Refresh Token Request
# ==========================================================

class RefreshTokenRequest(BaseModel):

    refresh_token: str


# ==========================================================
# JWT Token
# ==========================================================

class Token(BaseModel):

    access_token: str

    refresh_token: str

    token_type: str = "bearer"


# ==========================================================
# Access Token Response
# ==========================================================

class AccessTokenResponse(BaseModel):

    access_token: str

    token_type: str = "bearer"


# ==========================================================
# Token Payload
# ==========================================================

class TokenPayload(BaseModel):

    sub: str

    type: str

    exp: int