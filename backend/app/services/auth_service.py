from sqlalchemy.orm import Session

from backend.app.core.security import create_access_token
from backend.app.core.security import create_refresh_token
from backend.app.core.security import get_user_id
from backend.app.core.security import hash_password
from backend.app.core.security import is_refresh_token
from backend.app.core.security import verify_password
from backend.app.models.user import User
from backend.app.schemas.user import Token
from backend.app.schemas.user import UserCreate


class AuthService:

    @staticmethod
    def get_user_by_email(
        db: Session,
        email: str,
    ) -> User | None:

        return (
            db.query(User)
            .filter(User.email == email)
            .first()
        )

    @staticmethod
    def get_user_by_username(
        db: Session,
        username: str,
    ) -> User | None:

        return (
            db.query(User)
            .filter(User.username == username)
            .first()
        )

    @staticmethod
    def get_user_by_id(
        db: Session,
        user_id: str,
    ) -> User | None:

        return (
            db.query(User)
            .filter(User.id == user_id)
            .first()
        )

    @staticmethod
    def register(
        db: Session,
        user_data: UserCreate,
    ) -> User:

        existing_email = AuthService.get_user_by_email(
            db,
            user_data.email,
        )

        if existing_email:
            raise ValueError(
                "Email already registered."
            )

        existing_username = AuthService.get_user_by_username(
            db,
            user_data.username,
        )

        if existing_username:
            raise ValueError(
                "Username already exists."
            )

        user = User(
            full_name=user_data.full_name,
            username=user_data.username,
            email=user_data.email,
            hashed_password=hash_password(
                user_data.password,
            ),
        )

        db.add(user)
        db.commit()
        db.refresh(user)

        return user

    @staticmethod
    def authenticate(
        db: Session,
        username: str,
        password: str,
    ) -> User | None:

        user = AuthService.get_user_by_username(
            db,
            username,
        )

        if user is None:
            return None

        if not user.is_active:
            return None

        if not verify_password(
            password,
            user.hashed_password,
        ):
            return None

        return user

    @staticmethod
    def create_tokens(
        user: User,
    ) -> Token:

        access_token = create_access_token(
            {
                "sub": user.id,
            }
        )

        refresh_token = create_refresh_token(
            {
                "sub": user.id,
            }
        )

        return Token(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
        )

    @staticmethod
    def refresh_access_token(
        db: Session,
        refresh_token: str,
    ) -> str | None:

        if not is_refresh_token(refresh_token):
            return None

        user_id = get_user_id(refresh_token)

        if user_id is None:
            return None

        user = AuthService.get_user_by_id(
            db,
            user_id,
        )

        if user is None:
            return None

        if not user.is_active:
            return None

        return create_access_token(
            {
                "sub": user.id,
            }
        )