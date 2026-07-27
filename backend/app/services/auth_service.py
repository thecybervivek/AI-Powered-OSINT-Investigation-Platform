from datetime import datetime, timezone
from sqlalchemy.orm import Session
from backend.app.core.security import create_access_token, create_refresh_token, decode_token, hash_jti, hash_password, verify_password
from backend.app.models.refresh_session import RefreshSession
from backend.app.models.user import User
from backend.app.schemas.user import Token, UserCreate

class AuthService:
    @staticmethod
    def get_user_by_email(db, email): return db.query(User).filter(User.email == email).first()
    @staticmethod
    def get_user_by_username(db, username): return db.query(User).filter(User.username == username).first()
    @staticmethod
    def get_user_by_id(db, user_id): return db.query(User).filter(User.id == user_id).first()
    @staticmethod
    def register(db: Session, user_data: UserCreate) -> User:
        if AuthService.get_user_by_email(db, user_data.email): raise ValueError("Email already registered.")
        if AuthService.get_user_by_username(db, user_data.username): raise ValueError("Username already exists.")
        user=User(full_name=user_data.full_name, username=user_data.username, email=user_data.email, hashed_password=hash_password(user_data.password)); db.add(user); db.commit(); db.refresh(user); return user
    @staticmethod
    def authenticate(db, username, password):
        user=AuthService.get_user_by_username(db, username)
        return user if user and user.is_active and verify_password(password, user.hashed_password) else None
    @staticmethod
    def create_tokens(db: Session, user: User) -> Token:
        access=create_access_token({"sub": user.id}); refresh,jti,expires=create_refresh_token({"sub":user.id})
        db.add(RefreshSession(user_id=user.id,jti_hash=hash_jti(jti),expires_at=expires)); db.commit()
        return Token(access_token=access,refresh_token=refresh,token_type="bearer")
    @staticmethod
    def refresh_tokens(db: Session, refresh_token: str) -> Token | None:
        payload=decode_token(refresh_token)
        if not payload or payload.get("type")!="refresh" or not payload.get("jti") or not payload.get("sub"): return None
        user=AuthService.get_user_by_id(db,payload["sub"])
        if not user or not user.is_active: return None
        session=db.query(RefreshSession).filter(RefreshSession.jti_hash==hash_jti(payload["jti"])).first()
        now=datetime.now(timezone.utc)
        if not session or session.revoked or session.expires_at.replace(tzinfo=timezone.utc) <= now:
            # Reuse of a rotated token revokes every outstanding session for this user.
            if session and session.replaced_by_jti_hash:
                db.query(RefreshSession).filter(RefreshSession.user_id==user.id).update({RefreshSession.revoked: True}); db.commit()
            return None
        new_refresh,new_jti,expires=create_refresh_token({"sub":user.id}); new_hash=hash_jti(new_jti)
        session.revoked=True; session.replaced_by_jti_hash=new_hash
        db.add(RefreshSession(user_id=user.id,jti_hash=new_hash,expires_at=expires)); db.commit()
        return Token(access_token=create_access_token({"sub":user.id}),refresh_token=new_refresh,token_type="bearer")
    @staticmethod
    def revoke_refresh_token(db: Session, refresh_token: str, user_id: str) -> bool:
        payload=decode_token(refresh_token)
        if not payload or payload.get("type")!="refresh" or payload.get("sub")!=user_id or not payload.get("jti"): return False
        session=db.query(RefreshSession).filter(RefreshSession.jti_hash==hash_jti(payload["jti"]), RefreshSession.user_id==user_id).first()
        if not session: return False
        session.revoked=True; db.commit(); return True
    @staticmethod
    def revoke_all_sessions(db: Session, user_id: str) -> None:
        db.query(RefreshSession).filter(RefreshSession.user_id==user_id).update({RefreshSession.revoked: True}); db.commit()
