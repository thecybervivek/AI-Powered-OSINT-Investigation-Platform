from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.app.core.config import settings
from backend.app.models.base import BaseModel

# Import all models so SQLAlchemy registers them
from backend.app.models import *


# ==========================================================
# SQLAlchemy Engine
# ==========================================================

engine = create_engine(
    settings.DATABASE_URL,
    echo=settings.DATABASE_ECHO,
    future=True,
)


# ==========================================================
# Session Factory
# ==========================================================

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
)


# ==========================================================
# Base Model
# ==========================================================

Base = BaseModel


# ==========================================================
# Dependency
# ==========================================================

def get_db():

    db = SessionLocal()

    try:
        yield db

    finally:
        db.close()


# ==========================================================
# Database Utilities
# ==========================================================

def create_database():

    Base.metadata.create_all(bind=engine)


def drop_database():

    Base.metadata.drop_all(bind=engine)


def recreate_database():

    drop_database()
    create_database()


# ==========================================================
# Database Health Check
# ==========================================================

def database_health():

    try:

        with engine.connect() as connection:
            connection.exec_driver_sql("SELECT 1")

        return True

    except Exception:
        return False