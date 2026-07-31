import os
import uuid
from pathlib import Path

os.environ.setdefault("DATABASE_URL", "sqlite:///./test_platform.db")
os.environ.setdefault("ENVIRONMENT", "testing")
os.environ.setdefault(
    "TRUSTED_HOSTS",
    '["localhost","127.0.0.1","testserver"]',
)

import pytest
from alembic.config import Config as AlembicConfig
from alembic.script import ScriptDirectory
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from backend.app.core.security import create_access_token
from backend.app.core.security import hash_password
from backend.app.db.database import Base
from backend.app.db.database import get_db
from backend.app.main import app
from backend.app.models.user import User


TEST_DATABASE_URL = "sqlite:///./test_platform.db"

engine = create_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
)

TestingSessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
)


def _get_alembic_head_revision() -> str:
    """
    Return the repository's current Alembic head revision.

    Tests create their SQLite schema directly with Base.metadata.create_all(),
    so Alembic does not automatically create/update alembic_version.
    """
    repo_root = Path(__file__).resolve().parent.parent

    alembic_cfg = AlembicConfig(str(repo_root / "alembic.ini"))
    alembic_cfg.set_main_option(
        "script_location",
        str(repo_root / "alembic"),
    )

    script_dir = ScriptDirectory.from_config(alembic_cfg)
    head_revision = script_dir.get_current_head()

    if head_revision is None:
        raise RuntimeError("Unable to determine Alembic head revision.")

    return head_revision


def _stamp_test_database() -> None:
    """
    Mark the directly-created test schema as being at the current
    Alembic revision.

    This does not run migrations. It records the revision expected by
    application startup validation for this disposable test database.
    """
    head_revision = _get_alembic_head_revision()

    with engine.begin() as connection:
        connection.execute(
            text(
                "CREATE TABLE IF NOT EXISTS alembic_version "
                "(version_num VARCHAR(32) NOT NULL)"
            )
        )

        connection.execute(
            text("DELETE FROM alembic_version")
        )

        connection.execute(
            text(
                "INSERT INTO alembic_version (version_num) "
                "VALUES (:revision)"
            ),
            {"revision": head_revision},
        )


@pytest.fixture(scope="session", autouse=True)
def _setup_database():
    Base.metadata.create_all(bind=engine)
    _stamp_test_database()

    yield

    Base.metadata.drop_all(bind=engine)
    engine.dispose()


def _override_get_db():
    db = TestingSessionLocal()

    try:
        yield db

    finally:
        db.close()


app.dependency_overrides[get_db] = _override_get_db


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def db_session():
    db = TestingSessionLocal()

    try:
        yield db

    finally:
        db.close()


@pytest.fixture
def test_user(db_session) -> User:
    unique = uuid.uuid4().hex[:10]

    user = User(
        id=str(uuid.uuid4()),
        email=f"test-{unique}@example.com",
        username=f"testuser-{unique}",
        full_name="Test User",
        hashed_password=hash_password("TestPassword123!"),
        is_active=True,
    )

    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    return user


@pytest.fixture
def auth_headers(test_user: User) -> dict:
    token = create_access_token({"sub": test_user.id})

    return {"Authorization": f"Bearer {token}"}