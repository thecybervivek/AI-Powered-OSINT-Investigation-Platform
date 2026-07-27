import os
import uuid

os.environ.setdefault("DATABASE_URL", "sqlite:///./test_platform.db")
os.environ.setdefault("ENVIRONMENT", "testing")
os.environ.setdefault("TRUSTED_HOSTS", '["localhost","127.0.0.1","testserver"]')

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
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


@pytest.fixture(scope="session", autouse=True)
def _setup_database():

    Base.metadata.create_all(bind=engine)

    yield

    Base.metadata.drop_all(bind=engine)

    # Close pooled SQLite connections before deleting the database file.
    engine.dispose()

    if os.path.exists("test_platform.db"):
        os.remove("test_platform.db")


def _override_get_db():

    db = TestingSessionLocal()

    try:
        yield db

    finally:
        db.close()


app.dependency_overrides[get_db] = _override_get_db


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


@pytest.fixture
def db_session():

    db = TestingSessionLocal()

    yield db

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