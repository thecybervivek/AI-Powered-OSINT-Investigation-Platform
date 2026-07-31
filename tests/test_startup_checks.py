import os
import subprocess
import sys
import tempfile

import pytest

from backend.app.core.startup_checks import StartupDependencyError
from backend.app.core.startup_checks import verify_startup_dependencies


def test_startup_checks_pass_against_a_properly_migrated_database():
    """
    verify_startup_dependencies() (specifically its migration-state
    check) expects a database that was actually brought up to date via
    `alembic upgrade head` - which is deliberately NOT how the shared
    conftest.py test database is built (it uses
    Base.metadata.create_all() for test speed/simplicity and has no
    Alembic revision stamped). This test exercises the real,
    production-equivalent path instead: run actual migrations against
    a throwaway SQLite file, then verify the startup check passes.
    """

    with tempfile.TemporaryDirectory() as tmp_dir:

        db_path = os.path.join(tmp_dir, "startup_check_test.db")
        db_url = f"sqlite:///{db_path}"

        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

        subprocess.run(
            [sys.executable, "-m", "alembic", "upgrade", "head"],
            cwd=repo_root,
            env={**os.environ, "DATABASE_URL": db_url},
            check=True,
            capture_output=True,
        )

        # Re-point the already-imported engine/settings at the freshly
        # migrated database for the duration of this check, then
        # verify_startup_dependencies() should pass end to end.
        from backend.app.core import startup_checks as module
        from sqlalchemy import create_engine

        fresh_engine = create_engine(db_url)

        original_engine = module.engine
        module.engine = fresh_engine

        try:
            verify_startup_dependencies()  # must not raise
        finally:
            module.engine = original_engine
            fresh_engine.dispose()


def test_startup_check_fails_fast_on_unreachable_database(monkeypatch):

    from backend.app.core import startup_checks as module

    monkeypatch.setattr(module, "database_health", lambda: False)

    with pytest.raises(StartupDependencyError, match="database is not reachable"):
        module.verify_startup_dependencies()


def test_startup_check_fails_fast_on_unreachable_required_redis(monkeypatch):

    from backend.app.core import startup_checks as module
    from backend.app.core.config import settings

    monkeypatch.setattr(settings, "RATE_LIMIT_BACKEND", "redis")
    monkeypatch.setattr(settings, "REDIS_HOST", "127.0.0.1")
    monkeypatch.setattr(settings, "REDIS_PORT", 1)  # nothing listens here

    with pytest.raises(StartupDependencyError, match="Redis"):
        module._check_redis()


def test_startup_check_skips_redis_when_not_required(monkeypatch):

    from backend.app.core import startup_checks as module
    from backend.app.core.config import settings

    monkeypatch.setattr(settings, "RATE_LIMIT_BACKEND", "memory")

    module._check_redis()  # must not raise / must not even attempt a connection


def test_startup_check_detects_migration_mismatch(monkeypatch):

    from backend.app.core import startup_checks as module

    class _FakeScriptDir:
        def get_current_head(self):
            return "some-future-revision"

    monkeypatch.setattr(
        module.ScriptDirectory, "from_config", lambda cfg: _FakeScriptDir()
    )

    class _FakeContext:
        def get_current_revision(self):
            return "an-older-revision"

    monkeypatch.setattr(
        module.MigrationContext,
        "configure",
        lambda connection: _FakeContext(),
    )

    with pytest.raises(StartupDependencyError, match="does not match"):
        module._check_migration_state()
