import logging
from pathlib import Path

from alembic.config import Config as AlembicConfig
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory

from backend.app.core.config import settings
from backend.app.core.redis_health import redis_health
from backend.app.core.redis_health import redis_is_required
from backend.app.db.database import database_health
from backend.app.db.database import engine

logger = logging.getLogger("app.startup")


class StartupDependencyError(RuntimeError):
    """
    Raised when a mandatory dependency is unavailable at boot. Distinct
    from a generic RuntimeError so deployment tooling can special-case
    it (e.g. distinguish "app has a bug" from "app's dependencies
    aren't up yet") if needed, while still being a fatal error either
    way - the process must not continue starting.
    """


def _check_database() -> None:

    if database_health():
        logger.info("Startup check: database reachable.")
        return

    raise StartupDependencyError(
        "Startup check FAILED: database is not reachable. Verify "
        "DATABASE_URL is correct and the database server is running "
        "and accepting connections before starting this service."
    )


def _check_redis() -> None:

    if not redis_is_required():
        logger.info(
            "Startup check: Redis not required "
            "(RATE_LIMIT_BACKEND=%r).",
            settings.RATE_LIMIT_BACKEND,
        )
        return

    # redis_health() is async (used by /ready on the running event
    # loop); at startup we don't have one yet, so this check uses a
    # short synchronous ping instead - same policy, different context.
    import redis as redis_sync

    try:
        client = redis_sync.Redis(
            host=settings.REDIS_HOST,
            port=settings.REDIS_PORT,
            password=settings.REDIS_PASSWORD or None,
            db=settings.REDIS_DB,
            socket_connect_timeout=2.0,
            socket_timeout=2.0,
        )
        client.ping()
        client.close()

    except Exception as error:

        raise StartupDependencyError(
            f"Startup check FAILED: RATE_LIMIT_BACKEND=redis but Redis "
            f"at {settings.REDIS_HOST}:{settings.REDIS_PORT} is not "
            f"reachable ({error.__class__.__name__}: {error}). Either "
            f"start Redis, or set RATE_LIMIT_BACKEND=memory for "
            f"non-production use."
        ) from error

    logger.info("Startup check: Redis reachable.")


def _check_migration_state() -> None:
    """
    Compares the database's current Alembic revision against the
    latest revision available in alembic/versions/. A mismatch means
    the code was deployed without running migrations (or migrations
    were run against a different database) - a common, confusing
    class of production incident that's cheap to catch at boot instead
    of as a mysterious column-not-found error on the first request
    that touches the missing schema.
    """

    try:
        repo_root = Path(__file__).resolve().parent.parent.parent.parent
        alembic_cfg = AlembicConfig(str(repo_root / "alembic.ini"))
        alembic_cfg.set_main_option(
            "script_location", str(repo_root / "alembic")
        )

        script_dir = ScriptDirectory.from_config(alembic_cfg)
        head_revision = script_dir.get_current_head()

        with engine.connect() as connection:
            context = MigrationContext.configure(connection)
            current_revision = context.get_current_revision()

    except Exception as error:
        # This check is a best-effort diagnostic, not itself a
        # mandatory dependency - if Alembic's own introspection fails
        # (e.g. unusual DB state), log it clearly but don't block
        # startup on the diagnostic tool itself.
        logger.warning(
            "Startup check: could not determine migration state: %s",
            error,
        )
        return

    if current_revision != head_revision:

        raise StartupDependencyError(
            f"Startup check FAILED: database schema revision "
            f"({current_revision!r}) does not match the latest "
            f"migration ({head_revision!r}). Run "
            f"'alembic upgrade head' against this database before "
            f"starting the application."
        )

    logger.info(
        "Startup check: database schema up to date (revision %s).",
        current_revision,
    )


def verify_startup_dependencies() -> None:
    """
    Fail-fast startup validation. Called once from the application
    lifespan, before the app begins accepting traffic. Verifies actual
    dependency AVAILABILITY (real connections), not just that config
    strings are non-empty - config validation already happens
    separately in core/config.py's production validator.

    Any failure raises StartupDependencyError, which is intentionally
    allowed to propagate out of the lifespan context manager: uvicorn
    will then exit non-zero with the clear message logged above,
    rather than the process starting up "successfully" and only
    failing on the first real request (or worse, serving requests it
    can't actually fulfill).
    """

    logger.info("Running startup dependency checks...")

    _check_database()
    _check_redis()
    _check_migration_state()

    logger.info("All startup dependency checks passed.")
