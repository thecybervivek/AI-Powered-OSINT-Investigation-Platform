import re

from backend.app.core.intelligence.investigation_registry import INVESTIGATION_TYPE_REGISTRY


def _real_mounted_prefixes() -> set[str]:
    """
    Parses router.py's actual source text for literal
    `prefix="/investigations/..."` arguments, rather than importing the
    module (which pulls in every endpoint file's FastAPI/SQLAlchemy
    dependencies) - this keeps the check runnable in any environment
    and ties it to the literal, auditable source rather than runtime
    behavior that could itself be mocked.
    """

    router_text = open("backend/app/api/v1/router.py", encoding="utf-8").read()

    return set(re.findall(r'prefix="(/investigations/[^"]+)"', router_text))


def test_every_claimed_router_prefix_is_actually_mounted():
    """
    The exact check that would have caught the 'metadata' finding
    automatically: a registry entry claiming a router_prefix that
    router.py does not actually register is a lie the registry is
    telling about backend reality.
    """

    real_prefixes = _real_mounted_prefixes()

    for identifier, definition in INVESTIGATION_TYPE_REGISTRY.items():

        if definition.router_prefix is not None:
            assert definition.router_prefix in real_prefixes, (
                f"{identifier} claims router_prefix={definition.router_prefix!r} "
                "but no such prefix is registered in router.py"
            )


def test_metadata_has_no_mounted_router():
    """
    Confirms the Phase 1B audit finding directly: metadata is the one
    investigation type with no backend workflow at all.
    """

    assert INVESTIGATION_TYPE_REGISTRY["metadata"].router_prefix is None


def test_no_other_type_is_missing_a_router():
    """
    Every OTHER investigation type must have a real, mounted router -
    if this ever fails, either a new type was registered without
    wiring its endpoint, or a router was removed without updating the
    registry to reflect the resulting gap honestly.
    """

    missing = [
        identifier
        for identifier, definition in INVESTIGATION_TYPE_REGISTRY.items()
        if identifier != "metadata" and definition.router_prefix is None
    ]

    assert missing == [], missing


def test_no_two_investigation_types_share_a_router_prefix():

    prefixes = [
        d.router_prefix for d in INVESTIGATION_TYPE_REGISTRY.values() if d.router_prefix
    ]

    assert len(prefixes) == len(set(prefixes)), "duplicate router_prefix values found"


def test_real_mounted_prefixes_have_no_unclaimed_orphans_among_investigation_routes():
    """
    The reverse direction: every /investigations/* prefix router.py
    actually mounts should be claimed by some registry entry - an
    unclaimed mounted route is a real backend capability the registry
    doesn't know about at all (the mirror-image of the metadata bug).

    DOCUMENTED EXCEPTION: /investigations/ioc is a real, intentional
    exception - confirmed by reading
    backend/app/services/ioc_service.py, which classifies the submitted
    indicator (IP/domain/email/username/url) and delegates to whichever
    underlying InvestigationType actually handles it
    (`investigation_type=InvestigationType.DOMAIN` etc., set to the
    DETECTED type, never a distinct "ioc" type). It is a dispatcher
    endpoint, not a standalone investigation type, so it correctly has
    no InvestigationType/registry entry of its own. If this allowlist
    ever needs a second entry, that is a signal to re-run the same
    manual audit rather than silently widening it.
    """

    KNOWN_NON_TYPE_DISPATCHER_PREFIXES = {"/investigations/ioc"}

    real_prefixes = _real_mounted_prefixes()
    claimed_prefixes = {
        d.router_prefix for d in INVESTIGATION_TYPE_REGISTRY.values() if d.router_prefix
    }

    unclaimed = real_prefixes - claimed_prefixes - KNOWN_NON_TYPE_DISPATCHER_PREFIXES

    assert unclaimed == set(), (
        f"router.py mounts {unclaimed} but no registry entry claims them, and "
        "they are not in the documented KNOWN_NON_TYPE_DISPATCHER_PREFIXES allowlist"
    )
