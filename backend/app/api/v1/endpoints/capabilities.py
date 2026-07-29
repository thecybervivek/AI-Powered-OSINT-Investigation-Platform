from fastapi import APIRouter

from backend.app.core.intelligence.capability_registry import capability_report_as_json
from backend.app.core.intelligence.investigation_registry import registry_as_json_export

router = APIRouter()


@router.get("/")
def list_capabilities():
    """
    Machine-readable capability state for every registered investigation
    type - the single source Account 3's dashboard/New-Investigation UI,
    a README/release-audit script, and this endpoint can all read from,
    so "UI says supported" and "this actually works" can be compared
    instead of drifting independently. Unauthenticated/read-only, same
    precedent as /health.
    """

    return {"capabilities": capability_report_as_json()}


@router.get("/investigation-types")
def list_investigation_types():
    """
    The full Investigation Type Registry export - richer than
    /capabilities (includes label/category/icon/input_type/validation
    hints), intended for driving the frontend's investigation-type
    union/modal directly from this backend registry rather than a
    hand-maintained TypeScript copy.
    """

    return {"investigation_types": registry_as_json_export()}
