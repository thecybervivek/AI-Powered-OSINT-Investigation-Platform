from backend.app.core.intelligence.investigation_registry import INVESTIGATION_TYPE_REGISTRY


def test_capabilities_endpoint_reachable_through_real_router(client):

    response = client.get("/api/v1/capabilities/")

    assert response.status_code == 200


def test_investigation_types_endpoint_reachable_through_real_router(client):

    response = client.get("/api/v1/capabilities/investigation-types")

    assert response.status_code == 200


def test_capabilities_response_schema_and_completeness(client):

    response = client.get("/api/v1/capabilities/")
    payload = response.json()

    assert "capabilities" in payload
    capabilities = payload["capabilities"]

    assert len(capabilities) == len(INVESTIGATION_TYPE_REGISTRY)

    required_fields = {
        "identifier", "label", "category", "production_status",
        "implementation_state", "api_state", "ui_state", "provider_state",
        "is_production_ready", "discrepancy_warnings", "availability",
        "unavailable_reason", "input_mode",
    }

    for capability in capabilities:
        assert required_fields.issubset(capability.keys()), capability.keys()


def test_capability_identifiers_are_unique(client):

    response = client.get("/api/v1/capabilities/")
    capabilities = response.json()["capabilities"]

    identifiers = [c["identifier"] for c in capabilities]

    assert len(identifiers) == len(set(identifiers))


def test_response_matches_registry_truth_for_metadata(client):
    """The unavailable capability must be represented honestly through the real HTTP response, not just in-process."""

    response = client.get("/api/v1/capabilities/")
    capabilities = {c["identifier"]: c for c in response.json()["capabilities"]}

    metadata = capabilities["metadata"]

    assert metadata["availability"] == "coming_soon"
    assert metadata["unavailable_reason"] is not None
    assert metadata["is_production_ready"] is False


def test_response_matches_registry_truth_for_username(client):

    response = client.get("/api/v1/capabilities/")
    capabilities = {c["identifier"]: c for c in response.json()["capabilities"]}

    username = capabilities["username"]

    assert username["availability"] == "available"
    assert username["unavailable_reason"] is None
    assert username["is_production_ready"] is True


def test_no_sensitive_configuration_leaks_into_response(client):

    response = client.get("/api/v1/capabilities/")
    serialized = response.text.lower()

    for forbidden in ("api_key", "apikey", "secret", "password", "token", "/home/", "/mnt/"):
        assert forbidden not in serialized, forbidden


def test_response_ordering_is_deterministic_across_requests(client):

    first = [c["identifier"] for c in client.get("/api/v1/capabilities/").json()["capabilities"]]
    second = [c["identifier"] for c in client.get("/api/v1/capabilities/").json()["capabilities"]]

    assert first == second


def test_investigation_types_endpoint_exposes_richer_metadata_than_capabilities(client):
    """
    /investigation-types is the fuller registry export (label/category/
    icon/input_type/validation hints) intended to drive the frontend's
    type union/modal - distinct from /capabilities' more focused
    maturity/availability contract.
    """

    response = client.get("/api/v1/capabilities/investigation-types")
    payload = response.json()

    assert "investigation_types" in payload
    types = payload["investigation_types"]

    assert len(types) == len(INVESTIGATION_TYPE_REGISTRY)

    for t in types:
        assert "icon" in t
        assert "validation_hint" in t
        assert "input_mode" in t


def test_capabilities_endpoint_requires_no_authentication(client):
    """Matches the /health endpoint's precedent - capability discovery is public/read-only."""

    response = client.get("/api/v1/capabilities/")

    assert response.status_code != 401
    assert response.status_code != 403
