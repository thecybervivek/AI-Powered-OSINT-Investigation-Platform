import uuid
from datetime import datetime
from datetime import timezone

from backend.app.models.investigation import Investigation
from backend.app.models.investigation import InvestigationResult
from backend.app.models.investigation import InvestigationStatus
from backend.app.models.investigation import InvestigationType
from backend.app.models.investigation import ModuleResultStatus
from backend.app.models.investigation import RiskLevel
from backend.app.services.mitre_mapping import map_mitre_attack


def _make_investigation(
    db_session,
    user_id: str,
    *,
    investigation_type: InvestigationType,
    target: str,
    risk_score: float,
    risk_level: RiskLevel,
) -> Investigation:

    investigation = Investigation(
        user_id=user_id,
        investigation_type=investigation_type,
        target=target,
        status=InvestigationStatus.COMPLETED,
        risk_score=risk_score,
        risk_level=risk_level,
        summary=f"Test summary for {target}.",
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
    )

    db_session.add(investigation)
    db_session.commit()
    db_session.refresh(investigation)

    return investigation


# ==========================================================
# Authentication
# ==========================================================

def test_generate_report_requires_authentication(client):

    response = client.post(
        "/api/v1/reports/generate",
        json={"investigation_ids": ["some-id"]},
    )

    assert response.status_code == 401


def test_list_reports_requires_authentication(client):

    response = client.get("/api/v1/reports")

    assert response.status_code == 401


# ==========================================================
# Error handling
# ==========================================================

def test_generate_report_rejects_unknown_investigation_id(client, auth_headers):

    response = client.post(
        "/api/v1/reports/generate",
        json={"investigation_ids": [str(uuid.uuid4())]},
        headers=auth_headers,
    )

    assert response.status_code == 404


def test_generate_report_rejects_other_users_investigation(
    client, auth_headers, db_session
):

    other_user_id = str(uuid.uuid4())

    from backend.app.models.user import User

    other_user = User(
        id=other_user_id,
        email=f"other-{uuid.uuid4().hex[:8]}@example.com",
        username=f"other-{uuid.uuid4().hex[:8]}",
        full_name="Other User",
        hashed_password="x",
        is_active=True,
    )
    db_session.add(other_user)
    db_session.commit()

    other_investigation = _make_investigation(
        db_session,
        other_user_id,
        investigation_type=InvestigationType.DOMAIN,
        target="not-mine.com",
        risk_score=5.0,
        risk_level=RiskLevel.LOW,
    )

    response = client.post(
        "/api/v1/reports/generate",
        json={"investigation_ids": [other_investigation.id]},
        headers=auth_headers,
    )

    assert response.status_code == 404


# ==========================================================
# Report generation (end-to-end through the API)
# ==========================================================

def test_generate_report_end_to_end(client, auth_headers, test_user, db_session):

    file_investigation = _make_investigation(
        db_session,
        test_user.id,
        investigation_type=InvestigationType.FILE,
        target="a" * 64,
        risk_score=90.0,
        risk_level=RiskLevel.CRITICAL,
    )

    db_session.add(
        InvestigationResult(
            investigation_id=file_investigation.id,
            source="yara_scan",
            status=ModuleResultStatus.SUCCESS,
            data={
                "matched": True,
                "match_count": 1,
                "matches": [
                    {
                        "rule": "Suspicious_PE_Process_Injection_APIs",
                        "meta": {"severity": "high"},
                    }
                ],
            },
        )
    )
    db_session.commit()

    ip_investigation = _make_investigation(
        db_session,
        test_user.id,
        investigation_type=InvestigationType.IP_ADDRESS,
        target="203.0.113.5",
        risk_score=8.0,
        risk_level=RiskLevel.LOW,
    )

    response = client.post(
        "/api/v1/reports/generate",
        json={
            "investigation_ids": [file_investigation.id, ip_investigation.id],
            "title": "Test Correlated Report",
        },
        headers=auth_headers,
    )

    assert response.status_code == 201

    body = response.json()

    assert body["title"] == "Test Correlated Report"
    assert body["status"] == "completed"
    assert body["ai_engine_used"] == "local_deterministic"
    assert body["risk_level"] == "critical"
    assert body["risk_score"] == 90.0
    assert len(body["indicators_of_compromise"]) == 2
    assert any(
        t["technique_id"] == "T1055" for t in body["mitre_attack_mapping"]
    )
    assert len(body["ai_recommendations"]) >= 1
    assert body["confidence_score"] == 100.0


# ==========================================================
# List + pagination + filtering
# ==========================================================

def test_list_reports_paginated(client, auth_headers, test_user, db_session):

    investigation = _make_investigation(
        db_session,
        test_user.id,
        investigation_type=InvestigationType.DOMAIN,
        target="pagination-test.example",
        risk_score=2.0,
        risk_level=RiskLevel.LOW,
    )

    for i in range(3):

        client.post(
            "/api/v1/reports/generate",
            json={
                "investigation_ids": [investigation.id],
                "title": f"Pagination Report {i}",
            },
            headers=auth_headers,
        )

    response = client.get(
        "/api/v1/reports",
        params={"page": 1, "page_size": 2},
        headers=auth_headers,
    )

    assert response.status_code == 200
    body = response.json()

    assert body["page"] == 1
    assert body["page_size"] == 2
    assert len(body["items"]) == 2
    assert body["total"] >= 3


# ==========================================================
# Get + export formats
# ==========================================================

def test_get_report_json_markdown_pdf(client, auth_headers, test_user, db_session):

    investigation = _make_investigation(
        db_session,
        test_user.id,
        investigation_type=InvestigationType.DOMAIN,
        target="export-test.example",
        risk_score=15.0,
        risk_level=RiskLevel.LOW,
    )

    generate_response = client.post(
        "/api/v1/reports/generate",
        json={"investigation_ids": [investigation.id]},
        headers=auth_headers,
    )

    report_id = generate_response.json()["id"]

    json_response = client.get(
        f"/api/v1/reports/{report_id}",
        headers=auth_headers,
    )
    assert json_response.status_code == 200
    assert json_response.headers["content-type"].startswith("application/json")
    assert json_response.json()["id"] == report_id

    markdown_response = client.get(
        f"/api/v1/reports/{report_id}",
        params={"format": "markdown"},
        headers=auth_headers,
    )
    assert markdown_response.status_code == 200
    assert markdown_response.headers["content-type"].startswith("text/markdown")
    assert markdown_response.text.startswith("#")

    pdf_response = client.get(
        f"/api/v1/reports/{report_id}",
        params={"format": "pdf"},
        headers=auth_headers,
    )
    assert pdf_response.status_code == 200
    assert pdf_response.headers["content-type"] == "application/pdf"
    assert pdf_response.content[:5] == b"%PDF-"


def test_get_nonexistent_report_returns_404(client, auth_headers):

    response = client.get(
        f"/api/v1/reports/{uuid.uuid4()}",
        headers=auth_headers,
    )

    assert response.status_code == 404


# ==========================================================
# Delete
# ==========================================================

def test_delete_report(client, auth_headers, test_user, db_session):

    investigation = _make_investigation(
        db_session,
        test_user.id,
        investigation_type=InvestigationType.DOMAIN,
        target="delete-test.example",
        risk_score=1.0,
        risk_level=RiskLevel.LOW,
    )

    generate_response = client.post(
        "/api/v1/reports/generate",
        json={"investigation_ids": [investigation.id]},
        headers=auth_headers,
    )
    report_id = generate_response.json()["id"]

    delete_response = client.delete(
        f"/api/v1/reports/{report_id}",
        headers=auth_headers,
    )
    assert delete_response.status_code == 204

    get_response = client.get(
        f"/api/v1/reports/{report_id}",
        headers=auth_headers,
    )
    assert get_response.status_code == 404


def test_delete_nonexistent_report_returns_404(client, auth_headers):

    response = client.delete(
        f"/api/v1/reports/{uuid.uuid4()}",
        headers=auth_headers,
    )

    assert response.status_code == 404


# ==========================================================
# AI fallback (never fails even when OpenAI is configured but unreachable)
# ==========================================================

def test_ai_engine_falls_back_when_openai_unreachable(
    client, auth_headers, test_user, db_session, monkeypatch
):

    from backend.app.core.config import settings

    monkeypatch.setattr(settings, "OPENAI_API_KEY", "sk-fake-key-network-blocked")

    investigation = _make_investigation(
        db_session,
        test_user.id,
        investigation_type=InvestigationType.DOMAIN,
        target="fallback-test.example",
        risk_score=3.0,
        risk_level=RiskLevel.LOW,
    )

    response = client.post(
        "/api/v1/reports/generate",
        json={"investigation_ids": [investigation.id]},
        headers=auth_headers,
    )

    assert response.status_code == 201

    body = response.json()

    # Sandbox has no network egress to api.openai.com, so this call fails
    # and MUST fall back rather than error the whole report out.
    assert body["status"] == "completed"
    assert body["ai_engine_used"] == "local_deterministic"
    assert body["executive_summary"]


# ==========================================================
# MITRE mapping (pure unit tests)
# ==========================================================

def test_mitre_mapping_detects_process_injection():

    evidence = [
        {
            "investigation_type": "file",
            "source": "yara_scan",
            "status": "success",
            "data": {
                "matches": [
                    {"rule": "Suspicious_PE_Process_Injection_APIs"},
                ]
            },
        }
    ]

    mapped = map_mitre_attack(evidence)

    assert any(m["technique_id"] == "T1055" for m in mapped)


def test_mitre_mapping_empty_for_clean_evidence():

    evidence = [
        {
            "investigation_type": "domain",
            "source": "whois",
            "status": "success",
            "data": {"registrar": "Example Registrar"},
        }
    ]

    mapped = map_mitre_attack(evidence)

    assert mapped == []


def test_mitre_mapping_deduplicates_technique_across_multiple_sources():

    evidence = [
        {
            "investigation_type": "file",
            "source": "malwarebazaar",
            "status": "success",
            "data": {"known_to_malwarebazaar": True},
        },
        {
            "investigation_type": "file",
            "source": "virustotal_file",
            "status": "success",
            "data": {"analysis_stats": {"malicious": 5}},
        },
    ]

    mapped = map_mitre_attack(evidence)

    technique_ids = [m["technique_id"] for m in mapped]

    assert technique_ids.count("T1588.001") == 1
    assert len(mapped[0]["evidence_sources"]) == 2


# ==========================================================
# Investigation History (cross-module list/get/delete)
# ==========================================================

def test_list_investigations_requires_authentication(client):

    response = client.get("/api/v1/investigations")

    assert response.status_code == 401


def test_list_investigations_paginated_and_filtered(
    client, auth_headers, test_user, db_session
):

    _make_investigation(
        db_session,
        test_user.id,
        investigation_type=InvestigationType.DOMAIN,
        target="history-test-1.example",
        risk_score=1.0,
        risk_level=RiskLevel.LOW,
    )
    _make_investigation(
        db_session,
        test_user.id,
        investigation_type=InvestigationType.IP_ADDRESS,
        target="198.51.100.7",
        risk_score=1.0,
        risk_level=RiskLevel.LOW,
    )

    response = client.get(
        "/api/v1/investigations",
        params={"type": "domain"},
        headers=auth_headers,
    )

    assert response.status_code == 200
    body = response.json()

    assert body["total"] >= 1
    assert all(item["investigation_type"] == "domain" for item in body["items"])


def test_get_and_delete_investigation(client, auth_headers, test_user, db_session):

    investigation = _make_investigation(
        db_session,
        test_user.id,
        investigation_type=InvestigationType.DOMAIN,
        target="delete-history-test.example",
        risk_score=1.0,
        risk_level=RiskLevel.LOW,
    )

    get_response = client.get(
        f"/api/v1/investigations/{investigation.id}",
        headers=auth_headers,
    )
    assert get_response.status_code == 200
    assert get_response.json()["target"] == "delete-history-test.example"

    delete_response = client.delete(
        f"/api/v1/investigations/{investigation.id}",
        headers=auth_headers,
    )
    assert delete_response.status_code == 204

    get_after_delete = client.get(
        f"/api/v1/investigations/{investigation.id}",
        headers=auth_headers,
    )
    assert get_after_delete.status_code == 404
