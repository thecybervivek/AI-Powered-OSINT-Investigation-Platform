from backend.app.core.intelligence.correlation import correlate
from backend.app.core.intelligence.correlation import correlate_by_category
from backend.app.core.intelligence.correlation import RelationshipCategory
from backend.app.utils.evidence_correlation import InvestigationRef


def test_domain_correlation_categorized_as_infrastructure():

    refs = [
        InvestigationRef("a", "user@example.com", "email"),
        InvestigationRef("b", "example.com", "domain"),
    ]

    result = correlate(refs)

    assert len(result) == 1
    assert result[0].relationship_category == RelationshipCategory.INFRASTRUCTURE
    assert result[0].asserts_identity is False


def test_same_email_target_surfaces_identity_and_infrastructure_correlations():

    refs = [
        InvestigationRef("a", "user@example.com", "email"),
        InvestigationRef("b", "user@example.com", "breach"),
    ]

    result = correlate(refs)
    categories = {c.entity_type: c.relationship_category for c in result}

    assert categories["email"] == RelationshipCategory.IDENTITY
    assert categories["domain"] == RelationshipCategory.INFRASTRUCTURE


def test_shared_username_never_asserts_identity():
    """
    Core safeguard: 'same username across two platforms' must never be
    reported as a confirmed identity match.
    """

    refs = [
        InvestigationRef("a", "johndoe", "username"),
        InvestigationRef("b", "johndoe", "username"),
    ]

    result = correlate(refs)

    assert len(result) >= 1

    for correlation in result:
        assert correlation.asserts_identity is False
        assert "not" in correlation.caveat.lower()
        assert "person" in correlation.caveat.lower() or "match" in correlation.caveat.lower()


def test_correlate_by_category_filters():

    refs = [
        InvestigationRef("a", "1.2.3.4", "ip_address"),
        InvestigationRef("b", "1.2.3.4", "threat_intelligence"),
    ]

    assert correlate_by_category(refs, RelationshipCategory.IDENTITY) == []
    assert len(correlate_by_category(refs, RelationshipCategory.INFRASTRUCTURE)) == 1


def test_to_dict_always_includes_safeguard_fields():

    refs = [InvestigationRef("a", "1.2.3.4", "ip_address"), InvestigationRef("b", "1.2.3.4", "malware")]
    result = correlate(refs)

    assert result
    d = result[0].to_dict()
    assert d["asserts_identity"] is False
    assert "caveat" in d and d["caveat"]
