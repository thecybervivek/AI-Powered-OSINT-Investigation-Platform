import pytest

from backend.app.integrations.domain.ssl_integration import SSLCertificateIntegration
from backend.app.integrations.domain.technology_integration import TechnologyDetectionIntegration
from backend.app.models.investigation import ModuleResultStatus
from backend.app.utils.http_client import assert_public_url


def test_ssrf_guard_rejects_loopback_and_metadata():
    for url in ("http://127.0.0.1", "http://169.254.169.254", "http://localhost"):
        with pytest.raises(ValueError):
            assert_public_url(url)


@pytest.mark.anyio
async def test_technology_detection_rejects_private_target_before_http():
    result = await TechnologyDetectionIntegration()._query("127.0.0.1")
    assert result.status == ModuleResultStatus.FAILED
    assert "Unsafe target refused" in (result.error_message or "")


@pytest.mark.anyio
async def test_ssl_integration_rejects_private_target_before_socket():
    result = await SSLCertificateIntegration()._query("127.0.0.1")
    assert result.status == ModuleResultStatus.FAILED
    assert "Unsafe target refused" in (result.error_message or "")

# Release-candidate security regressions
import pytest
from backend.app.utils.http_client import assert_public_url

@pytest.mark.parametrize("url", [
    "http://localhost/", "http://127.0.0.1/", "http://[::1]/",
    "http://10.0.0.1/", "http://172.16.0.1/", "http://192.168.1.1/",
    "http://169.254.169.254/latest/meta-data/", "http://224.0.0.1/",
])
def test_outbound_policy_rejects_non_public_targets(url):
    with pytest.raises(ValueError):
        assert_public_url(url)

def test_outbound_policy_rejects_scheme_confusion():
    with pytest.raises(ValueError):
        assert_public_url("file:///etc/passwd")
