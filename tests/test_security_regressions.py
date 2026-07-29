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


# ==========================================================
# Additional SSRF bypass regression tests (Phase 0)
#
# These specifically cover cases the suite above did not: alternative
# IP representations that a naive string-based blocklist would miss,
# and - most importantly - the *dynamic* attack surface (redirects,
# DNS rebinding) that a one-shot assert_public_url() call cannot catch
# on its own, which is why request_with_retry() re-validates every
# redirect hop and pins each connection to its validated IP address.
# ==========================================================

import httpx


@pytest.mark.parametrize("url", [
    "http://2130706433/",             # decimal-encoded 127.0.0.1
    "http://0177.0.0.1/",             # octal-encoded 127.0.0.1
    "http://0x7f.0.0.1/",             # hex-encoded 127.0.0.1
    "http://[::ffff:127.0.0.1]/",     # IPv4-mapped IPv6 loopback
    "http://[::ffff:169.254.169.254]/",  # IPv4-mapped IPv6 metadata
])
def test_outbound_policy_rejects_alternative_ip_representations(url):
    with pytest.raises(ValueError):
        assert_public_url(url)


@pytest.mark.anyio
async def test_redirect_to_private_target_is_rejected_not_followed():
    """
    A publicly-resolvable URL whose server responds with a redirect to
    a private/metadata address must never actually be connected to -
    every redirect hop is a new destination and must be revalidated.
    """

    from backend.app.utils.http_client import request_with_retry

    call_count = 0

    class _RedirectToMetadataTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            nonlocal call_count
            call_count += 1
            return httpx.Response(
                302,
                headers={"location": "http://169.254.169.254/latest/meta-data/"},
                request=request,
            )

    async with httpx.AsyncClient(
        transport=_RedirectToMetadataTransport(), timeout=5,
    ) as client:

        with pytest.raises(ValueError):
            await request_with_retry(client, "GET", "http://example.com/")

    # The malicious redirect target must never actually be requested -
    # only the single legitimate initial hop.
    assert call_count == 1


@pytest.mark.anyio
async def test_multi_hop_redirect_to_private_target_is_rejected():
    """
    A chain of otherwise-legitimate-looking redirects that eventually
    lands on a private target must be caught at the final hop, not
    just the first one.
    """

    from backend.app.utils.http_client import request_with_retry

    calls: list[str] = []

    class _MultiHopTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            calls.append(str(request.url))

            if len(calls) == 1:
                return httpx.Response(
                    302,
                    headers={"location": "https://example.org/"},
                    request=request,
                )

            if len(calls) == 2:
                return httpx.Response(
                    302,
                    headers={"location": "http://10.0.0.5/internal"},
                    request=request,
                )

            return httpx.Response(200, content=b"unreachable", request=request)

    async with httpx.AsyncClient(
        transport=_MultiHopTransport(), timeout=5,
    ) as client:

        with pytest.raises(ValueError):
            await request_with_retry(client, "GET", "http://example.com/")

    assert len(calls) == 2  # never reached the third (private) hop


@pytest.mark.anyio
async def test_dns_rebinding_is_closed_by_ip_pinning(monkeypatch):
    """
    Simulates DNS rebinding: the hostname resolves to a PUBLIC address
    at validation time, but would resolve to a PRIVATE address if
    looked up again at connect time. Because request_with_retry()
    connects directly to the address it already validated (rather than
    letting the transport re-resolve the hostname), the rebind must
    never take effect.
    """

    import ipaddress
    from backend.app.utils import http_client as http_client_module

    real_resolve = http_client_module.resolve_public_addresses

    def _fake_resolve(hostname):
        # First (validation) call sees a public IP; if the connection
        # path ever resolved again, it would see a private one - the
        # fix must never call this a second time for the same hop.
        if hostname == "rebinding-target.test":
            return (ipaddress.ip_address("93.184.216.34"),)
        return real_resolve(hostname)

    monkeypatch.setattr(
        http_client_module, "resolve_public_addresses", _fake_resolve,
    )

    connected_hosts: list[str] = []

    class _RecordingTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            connected_hosts.append(request.url.host)
            return httpx.Response(200, content=b"ok", request=request)

    async with httpx.AsyncClient(
        transport=_RecordingTransport(), timeout=5,
    ) as client:

        response = await http_client_module.request_with_retry(
            client, "GET", "http://rebinding-target.test/",
        )

    assert response.status_code == 200
    # The transport must have been asked to connect to the pinned IP
    # literal, never to the raw hostname (which is the only thing a
    # rebinding DNS server controls).
    assert connected_hosts == ["93.184.216.34"]
