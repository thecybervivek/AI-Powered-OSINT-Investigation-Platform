import asyncio
import ssl
from datetime import datetime
from datetime import timezone

from backend.app.core.config import settings
from backend.app.integrations.base import AsyncBaseIntegration
from backend.app.integrations.base import IntegrationResult
from backend.app.models.investigation import ModuleResultStatus
from backend.app.utils.http_client import resolve_public_addresses

_CERT_DATE_FORMAT = "%b %d %H:%M:%S %Y %Z"


class SSLCertificateIntegration(AsyncBaseIntegration):
    """
    Opens a TLS connection to the target on port 443 and reports the
    presented certificate's subject, issuer, validity window, SANs, and
    whether it is currently expired — using only asyncio + the stdlib
    ssl module (no extra dependency).
    """

    source_name = "ssl_certificate"

    def is_configured(self) -> bool:
        return True

    async def _query(self, target: str) -> IntegrationResult:

        host = target.strip().lower()
        # Strip a scheme/path if the caller passed a URL by mistake.
        host = host.split("://")[-1].split("/")[0].split(":")[0]

        try:
            # Resolve and validate now, then connect directly to a
            # validated IP (not the hostname) below - this is the same
            # DNS-rebinding TOCTOU fix as request_with_retry in
            # http_client.py: asyncio's own connector would otherwise
            # re-resolve the hostname at connect time, and an
            # attacker-controlled DNS server could serve a different
            # (private/internal) address for that second lookup.
            validated_addresses = resolve_public_addresses(host)

            # IPv4 first: broader outbound compatibility across runtimes
            # (some environments resolve AAAA records but have no
            # working IPv6 egress), while still trying every validated
            # address rather than giving up after just one.
            candidate_ips = sorted(
                (str(addr) for addr in validated_addresses),
                key=lambda ip: ":" in ip,
            )

        except ValueError as error:
            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.FAILED,
                error_message=f"Unsafe target refused: {error}",
            )

        context = ssl.create_default_context()
        loop = asyncio.get_running_loop()

        transport = None
        connect_errors: list[str] = []

        for candidate_ip in candidate_ips:

            try:
                transport, _ = await asyncio.wait_for(
                    loop.create_connection(
                        lambda: asyncio.Protocol(),
                        host=candidate_ip,
                        port=443,
                        ssl=context,
                        server_hostname=host,
                    ),
                    timeout=settings.SSL_CHECK_TIMEOUT_SECONDS,
                )
                break

            except asyncio.TimeoutError:
                connect_errors.append(f"{candidate_ip}: timed out")

            except ssl.SSLCertVerificationError as error:

                return IntegrationResult(
                    source=self.source_name,
                    status=ModuleResultStatus.SUCCESS,
                    data={
                        "host": host,
                        "certificate_valid": False,
                        "verification_error": str(error),
                    },
                )

            except (OSError, ssl.SSLError) as error:
                connect_errors.append(f"{candidate_ip}: {error}")

        if transport is None:

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.FAILED,
                error_message=(
                    f"Could not establish TLS connection to '{host}' "
                    f"via any resolved address: {'; '.join(connect_errors)}"
                ),
            )

        try:
            cert = transport.get_extra_info("peercert") or {}
        finally:
            transport.close()

        subject = _flatten_name(cert.get("subject", ()))
        issuer = _flatten_name(cert.get("issuer", ()))

        not_before = _parse_cert_date(cert.get("notBefore"))
        not_after = _parse_cert_date(cert.get("notAfter"))

        is_expired = (
            not_after is not None and not_after < datetime.now(timezone.utc)
        )

        san_entries = [
            value for key, value in cert.get("subjectAltName", ()) if key == "DNS"
        ]

        data = {
            "host": host,
            "certificate_valid": True,
            "subject": subject,
            "issuer": issuer,
            "not_before": not_before.isoformat() if not_before else None,
            "not_after": not_after.isoformat() if not_after else None,
            "is_expired": is_expired,
            "subject_alt_names": san_entries,
            "serial_number": cert.get("serialNumber"),
        }

        return IntegrationResult(
            source=self.source_name,
            status=ModuleResultStatus.SUCCESS,
            data=data,
        )


def _flatten_name(name_tuples) -> dict:

    flattened = {}

    for rdn in name_tuples:
        for key, value in rdn:
            flattened[key] = value

    return flattened


def _parse_cert_date(raw: str | None) -> datetime | None:

    if not raw:
        return None

    try:
        return datetime.strptime(raw, _CERT_DATE_FORMAT).replace(tzinfo=timezone.utc)

    except ValueError:
        return None
