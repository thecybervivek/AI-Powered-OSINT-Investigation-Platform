import asyncio
import ssl
from datetime import datetime
from datetime import timezone

from backend.app.core.config import settings
from backend.app.integrations.base import AsyncBaseIntegration
from backend.app.integrations.base import IntegrationResult
from backend.app.integrations.exceptions import IntegrationTimeoutError
from backend.app.models.investigation import ModuleResultStatus

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

        context = ssl.create_default_context()

        try:
            loop = asyncio.get_running_loop()

            transport, _ = await asyncio.wait_for(
                loop.create_connection(
                    lambda: asyncio.Protocol(),
                    host=host,
                    port=443,
                    ssl=context,
                    server_hostname=host,
                ),
                timeout=settings.SSL_CHECK_TIMEOUT_SECONDS,
            )

        except asyncio.TimeoutError as error:
            raise IntegrationTimeoutError(
                f"TLS handshake with '{host}' timed out."
            ) from error

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

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.FAILED,
                error_message=f"Could not establish TLS connection to '{host}': {error}",
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
