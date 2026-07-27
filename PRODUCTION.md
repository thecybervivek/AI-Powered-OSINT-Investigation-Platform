# Production Deployment Checklist

1. Copy `.env.example` to `.env` and replace every placeholder. Generate a cryptographically random `SECRET_KEY` of at least 32 characters.
2. Set `ENVIRONMENT=production`, `DEBUG=false`, `ENABLE_API_DOCS=false`, explicit `ALLOWED_ORIGINS`, explicit `TRUSTED_HOSTS`, and `RATE_LIMIT_BACKEND=redis`.
3. Use PostgreSQL and Redis. Do not use SQLite or in-memory rate limiting for a multi-user production deployment.
4. Run `alembic upgrade head` before starting the API.
5. Terminate TLS at a trusted reverse proxy/load balancer and forward HTTPS correctly. HSTS is emitted on HTTPS requests.
6. Keep provider API keys in environment variables or a managed secret store. Rotate any key that was ever committed or shared.
7. Persist and back up PostgreSQL and the application storage volume according to your retention policy.
8. Monitor `/health` for liveness and `/ready` for database readiness. Centralize application logs and alert on repeated 401/403/429/5xx responses.
9. Run backend tests and the frontend production build before each release. Review dependency vulnerability reports before deployment.
10. Restrict OSINT use to lawful, authorized investigations and define data minimization/deletion procedures.

## Release candidate security controls (1.0.0-rc.2)

Active urlscan.io submission is disabled by default (`URLSCAN_ACTIVE_SCANNING_ENABLED=false`) and requires an API key. Keep `URLSCAN_VISIBILITY=private`; target URLs are rejected when they resolve to non-global IPv4/IPv6 space. Outbound HTTP validates each redirect destination. Application-layer DNS checks cannot fully eliminate DNS rebinding because the HTTP transport resolves the hostname independently; production egress firewall/proxy policy MUST block loopback, RFC1918/ULA, link-local, multicast, reserved, and cloud metadata networks.

File uploads are streamed with an application size ceiling and partial files are removed on failure. Enforce the same or a smaller request-body limit at the production reverse proxy/load balancer so oversized bodies are rejected before reaching FastAPI.

`docker compose up` includes a one-shot Alembic migration service and a production Nginx-served frontend on port 8080. The API waits for successful migrations.
