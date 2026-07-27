# AI-Powered OSINT Investigation Platform

Production-oriented OSINT investigation platform with a FastAPI backend and React/TypeScript analyst dashboard. The platform consolidates multiple intelligence modules into authenticated investigations, correlates evidence, scores risk, and generates analyst reports including PDF export.

## Implemented capabilities

- Authentication and protected investigation history
- Username, email, domain, IP, DNS, URL and IOC intelligence
- File intelligence with validation, hashing, YARA and external reputation integrations
- Phone, reverse-image, social-media, breach, threat and malware intelligence
- Composite cross-investigation risk assessment
- AI/local-deterministic report generation, MITRE ATT&CK mapping and PDF export
- React/TypeScript dashboard for investigations and reports
- Alembic migrations, CI, Docker deployment, health/readiness endpoints and release quality gates

## Quick start

### Backend

Create a Python 3.12 virtual environment, install `requirements.txt`, copy `.env.example` to `.env` and set local values, then run:

```bash
alembic upgrade head
uvicorn backend.app.main:app --reload
```

API documentation is available at `/docs` when documentation is enabled for the selected environment.

### Frontend

```bash
cd frontend
npm ci
npm run dev
```

The Vite development server defaults to port 5173. Configure its API base URL as required by your environment.

## Validation

Backend gate:

```bash
python scripts/quality_gate.py
```

Backend + frontend gate:

```bash
python scripts/quality_gate.py --frontend
```

For a release candidate, also validate a clean Alembic upgrade, Docker build, `/health`, `/ready`, authentication, an investigation flow, report generation and authenticated PDF download. See `RELEASE_CHECKLIST.md`.

## Deployment

`Dockerfile` and `docker-compose.yml` provide the deployment baseline. Never ship `.env`, local databases, virtual environments, dependency folders, caches, generated storage, or frontend build output as source artifacts.

See `PRODUCTION.md`, `SECURITY.md`, `OBSERVABILITY.md`, `QUALITY.md`, and `RELEASE.md` for operational guidance.

## Release status

This source package represents the M13 release-candidate baseline. Static/source validation performed during packaging does not replace runtime tests in a fully provisioned environment. CI is the authoritative clean-environment gate before production release.

### Authentication and privacy notes (1.0.0-rc.2)

Refresh credentials are server-tracked, rotated, and delivered only in an HttpOnly cookie. JavaScript stores only the short-lived access token. Production requires HTTPS (`REFRESH_COOKIE_SECURE=true`). The refresh cookie uses SameSite protection and is scoped to `/api/v1`; deployments that intentionally use cross-site frontend/API origins must add a CSRF-token design before selecting `SameSite=None`.

External AI report processing is disabled by default (`EXTERNAL_AI_PROCESSING_ENABLED=false`). Local deterministic reporting remains available. When external AI is explicitly enabled, the platform applies payload minimization/redaction; operators remain responsible for provider contracts, retention policy, and applicable privacy law.

Application storage and bundled YARA rule paths are resolved from the project root rather than the process working directory. In production, enforce request-body limits at the reverse proxy in addition to application streaming limits.
