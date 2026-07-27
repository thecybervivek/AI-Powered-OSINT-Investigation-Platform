# Release remediation status — 1.0.0-rc.2

This tree is a release candidate, not final v1.0.0.

## Completed in this pass
- Refresh token moved out of browser localStorage into an HttpOnly cookie; access token remains short-lived JS state/storage.
- Cookie refresh rotation continues to use server-side hashed JTI refresh sessions.
- Login/register/refresh have dedicated rate-limit policies.
- External AI processing is explicit opt-in and evidence is minimized/redacted before provider transmission.
- External AI upstream error bodies are not returned in raised provider errors.
- File/image/YARA paths are resolved from a stable project root rather than process CWD.
- Evidence correlation now emits normalized entity type, relationship, provenance and confidence for deterministic relationships derivable from investigation targets.
- CI definition includes PostgreSQL/Redis migration gates, runtime Compose health/readiness smoke checks, Gitleaks and Trivy gates.
- Added regression tests for refresh-cookie behavior, rotation/logout, privacy redaction and CWD-independent path resolution.

## Executed verification
- `python -m compileall -q backend tests`: PASS
- Python AST parse of backend/tests: PASS
- `alembic heads`: PASS, one head `d0e1f2a3b4c5`
- `python -m pytest -q`: NOT EXECUTABLE in supplied runtime; `python-jose` is absent before collection.
- `npm test -- --run`: NOT EXECUTABLE; frontend node_modules/vitest absent.
- `npm ci`: attempted but package installation unavailable in this container.
- Docker/Compose runtime: NOT EXECUTABLE; Docker CLI is absent.

Because mandatory dynamic gates could not execute, this build must remain an RC and must not be labelled production-ready or v1.0.0.
