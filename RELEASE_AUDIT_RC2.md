# v1.0.0-rc.2 Remediation Audit

This artifact is a release candidate, not a final v1.0.0.

## Baseline
- Source files: 261 before remediation.
- `python -m compileall -q backend tests`: PASS before modifications.
- Backend pytest: NOT EXECUTED to completion; runtime lacked `python-jose`, and dependency installation could not reach a package index (`alembic==1.18.5` unavailable in the execution environment).
- Frontend `npm ci/test/build`: NOT EXECUTED to completion; package installation timed out in the execution environment.
- Alembic CLI: not available in the baseline runtime. Static revision graph inspection was used only as a supplemental check, not as a substitute for PostgreSQL migration execution.

## Finding disposition
- URLScan active scanning/privacy: CONFIRMED; remediated with explicit opt-in, API-key requirement, private default, public-target validation, UUID-derived result URL, sanitized upstream errors.
- Central SSRF policy: CONFIRMED; outbound HTTP helper now validates every destination and redirect hop. DNS-rebinding limitation is documented and requires production egress controls.
- File upload resource limit: CONFIRMED; remediated with bounded chunk streaming, early abort, restrictive permissions, partial-file cleanup.
- Refresh session security: CONFIRMED; server-side hashed-JTI refresh sessions, rotation, revocation and reuse response added with migration.
- RBAC enum bug: CONFIRMED; enum comparison corrected. Full product permissions matrix remains a release-gate review item.
- Production migrations: CONFIRMED; Compose migration service added and API waits for successful completion.
- Frontend production deployment: CONFIRMED; multi-stage Vite build + Nginx service added.
- PostgreSQL migration verification: CONFIRMED gap; CI now provisions PostgreSQL and runs heads/upgrade/current. Local execution was not possible in this environment.
- JWT claim hardening: CONFIRMED; iat/jti/type/iss/aud added and issuer/audience validation centralized.
- Frontend token storage: CONFIRMED and NOT FULLY REMEDIATED. Refresh tokens remain in localStorage; migration to HttpOnly refresh cookies requires coordinated CSRF/CORS architecture and regression testing and is a remaining blocker.
- MITRE URL contract: CONFIRMED; normalized malicious field recognized.
- ATT&CK mapping quality: CONFIRMED; reputation-only IP/URL results are now indicator classifications rather than asserted ATT&CK techniques.
- Composite risk dilution: CONFIRMED; strongest usable risk is a floor and regression coverage added.
- Evidence correlation: CONFIRMED; existing correlation remains target-centric. Entity/edge provenance graph is not fully implemented and remains follow-up work.
- Risk calibration: CONFIRMED; heuristic scoring remains heuristic and is not represented as statistical probability.
- AI report privacy controls: requires further dedicated remediation/testing before final release approval.
- Error sanitization: URLScan fixed; complete endpoint/provider audit remains required.
- Auth rate limiting: dedicated auth throttling remains required.
- Frontend/backend parity: malware type omission fixed; full workflow parity still requires UI test verification.
- PDF download: CONFIRMED; direct Bearer-protected URL helper removed in favor of authenticated Blob download/object URL.
- CI production gates: PARTIALLY FIXED; PostgreSQL/Redis/migrations and Docker Compose validation added. Runtime API/auth smoke and security scanners beyond Bandit/pip-audit still require execution/extension.
- Versioning: CONFIRMED; synchronized to 1.0.0-rc.2 in VERSION, backend and frontend metadata.
- Path safety: remains follow-up; storage paths are still configurable relative paths.

## Post-change verification actually executed
- `python -m compileall -q backend tests`: PASS.
- AST parse of all backend/test Python sources: PASS.
- Static Alembic revision graph: 11 revisions, exactly one head `d0e1f2a3b4c5`: PASS.
- Full pytest/PostgreSQL migration/frontend/Docker runtime gates: NOT EXECUTED in this environment; therefore this RC is not certified production-ready.

## Release decision
NO. Do not promote to v1.0.0 yet. Remaining blockers include HttpOnly refresh-cookie migration or formally accepted alternative threat model, dedicated auth throttling, full AI-data privacy/error-sanitization audit, entity-level evidence correlation if required for 1.0 scope, path-root hardening, and successful execution of all CI/migration/runtime/frontend gates in a provisioned environment.
