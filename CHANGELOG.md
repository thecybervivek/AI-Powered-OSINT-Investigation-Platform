# Changelog

## 1.0.0 - 2026-07-26

### Added
- End-to-end authenticated OSINT investigation platform covering core and advanced intelligence modules.
- Investigation history, evidence correlation, composite risk scoring and analyst reporting.
- React/TypeScript dashboard and authenticated PDF report downloads.
- PostgreSQL/Alembic persistence, production configuration, health/readiness checks and Docker baseline.
- CI, consolidated quality gate, observability guidance, security guidance and release checklist.

### Release-candidate notes
- Runtime integrations that depend on external providers require their own credentials and network access.
- A full clean-environment backend/frontend test run, migration upgrade and container smoke test remain release gates before declaring a production release.
