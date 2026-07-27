# Release Candidate Checklist

- [ ] `python scripts/quality_gate.py --frontend` passes in a fully provisioned environment.
- [ ] `alembic current` reports the expected revision after `alembic upgrade head` on a clean database.
- [ ] Alembic has exactly one head.
- [ ] Docker image builds from the release commit.
- [ ] `.env` is not packaged; deployment secrets are supplied by the target environment.
- [ ] `/health` returns healthy and `/ready` confirms database readiness.
- [ ] Register/login and protected API access work.
- [ ] At least one investigation completes and persists.
- [ ] Report generation and authenticated PDF download work.
- [ ] Logs contain request IDs and no secrets/tokens.
- [ ] Backup/rollback plan is reviewed before applying production migrations.
