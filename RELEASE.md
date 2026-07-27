# Release Process

1. Work through a pull request into `main`.
2. Require the CI workflow to pass before merge.
3. Review database migrations and confirm there is exactly one Alembic head.
4. Build the production container from the committed source.
5. Apply `alembic upgrade head` before serving traffic with code that requires the new schema.
6. Verify `/health` and `/ready` after deployment.
7. Run a smoke test covering authentication, one investigation, report generation, and report download.
8. Roll back application code if health checks fail. Database rollback must be evaluated migration-by-migration; do not automatically downgrade destructive migrations.

## Release candidate quality gate

Before creating a release candidate, run `python scripts/quality_gate.py --frontend` in a provisioned development/CI environment and complete `RELEASE_CHECKLIST.md`. A successful compile-only check is not a substitute for runtime tests.
