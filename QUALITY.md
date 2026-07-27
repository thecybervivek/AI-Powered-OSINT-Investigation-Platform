# Quality and Release Readiness

Milestone 12 defines the consolidated quality gate for the OSINT Investigation Platform.

## Required gates

- Backend source and tests compile on Python 3.12.
- Backend test suite passes in the project virtual environment with dependencies from `requirements.txt`.
- Frontend unit tests pass with `npm test -- --run`.
- Frontend production build passes with `npm run build`.
- Alembic revision graph has exactly one head and upgrades a clean database to `head`.
- No runtime secrets, local databases, virtual environments, dependency folders, caches, or build output are committed/released.
- Production image builds successfully.
- Authentication, investigation creation, report generation, authenticated PDF download, `/health`, and `/ready` are covered by the release smoke test.

## Local validation

Run from the repository root after activating the Python virtual environment:

```powershell
python scripts/quality_gate.py
```

For frontend validation as well:

```powershell
python scripts/quality_gate.py --frontend
```

The CI workflow remains the authoritative clean-environment gate.

## Current checkpoint

Static Python compilation was verified while preparing M12. Full backend runtime tests require the Python dependencies from `requirements.txt`; they must not be reported as passing when those dependencies are absent from the validation environment.
