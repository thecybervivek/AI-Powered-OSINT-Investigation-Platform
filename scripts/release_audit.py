"""Source-tree audit used before creating a release artifact."""
from __future__ import annotations

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
FORBIDDEN_PARTS = {".venv", "venv", "node_modules", "dist", "__pycache__", ".pytest_cache", ".git"}
FORBIDDEN_NAMES = {".env"}
FORBIDDEN_SUFFIXES = {".db", ".sqlite3", ".pyc", ".pyo", ".tsbuildinfo"}


def main() -> None:
    violations: list[str] = []
    for path in ROOT.rglob("*"):
        rel = path.relative_to(ROOT)
        if any(part in FORBIDDEN_PARTS for part in rel.parts):
            violations.append(str(rel))
            continue
        if path.is_file() and (path.name in FORBIDDEN_NAMES or path.suffix in FORBIDDEN_SUFFIXES):
            violations.append(str(rel))

    if violations:
        print("RELEASE_AUDIT_FAILED")
        for item in sorted(set(violations))[:100]:
            print(f" - {item}")
        raise SystemExit(1)

    required = ["README.md", "VERSION", "CHANGELOG.md", "SECURITY.md", "RELEASE_CHECKLIST.md", ".env.example"]
    missing = [name for name in required if not (ROOT / name).exists()]
    if missing:
        print("RELEASE_AUDIT_FAILED: missing required release files:", ", ".join(missing))
        raise SystemExit(1)

    print("RELEASE_AUDIT_OK")


if __name__ == "__main__":
    main()
