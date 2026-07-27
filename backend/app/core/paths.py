from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]


def resolve_project_path(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else PROJECT_ROOT / path
