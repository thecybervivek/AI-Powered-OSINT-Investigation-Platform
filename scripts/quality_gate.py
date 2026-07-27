"""Local consolidated quality gate for release candidates."""
from __future__ import annotations

import argparse
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]


def run(label: str, command: list[str], cwd: pathlib.Path = ROOT) -> None:
    print(f"\n== {label} ==")
    completed = subprocess.run(command, cwd=cwd, check=False)
    if completed.returncode:
        raise SystemExit(f"{label} failed with exit code {completed.returncode}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--frontend", action="store_true", help="also run frontend tests and build")
    args = parser.parse_args()

    run("Python compile", [sys.executable, "-m", "compileall", "-q", "backend", "tests"])
    run("Backend tests", [sys.executable, "-m", "pytest", "-q"])

    if args.frontend:
        frontend = ROOT / "frontend"
        run("Frontend tests", ["npm", "test", "--", "--run"], frontend)
        run("Frontend build", ["npm", "run", "build"], frontend)

    print("\nQUALITY_GATE_OK")


if __name__ == "__main__":
    main()
