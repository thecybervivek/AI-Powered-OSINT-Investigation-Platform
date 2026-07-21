import argparse
import subprocess
import sys
from pathlib import Path

# ==========================================================
# AI Powered OSINT Investigation Platform
# Project Manager
# Version : 1.0
# ==========================================================

PROJECT_NAME = "AI-Powered-OSINT-Investigation-Platform"
ROOT = Path(__file__).parent.resolve()

# ==========================================================
# Console Helpers
# ==========================================================

def info(message: str):
    print(f"[INFO] {message}")


def success(message: str):
    print(f"[SUCCESS] {message}")


def warning(message: str):
    print(f"[WARNING] {message}")


def error(message: str):
    print(f"[ERROR] {message}")


def separator():
    print("=" * 60)


# ==========================================================
# File Utilities
# ==========================================================

def create_folder(path: Path):

    if not path.exists():

        path.mkdir(parents=True, exist_ok=True)

        success(f"Folder Created : {path}")

    else:

        warning(f"Folder Exists : {path}")


def create_file(path: Path, content: str = ""):

    if not path.exists():

        path.write_text(content, encoding="utf-8")

        success(f"File Created : {path}")

    else:

        warning(f"File Exists : {path}")


def overwrite_file(path: Path, content: str = ""):

    path.write_text(content, encoding="utf-8")

    success(f"Updated : {path}")


def create_init(folder: Path):

    create_file(folder / "__init__.py")


# ==========================================================
# Run FastAPI
# ==========================================================

def run_server():

    separator()

    info("Starting FastAPI Development Server...")

    separator()

    subprocess.run(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "backend.app.main:app",
            "--reload",
        ]
    )


# ==========================================================
# Project Folder Structure
# ==========================================================

FOLDERS = [

    "backend",

    "backend/app",

    "backend/app/api",

    "backend/app/api/v1",

    "backend/app/api/v1/endpoints",

    "backend/app/core",

    "backend/app/db",

    "backend/app/models",

    "backend/app/schemas",

    "backend/app/services",

    "backend/app/utils",

    "frontend",

    "docker",

    "docs",

    "scripts",

    "tests",

]

# ==========================================================
# Default Files
# ==========================================================

FILES = [

    "backend/app/main.py",

    "backend/app/core/config.py",

    "backend/app/core/security.py",

    "backend/app/db/database.py",

    "backend/app/db/session.py",

    "backend/app/models/__init__.py",

    "backend/app/schemas/__init__.py",

    "backend/app/services/__init__.py",

    "backend/app/utils/__init__.py",

    "backend/app/api/__init__.py",

    "backend/app/api/v1/__init__.py",

    "backend/app/api/v1/router.py",

    "backend/app/api/v1/endpoints/__init__.py",

    "requirements.txt",

    ".env",

    ".env.example",

    ".gitignore",

    "README.md",

    "docker-compose.yml",

    "Dockerfile",

]

# ==========================================================
# Create Project
# ==========================================================

def create_structure():

    separator()

    info("Creating Project Structure")

    separator()

    for folder in FOLDERS:

        create_folder(ROOT / folder)

    create_init(ROOT / "backend")

    create_init(ROOT / "backend/app")

    create_init(ROOT / "backend/app/api")

    create_init(ROOT / "backend/app/api/v1")

    create_init(ROOT / "backend/app/api/v1/endpoints")

    create_init(ROOT / "backend/app/core")

    create_init(ROOT / "backend/app/db")

    create_init(ROOT / "backend/app/models")

    create_init(ROOT / "backend/app/schemas")

    create_init(ROOT / "backend/app/services")

    create_init(ROOT / "backend/app/utils")

    for file in FILES:

        create_file(ROOT / file)

    success("Project Structure Created Successfully")

# ==========================================================
# Requirements
# ==========================================================

REQUIREMENTS = """fastapi
uvicorn
sqlalchemy
alembic
python-dotenv
passlib[bcrypt]
python-jose[cryptography]
pydantic
pydantic-settings
redis
httpx
requests
"""
# ==========================================================
# Write Default Files
# ==========================================================

def write_default_files():

    info("Writing Default Project Files...")

    overwrite_file(
        ROOT / "requirements.txt",
        REQUIREMENTS,
    )

    overwrite_file(
        ROOT / ".gitignore",
        """__pycache__/
*.pyc
*.pyo
*.db
.env
.venv/
.idea/
.vscode/
""",
    )

    overwrite_file(
        ROOT / ".env.example",
        """APP_NAME=AI Powered OSINT Platform
DEBUG=True
SECRET_KEY=CHANGE_ME
DATABASE_URL=sqlite:///./osint.db
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
""",
    )

    overwrite_file(
        ROOT / "README.md",
        f"""# {PROJECT_NAME}

AI Powered OSINT Investigation Platform

## Features

- FastAPI
- SQLAlchemy
- JWT Authentication
- Docker
- Redis
- Alembic
- REST API
""",
    )

    success("Default Files Written Successfully")


# ==========================================================
# Install Requirements
# ==========================================================

def install_requirements():

    separator()

    info("Installing Python Packages")

    separator()

    subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "-r",
            "requirements.txt",
        ]
    )

    success("Requirements Installed")
    # ==========================================================
# Development Commands
# ==========================================================

def format_code():

    info("Formatting Project...")

    subprocess.run(
        [
            sys.executable,
            "-m",
            "black",
            ".",
        ]
    )

    success("Formatting Completed")


def lint_code():

    info("Running Flake8...")

    subprocess.run(
        [
            sys.executable,
            "-m",
            "flake8",
            ".",
        ]
    )

    success("Lint Completed")


def freeze_requirements():

    info("Updating requirements.txt")

    result = subprocess.check_output(
        [
            sys.executable,
            "-m",
            "pip",
            "freeze",
        ]
    )

    overwrite_file(
        ROOT / "requirements.txt",
        result.decode(),
    )

    success("requirements.txt Updated")


# ==========================================================
# Clean Cache
# ==========================================================

def clean():

    info("Cleaning Cache Files...")

    for item in ROOT.rglob("__pycache__"):

        if item.is_dir():

            import shutil

            shutil.rmtree(item)

    success("Cache Cleaned")


# ==========================================================
# Project Information
# ==========================================================

def project_info():

    separator()

    print(f"Project : {PROJECT_NAME}")

    print(f"Root    : {ROOT}")

    print(f"Python  : {sys.version}")

    separator()
    # ==========================================================
# Argument Parser
# ==========================================================

def build_parser():

    parser = argparse.ArgumentParser(
        description="AI Powered OSINT Project Manager"
    )

    parser.add_argument(
        "command",
        nargs="?",
        default="help",
        help="Command to execute",
    )

    return parser


# ==========================================================
# Main
# ==========================================================

def main():

    parser = build_parser()

    args = parser.parse_args()

    command = args.command.lower()

    if command == "create":

        create_structure()

        write_default_files()

    elif command == "install":

        install_requirements()

    elif command == "run":

        run_server()

    elif command == "format":

        format_code()

    elif command == "lint":

        lint_code()

    elif command == "freeze":

        freeze_requirements()

    elif command == "clean":

        clean()

    elif command == "info":

        project_info()

    else:

        separator()

        print("Available Commands")

        separator()

        print("create   -> Create Project Structure")

        print("install  -> Install Requirements")

        print("run      -> Start FastAPI Server")

        print("format   -> Format Source Code")

        print("lint     -> Run Flake8")

        print("freeze   -> Update requirements.txt")

        print("clean    -> Remove Cache")

        print("info     -> Project Information")

        separator()


# ==========================================================
# Entry Point
# ==========================================================

if __name__ == "__main__":

    main()
    