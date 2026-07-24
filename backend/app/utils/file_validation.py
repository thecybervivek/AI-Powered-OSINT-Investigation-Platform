import os
import re
from dataclasses import dataclass
from dataclasses import field

import filetype

from backend.app.core.config import settings

# Extensions considered "document/media" types users legitimately
# upload for OSINT metadata analysis. Anything with two extensions
# where the FIRST looks like one of these and the LAST is executable-ish
# is a classic double-extension disguise (e.g. invoice.pdf.exe).
_DOCUMENT_LIKE_EXTENSIONS = {
    ".pdf", ".doc", ".docx", ".ppt", ".pptx", ".xls", ".xlsx",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".webp",
    ".txt", ".csv", ".zip", ".rar",
}

_FILENAME_SAFE_RE = re.compile(r"[^A-Za-z0-9._-]")


@dataclass
class FileValidationResult:

    is_valid: bool
    declared_extension: str | None
    detected_mime_type: str | None
    file_size_bytes: int
    has_double_extension: bool
    suspicious_extension: bool
    errors: list[str] = field(default_factory=list)


def sanitize_filename(filename: str) -> str:
    """
    Strips path separators and unsafe characters so the original
    filename can never be used to escape the storage directory or
    inject shell/path metacharacters, while remaining human-readable.
    """

    base = os.path.basename(filename or "upload")
    base = _FILENAME_SAFE_RE.sub("_", base)

    return base[:255] if base else "upload"


def _extract_extensions(filename: str) -> list[str]:
    """
    Returns every dotted suffix, lowercased, e.g. "invoice.pdf.exe"
    -> [".pdf", ".exe"]. Used for double-extension detection.
    """

    name = filename.lower()
    parts = name.split(".")

    if len(parts) <= 1:
        return []

    return [f".{part}" for part in parts[1:]]


def validate_upload(
    *,
    filename: str,
    file_size_bytes: int,
    file_path: str,
) -> FileValidationResult:
    """
    Validates an already-written-to-disk upload: size ceiling, blocked
    extensions, double-extension disguises, and magic-byte MIME
    detection (never trusts the client-supplied Content-Type header).
    """

    errors: list[str] = []

    max_bytes = settings.FILE_UPLOAD_MAX_SIZE_MB * 1024 * 1024

    if file_size_bytes <= 0:
        errors.append("Uploaded file is empty.")

    if file_size_bytes > max_bytes:
        errors.append(
            f"File exceeds the {settings.FILE_UPLOAD_MAX_SIZE_MB} MB upload limit."
        )

    extensions = _extract_extensions(filename)
    declared_extension = extensions[-1] if extensions else None

    suspicious_extension = declared_extension in settings.FILE_BLOCKED_EXTENSIONS

    if suspicious_extension:
        errors.append(
            f"Extension '{declared_extension}' is not permitted for upload."
        )

    has_double_extension = (
        len(extensions) >= 2
        and extensions[-2] in _DOCUMENT_LIKE_EXTENSIONS
        and extensions[-1] not in _DOCUMENT_LIKE_EXTENSIONS
    )

    if has_double_extension:
        errors.append(
            f"Double extension detected ('{''.join(extensions[-2:])}') — "
            f"this pattern is commonly used to disguise executables."
        )

    detected_mime_type: str | None = None

    try:
        kind = filetype.guess(file_path)

        if kind is not None:
            detected_mime_type = kind.mime

    except (OSError, ValueError):
        detected_mime_type = None

    return FileValidationResult(
        is_valid=not errors,
        declared_extension=declared_extension,
        detected_mime_type=detected_mime_type,
        file_size_bytes=file_size_bytes,
        has_double_extension=has_double_extension,
        suspicious_extension=suspicious_extension,
        errors=errors,
    )
