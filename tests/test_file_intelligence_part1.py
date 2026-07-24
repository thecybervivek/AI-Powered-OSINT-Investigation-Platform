import hashlib
import os
import tempfile

import pytest

from backend.app.utils.file_hashing import hash_file
from backend.app.utils.file_validation import sanitize_filename
from backend.app.utils.file_validation import validate_upload


@pytest.fixture
def sample_file():

    fd, path = tempfile.mkstemp(suffix=".txt")

    with os.fdopen(fd, "wb") as handle:
        handle.write(b"AI Powered OSINT Investigation Platform - Milestone 6")

    yield path

    os.remove(path)


def test_hash_file_matches_hashlib(sample_file):

    result = hash_file(sample_file)

    with open(sample_file, "rb") as handle:
        content = handle.read()

    assert result.md5 == hashlib.md5(content).hexdigest()
    assert result.sha1 == hashlib.sha1(content).hexdigest()
    assert result.sha256 == hashlib.sha256(content).hexdigest()
    assert result.sha512 == hashlib.sha512(content).hexdigest()


def test_sanitize_filename_strips_path_traversal():

    assert sanitize_filename("../../etc/passwd") == "passwd"
    assert sanitize_filename("report final (v2).pdf") == "report_final__v2_.pdf"


def test_validate_upload_rejects_blocked_extension(sample_file):

    result = validate_upload(
        filename="totally-safe.exe",
        file_size_bytes=os.path.getsize(sample_file),
        file_path=sample_file,
    )

    assert result.is_valid is False
    assert result.suspicious_extension is True


def test_validate_upload_flags_double_extension(sample_file):

    result = validate_upload(
        filename="invoice.pdf.exe",
        file_size_bytes=os.path.getsize(sample_file),
        file_path=sample_file,
    )

    assert result.has_double_extension is True
    assert result.is_valid is False


def test_validate_upload_accepts_plain_text(sample_file):

    result = validate_upload(
        filename="notes.txt",
        file_size_bytes=os.path.getsize(sample_file),
        file_path=sample_file,
    )

    assert result.is_valid is True
    assert result.declared_extension == ".txt"
