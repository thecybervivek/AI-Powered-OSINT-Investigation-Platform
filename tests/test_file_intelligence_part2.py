import os
import tempfile

import pytest

from backend.app.integrations.file.yara_scanner import YaraScanner


EICAR_STRING = (
    rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)


def _write_temp_file(content: bytes) -> str:

    fd, path = tempfile.mkstemp(suffix=".txt")

    with os.fdopen(fd, "wb") as handle:
        handle.write(content)

    return path


def test_yara_scanner_compiles_default_rules():

    scanner = YaraScanner()

    assert scanner.is_configured() is True


def test_yara_scanner_detects_eicar_string():

    path = _write_temp_file(EICAR_STRING)

    try:
        # EICAR is intentionally recognized by endpoint antivirus.
        # On Windows, Defender or another AV may intercept access to the
        # artifact before yara-python gets an opportunity to scan it.
        try:
            with open(path, "rb") as handle:
                content = handle.read()

        except OSError:

            pytest.skip(
                "EICAR artifact was blocked by endpoint antivirus "
                "before YARA could scan it."
            )

        if content != EICAR_STRING:

            pytest.skip(
                "EICAR artifact was modified by endpoint antivirus "
                "before YARA could scan it."
            )

        result = YaraScanner().scan(path)

        # A Windows endpoint security product may allow creation/read
        # but block yara-python when it subsequently opens the artifact.
        if (
            result.status.value == "failed"
            and result.error_message
            and "could not open file" in result.error_message.lower()
        ):

            pytest.skip(
                "EICAR artifact became inaccessible to YARA due to "
                "endpoint antivirus interception."
            )

        # Any other scanner failure remains a genuine test failure.
        assert result.data["matched"] is True

        assert "EICAR_Test_File" in [
            match["rule"]
            for match in result.data["matches"]
        ]

    finally:

        try:
            os.remove(path)
        except OSError:
            pass


def test_yara_scanner_reports_no_match_on_clean_file():

    path = _write_temp_file(
        b"nothing suspicious in here at all"
    )

    try:

        result = YaraScanner().scan(path)

        assert result.data["matched"] is False
        assert result.data["match_count"] == 0

    finally:

        os.remove(path)


def test_yara_scanner_detects_powershell_encoded_command():

    path = _write_temp_file(
        b"powershell.exe -NoP -NonI -W Hidden "
        b"-EncodedCommand SQBFAFgA"
    )

    try:

        result = YaraScanner().scan(path)

        assert result.data["matched"] is True

        assert (
            "Suspicious_Embedded_PowerShell_EncodedCommand"
            in [
                match["rule"]
                for match in result.data["matches"]
            ]
        )

    finally:

        os.remove(path)