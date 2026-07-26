import os
import tempfile

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
        result = YaraScanner().scan(path)

        assert result.data["matched"] is True
        assert "EICAR_Test_File" in [m["rule"] for m in result.data["matches"]]

    finally:
        os.remove(path)


def test_yara_scanner_reports_no_match_on_clean_file():

    path = _write_temp_file(b"nothing suspicious in here at all")

    try:
        result = YaraScanner().scan(path)

        assert result.data["matched"] is False
        assert result.data["match_count"] == 0

    finally:
        os.remove(path)


def test_yara_scanner_detects_powershell_encoded_command():

    path = _write_temp_file(
        b"powershell.exe -NoP -NonI -W Hidden -EncodedCommand SQBFAFgA"
    )

    try:
        result = YaraScanner().scan(path)

        assert result.data["matched"] is True
        assert "Suspicious_Embedded_PowerShell_EncodedCommand" in [
            m["rule"] for m in result.data["matches"]
        ]

    finally:
        os.remove(path)
