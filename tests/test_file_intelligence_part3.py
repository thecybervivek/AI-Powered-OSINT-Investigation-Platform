import os
import tempfile

from backend.app.integrations.base import IntegrationResult
from backend.app.models.investigation import ModuleResultStatus
from backend.app.models.investigation import RiskLevel
from backend.app.services.file_service import FileIntelligenceService
from backend.app.utils.file_validation import validate_upload
from backend.app.utils.risk_scoring import risk_level_from_score


def _service() -> FileIntelligenceService:
    # _compute_risk_score/_build_summary touch no database state, so a
    # None db is safe for these pure-logic unit tests.
    return FileIntelligenceService(db=None)


def _sample_file():

    fd, path = tempfile.mkstemp(suffix=".txt")

    with os.fdopen(fd, "wb") as handle:
        handle.write(b"sample content for risk engine tests")

    return path


def test_double_extension_flags_but_does_not_block_when_not_dangerous():

    path = _sample_file()

    try:
        result = validate_upload(
            filename="resume.pdf.html",
            file_size_bytes=os.path.getsize(path),
            file_path=path,
        )

        assert result.has_double_extension is True
        assert result.is_valid is True  # flagged, not blocked

    finally:
        os.remove(path)


def test_blocked_extension_still_hard_blocks_regardless_of_double_extension():

    path = _sample_file()

    try:
        result = validate_upload(
            filename="invoice.pdf.exe",
            file_size_bytes=os.path.getsize(path),
            file_path=path,
        )

        assert result.suspicious_extension is True
        assert result.is_valid is False

    finally:
        os.remove(path)


def test_risk_score_zero_when_all_sources_clean_or_skipped():

    service = _service()

    results_by_source = {
        "virustotal_file": IntegrationResult(
            source="virustotal_file",
            status=ModuleResultStatus.SKIPPED,
        ),
        "malwarebazaar": IntegrationResult(
            source="malwarebazaar",
            status=ModuleResultStatus.NOT_FOUND,
            data={"known_to_malwarebazaar": False},
        ),
        "yara_scan": IntegrationResult(
            source="yara_scan",
            status=ModuleResultStatus.SUCCESS,
            data={"matched": False, "match_count": 0, "matches": []},
        ),
    }

    validation = validate_upload(
        filename="clean.txt",
        file_size_bytes=10,
        file_path=_sample_file(),
    )

    score, notes = service._compute_risk_score(
        results_by_source=results_by_source,
        validation=validation,
    )

    assert score == 0.0
    assert notes == []
    assert risk_level_from_score(score) == RiskLevel.LOW


def test_risk_score_high_when_multiple_sources_flag_malicious():

    service = _service()

    results_by_source = {
        "virustotal_file": IntegrationResult(
            source="virustotal_file",
            status=ModuleResultStatus.SUCCESS,
            data={
                "known_to_virustotal": True,
                "analysis_stats": {"malicious": 10, "suspicious": 2},
            },
        ),
        "malwarebazaar": IntegrationResult(
            source="malwarebazaar",
            status=ModuleResultStatus.SUCCESS,
            data={"known_to_malwarebazaar": True, "signature": "TrickBot"},
        ),
        "yara_scan": IntegrationResult(
            source="yara_scan",
            status=ModuleResultStatus.SUCCESS,
            data={
                "matched": True,
                "match_count": 1,
                "matches": [
                    {
                        "rule": "Suspicious_PE_Process_Injection_APIs",
                        "meta": {"severity": "high"},
                    }
                ],
            },
        ),
    }

    validation = validate_upload(
        filename="malware.txt",
        file_size_bytes=10,
        file_path=_sample_file(),
    )

    score, notes = service._compute_risk_score(
        results_by_source=results_by_source,
        validation=validation,
    )

    assert score == 100.0  # clamped ceiling with this many strong signals
    assert any("MalwareBazaar" in note for note in notes)
    assert any("VirusTotal" in note for note in notes)
    assert any("YARA rule matched" in note for note in notes)
    assert risk_level_from_score(score) == RiskLevel.CRITICAL


def test_risk_score_reflects_double_extension_signal():

    service = _service()

    validation = validate_upload(
        filename="resume.pdf.html",
        file_size_bytes=10,
        file_path=_sample_file(),
    )

    score, notes = service._compute_risk_score(
        results_by_source={},
        validation=validation,
    )

    assert score == 10.0
    assert "Double file extension detected" in notes
