import asyncio
import os
import uuid
from datetime import datetime
from datetime import timezone
from pathlib import Path

from fastapi import UploadFile
from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.integrations.base import IntegrationResult
from backend.app.integrations.file.hybrid_analysis_integration import HybridAnalysisIntegration
from backend.app.integrations.file.malwarebazaar_integration import MalwareBazaarIntegration
from backend.app.integrations.file.virustotal_file_integration import VirusTotalFileIntegration
from backend.app.integrations.file.yara_scanner import YaraScanner
from backend.app.models.file_record import FileRecord
from backend.app.models.investigation import Investigation
from backend.app.models.investigation import InvestigationResult
from backend.app.models.investigation import InvestigationStatus
from backend.app.models.investigation import InvestigationType
from backend.app.models.investigation import ModuleResultStatus
from backend.app.repositories.file_repository import FileRecordRepository
from backend.app.repositories.investigation_repository import InvestigationRepository
from backend.app.utils.file_hashing import hash_file
from backend.app.utils.file_validation import FileValidationResult
from backend.app.utils.file_validation import sanitize_filename
from backend.app.utils.file_validation import validate_upload
from backend.app.utils.metadata_extraction import extract_metadata
from backend.app.utils.risk_scoring import clamp
from backend.app.utils.risk_scoring import risk_level_from_score
from backend.app.utils.timeline_builder import build_timeline

# Reputation sources queried by sha256. Each is optional and skips
# gracefully (ModuleResultStatus.SKIPPED) without its API key configured.
_REPUTATION_ENGINES = [
    VirusTotalFileIntegration,
    MalwareBazaarIntegration,
    HybridAnalysisIntegration,
]


class FileIntelligenceService:
    """
    Orchestrates Milestone 6 end-to-end: securely persists an upload to
    disk, validates it (size/blocked-extension/magic-byte MIME), computes
    all four hashes in one streamed pass, extracts type-specific metadata
    (EXIF / PDF / DOCX / PPTX / XLSX), builds a timeline, runs optional
    reputation lookups (VirusTotal/MalwareBazaar/HybridAnalysis) keyed by
    sha256, runs a local YARA scan, and combines every signal into a
    composite risk_score/risk_level - recording every stage as one
    Investigation + FileRecord + per-stage InvestigationResult row, the
    same shape every other module uses.
    """

    def __init__(self, db: Session) -> None:
        self.db = db
        self.investigations = InvestigationRepository(db)
        self.files = FileRecordRepository(db)

    async def investigate(
        self,
        *,
        user_id: str,
        upload: UploadFile,
    ) -> tuple[Investigation, FileRecord]:

        investigation = self.investigations.create(
            Investigation(
                user_id=user_id,
                investigation_type=InvestigationType.FILE,
                target=upload.filename or "unnamed_upload",
                status=InvestigationStatus.RUNNING,
                started_at=datetime.now(timezone.utc),
            )
        )

        storage_dir = Path(settings.FILE_STORAGE_DIR)
        storage_dir.mkdir(parents=True, exist_ok=True)

        original_filename = sanitize_filename(upload.filename or "upload")
        stored_filename = f"{uuid.uuid4().hex}_{original_filename}"
        stored_path = storage_dir / stored_filename

        contents = await upload.read()

        with open(stored_path, "wb") as handle:
            handle.write(contents)

        file_size_bytes = len(contents)

        validation = validate_upload(
            filename=original_filename,
            file_size_bytes=file_size_bytes,
            file_path=str(stored_path),
        )

        self.investigations.add_result(
            InvestigationResult(
                investigation_id=investigation.id,
                source="file_validation",
                status=(
                    ModuleResultStatus.SUCCESS
                    if validation.is_valid
                    else ModuleResultStatus.FAILED
                ),
                data={
                    "declared_extension": validation.declared_extension,
                    "detected_mime_type": validation.detected_mime_type,
                    "file_size_bytes": validation.file_size_bytes,
                    "has_double_extension": validation.has_double_extension,
                    "suspicious_extension": validation.suspicious_extension,
                    "errors": validation.errors,
                },
                error_message="; ".join(validation.errors) or None,
            )
        )

        if not validation.is_valid:

            os.remove(stored_path)

            investigation = self.investigations.update(
                investigation,
                status=InvestigationStatus.FAILED,
                error_message="; ".join(validation.errors),
                completed_at=datetime.now(timezone.utc),
            )

            # Still persist a FileRecord shell so history/reporting has
            # something to point to, with zeroed hashes since the file
            # was rejected before analysis and has been deleted.
            file_record = self.files.create(
                FileRecord(
                    investigation_id=investigation.id,
                    original_filename=original_filename,
                    stored_filename=stored_filename,
                    storage_path="",
                    declared_extension=validation.declared_extension,
                    detected_mime_type=validation.detected_mime_type,
                    file_size_bytes=file_size_bytes,
                    md5="",
                    sha1="",
                    sha256="",
                    sha512="",
                    extracted_metadata=None,
                    timeline=None,
                    uploaded_at=datetime.now(timezone.utc),
                )
            )

            return investigation, file_record

        hashes = hash_file(str(stored_path))

        self.investigations.add_result(
            InvestigationResult(
                investigation_id=investigation.id,
                source="hash_analysis",
                status=ModuleResultStatus.SUCCESS,
                data={
                    "md5": hashes.md5,
                    "sha1": hashes.sha1,
                    "sha256": hashes.sha256,
                    "sha512": hashes.sha512,
                },
            )
        )

        extracted_metadata = extract_metadata(
            path=str(stored_path),
            detected_mime_type=validation.detected_mime_type,
            declared_extension=validation.declared_extension,
        )

        metadata_status = ModuleResultStatus.SUCCESS

        if extracted_metadata.get("error"):
            metadata_status = ModuleResultStatus.FAILED

        elif not extracted_metadata.get("supported"):
            metadata_status = ModuleResultStatus.SKIPPED

        self.investigations.add_result(
            InvestigationResult(
                investigation_id=investigation.id,
                source="metadata_extraction",
                status=metadata_status,
                data=extracted_metadata,
                error_message=extracted_metadata.get("error"),
            )
        )

        timeline = build_timeline(
            path=str(stored_path),
            extracted_metadata=extracted_metadata,
        )

        self.investigations.add_result(
            InvestigationResult(
                investigation_id=investigation.id,
                source="timeline_analysis",
                status=ModuleResultStatus.SUCCESS,
                data=timeline,
            )
        )

        reputation_results, yara_result = await asyncio.gather(
            asyncio.gather(
                *(engine_cls().run(hashes.sha256) for engine_cls in _REPUTATION_ENGINES)
            ),
            asyncio.to_thread(YaraScanner().scan, str(stored_path)),
        )

        engine_results: list[IntegrationResult] = list(reputation_results) + [yara_result]

        for engine_result in engine_results:

            self.investigations.add_result(
                InvestigationResult(
                    investigation_id=investigation.id,
                    source=engine_result.source,
                    status=engine_result.status,
                    data=engine_result.data,
                    latency_ms=engine_result.latency_ms,
                    error_message=engine_result.error_message,
                )
            )

        metadata_engine_result = IntegrationResult(
            source="metadata_extraction",
            status=metadata_status,
            data=extracted_metadata,
            error_message=extracted_metadata.get("error"),
        )

        overall_status = self._overall_status([metadata_engine_result] + engine_results)

        file_record = self.files.create(
            FileRecord(
                investigation_id=investigation.id,
                original_filename=original_filename,
                stored_filename=stored_filename,
                storage_path=str(stored_path),
                declared_extension=validation.declared_extension,
                detected_mime_type=validation.detected_mime_type,
                file_size_bytes=file_size_bytes,
                md5=hashes.md5,
                sha1=hashes.sha1,
                sha256=hashes.sha256,
                sha512=hashes.sha512,
                extracted_metadata=extracted_metadata,
                timeline=timeline,
                uploaded_at=datetime.now(timezone.utc),
            )
        )

        results_by_source = {r.source: r for r in engine_results}
        results_by_source["metadata_extraction"] = metadata_engine_result

        risk_score, risk_notes = self._compute_risk_score(
            results_by_source=results_by_source,
            validation=validation,
        )

        # Investigation.target is updated to the sha256 once known, so
        # history search/filtering (Module 12) can find this file by
        # hash the same way other modules search by their own target.
        investigation = self.investigations.update(
            investigation,
            target=hashes.sha256,
            status=overall_status,
            risk_score=risk_score,
            risk_level=risk_level_from_score(risk_score),
            summary=self._build_summary(
                filename=original_filename,
                sha256=hashes.sha256,
                file_size_bytes=file_size_bytes,
                risk_notes=risk_notes,
            ),
            completed_at=datetime.now(timezone.utc),
        )

        return investigation, file_record

    def _overall_status(
        self,
        engine_results: list[IntegrationResult],
    ) -> InvestigationStatus:
        """
        Mirrors the same aggregation rule used by every other module's
        service layer: a source reporting SKIPPED (e.g. no API key
        configured) doesn't count against the investigation, since that's
        an operator configuration choice, not a failure of the analysis.
        """

        actionable = [
            r for r in engine_results if r.status != ModuleResultStatus.SKIPPED
        ]

        if not actionable:
            return InvestigationStatus.COMPLETED

        if all(r.status == ModuleResultStatus.FAILED for r in actionable):
            return InvestigationStatus.PARTIAL

        if any(r.status == ModuleResultStatus.FAILED for r in actionable):
            return InvestigationStatus.PARTIAL

        return InvestigationStatus.COMPLETED

    # ==========================================================
    # Risk Engine (Milestone 6 Part 3)
    # ==========================================================

    #: YARA rule `severity` meta value -> score contribution per match.
    _YARA_SEVERITY_WEIGHTS = {
        "high": 20,
        "medium": 10,
        "info": 2,
    }

    def _compute_risk_score(
        self,
        *,
        results_by_source: dict[str, IntegrationResult],
        validation: FileValidationResult,
    ) -> tuple[float, list[str]]:
        """
        Combines file reputation, YARA matches, and metadata/extension
        risk indicators into a single 0-100 score, using the same
        additive-then-clamp shape as every other module's risk engine
        (see ip_service._compute_risk_score). A SKIPPED source (no API
        key configured) contributes nothing either way - absence of
        data is not evidence of safety or danger.
        """

        score = 0.0
        notes: list[str] = []

        # --- VirusTotal -----------------------------------------------
        virustotal = results_by_source.get("virustotal_file")

        if virustotal and virustotal.status == ModuleResultStatus.SUCCESS and virustotal.data:

            stats = virustotal.data.get("analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)

            if malicious:
                score += clamp(malicious * 6, high=40)
                notes.append(f"{malicious} VirusTotal vendor(s) flagged malicious")

            if suspicious:
                score += clamp(suspicious * 3, high=15)
                notes.append(f"{suspicious} VirusTotal vendor(s) flagged suspicious")

        # --- MalwareBazaar ----------------------------------------------
        malwarebazaar = results_by_source.get("malwarebazaar")

        if (
            malwarebazaar
            and malwarebazaar.status == ModuleResultStatus.SUCCESS
            and malwarebazaar.data
            and malwarebazaar.data.get("known_to_malwarebazaar")
        ):

            score += 35
            signature = malwarebazaar.data.get("signature") or "unclassified sample"
            notes.append(f"Known malware sample on MalwareBazaar ({signature})")

        # --- Hybrid Analysis --------------------------------------------
        hybrid_analysis = results_by_source.get("hybrid_analysis")

        if (
            hybrid_analysis
            and hybrid_analysis.status == ModuleResultStatus.SUCCESS
            and hybrid_analysis.data
            and hybrid_analysis.data.get("known_to_hybrid_analysis")
        ):

            verdict = hybrid_analysis.data.get("verdict")
            threat_score = hybrid_analysis.data.get("threat_score") or 0

            if verdict == "malicious":
                score += 30
                notes.append("Hybrid Analysis sandbox verdict: malicious")

            elif verdict == "suspicious":
                score += 15
                notes.append("Hybrid Analysis sandbox verdict: suspicious")

            if threat_score:
                score += clamp(threat_score * 0.2, high=20)

        # --- YARA ---------------------------------------------------------
        yara_result = results_by_source.get("yara_scan")

        if yara_result and yara_result.status == ModuleResultStatus.SUCCESS and yara_result.data:

            matches = yara_result.data.get("matches", [])
            yara_score = 0.0

            for match in matches:

                severity = (match.get("meta") or {}).get("severity", "info")
                yara_score += self._YARA_SEVERITY_WEIGHTS.get(severity, 2)
                notes.append(f"YARA rule matched: {match.get('rule')}")

            score += clamp(yara_score, high=40)

        # --- Extension / metadata risk indicators ------------------------
        if validation.has_double_extension:
            score += 10
            notes.append("Double file extension detected")

        metadata_result = results_by_source.get("metadata_extraction")

        if (
            metadata_result
            and metadata_result.status == ModuleResultStatus.SUCCESS
            and metadata_result.data
            and metadata_result.data.get("is_encrypted")
        ):
            score += 8
            notes.append("PDF is password-protected/encrypted")

        return clamp(score), notes

    def _build_summary(
        self,
        *,
        filename: str,
        sha256: str,
        file_size_bytes: int,
        risk_notes: list[str],
    ) -> str:

        prefix = f"'{filename}' (sha256={sha256[:16]}..., {file_size_bytes} bytes)"

        if not risk_notes:
            return f"No notable risk signals found for {prefix}."

        return f"Risk signals for {prefix}: " + "; ".join(risk_notes) + "."
