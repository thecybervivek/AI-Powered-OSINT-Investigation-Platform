import os
import uuid
from datetime import datetime
from datetime import timezone
from pathlib import Path

from fastapi import UploadFile
from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.models.file_record import FileRecord
from backend.app.models.investigation import Investigation
from backend.app.models.investigation import InvestigationResult
from backend.app.models.investigation import InvestigationStatus
from backend.app.models.investigation import InvestigationType
from backend.app.models.investigation import ModuleResultStatus
from backend.app.repositories.file_repository import FileRecordRepository
from backend.app.repositories.investigation_repository import InvestigationRepository
from backend.app.utils.file_hashing import hash_file
from backend.app.utils.file_validation import sanitize_filename
from backend.app.utils.file_validation import validate_upload
from backend.app.utils.metadata_extraction import extract_metadata
from backend.app.utils.timeline_builder import build_timeline


class FileIntelligenceService:
    """
    Orchestrates Milestone 6 Part 1: securely persists an upload to disk,
    validates it (size/extension/double-extension/magic-byte MIME),
    computes all four hashes in one streamed pass, extracts type-specific
    metadata (EXIF / PDF / DOCX / PPTX / XLSX), builds a timeline, and
    records everything as one Investigation + FileRecord + per-stage
    InvestigationResult rows - the same shape every other module uses.

    Reputation lookups (VirusTotal/MalwareBazaar/HybridAnalysis), YARA
    scanning, and the composite risk engine are layered on top of this
    in Part 2 / Part 3 without changing what's persisted here.
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

        # Investigation.target is updated to the sha256 once known, so
        # history search/filtering (Module 12) can find this file by
        # hash the same way other modules search by their own target.
        investigation = self.investigations.update(
            investigation,
            target=hashes.sha256,
            status=InvestigationStatus.COMPLETED,
            summary=(
                f"File '{original_filename}' analyzed "
                f"(sha256={hashes.sha256}, {file_size_bytes} bytes). "
                f"Reputation/YARA/risk scoring land in later milestones."
            ),
            completed_at=datetime.now(timezone.utc),
        )

        return investigation, file_record
