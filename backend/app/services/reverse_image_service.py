import asyncio
import os
import uuid
from datetime import datetime
from datetime import timezone
from pathlib import Path

from fastapi import UploadFile
from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.core.paths import resolve_project_path
from backend.app.models.image_fingerprint import ImageFingerprint
from backend.app.models.investigation import Investigation
from backend.app.models.investigation import InvestigationResult
from backend.app.models.investigation import InvestigationStatus
from backend.app.models.investigation import InvestigationType
from backend.app.models.investigation import ModuleResultStatus
from backend.app.repositories.image_fingerprint_repository import ImageFingerprintRepository
from backend.app.repositories.investigation_repository import InvestigationRepository
from backend.app.utils.file_hashing import hash_file
from backend.app.utils.file_validation import sanitize_filename
from backend.app.utils.file_validation import validate_upload
from backend.app.utils.metadata_extraction import extract_metadata
from backend.app.utils.perceptual_hashing import PerceptualHashes
from backend.app.utils.perceptual_hashing import compute_perceptual_hashes
from backend.app.utils.perceptual_hashing import hamming_distance
from backend.app.utils.perceptual_hashing import is_near_duplicate
from backend.app.utils.perceptual_hashing import similarity_score
from backend.app.utils.risk_scoring import clamp
from backend.app.utils.risk_scoring import risk_level_from_score
from backend.app.integrations.base import IntegrationResult

class ReverseImageIntelligenceService:
    """
    Orchestrates Milestone 9 Part 2 (Reverse Image Intelligence):
    securely persists an uploaded image, computes cryptographic hashes
    (reusing Milestone 6's hash_file) and perceptual hashes (phash/
    ahash/dhash), extracts EXIF/GPS metadata (reusing Milestone 6's
    extract_metadata dispatcher), and checks it against every image this
    same user has previously investigated for exact or near-duplicate
    matches - all combined into one risk-scored Investigation +
    ImageFingerprint record, the same shape File Intelligence uses.

    This deliberately does NOT call out to any third-party reverse-
    image-search service: genuine "search the whole internet for this
    image" APIs either require a paid commercial contract this project
    has no credentials for, or amount to scraping a consumer search
    engine's UI in violation of its Terms of Service. Duplicate
    detection here is scoped to the analyst's own investigation history,
    which is both fully within this platform's control and a real,
    common OSINT use case (e.g. "has this profile picture shown up in
    a prior case?").
    """

    def __init__(self, db: Session) -> None:
        self.db = db
        self.investigations = InvestigationRepository(db)
        self.images = ImageFingerprintRepository(db)

    async def investigate(
        self,
        *,
        user_id: str,
        upload: UploadFile,
    ) -> tuple[Investigation, ImageFingerprint]:

        investigation = self.investigations.create(
            Investigation(
                user_id=user_id,
                investigation_type=InvestigationType.REVERSE_IMAGE,
                target=upload.filename or "unnamed_upload",
                status=InvestigationStatus.RUNNING,
                started_at=datetime.now(timezone.utc),
            )
        )

        storage_dir = resolve_project_path(settings.IMAGE_STORAGE_DIR)
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

        validation_errors = list(validation.errors)

        is_valid_image = validation.is_valid and (
            validation.detected_mime_type or ""
        ).startswith("image/")

        if validation.is_valid and not is_valid_image:
            validation_errors.append(
                "This endpoint only accepts image files "
                f"(detected type: {validation.detected_mime_type or 'unknown'})."
            )

        self.investigations.add_result(
            InvestigationResult(
                investigation_id=investigation.id,
                source="file_validation",
                status=(
                    ModuleResultStatus.SUCCESS
                    if is_valid_image
                    else ModuleResultStatus.FAILED
                ),
                data={
                    "declared_extension": validation.declared_extension,
                    "detected_mime_type": validation.detected_mime_type,
                    "file_size_bytes": validation.file_size_bytes,
                    "has_double_extension": validation.has_double_extension,
                    "suspicious_extension": validation.suspicious_extension,
                    "errors": validation_errors,
                },
                error_message="; ".join(validation_errors) or None,
            )
        )

        if not is_valid_image:

            os.remove(stored_path)

            investigation = self.investigations.update(
                investigation,
                status=InvestigationStatus.FAILED,
                error_message="; ".join(validation_errors),
                completed_at=datetime.now(timezone.utc),
            )

            image_record = self.images.create(
                ImageFingerprint(
                    investigation_id=investigation.id,
                    user_id=user_id,
                    original_filename=original_filename,
                    stored_filename=stored_filename,
                    storage_path="",
                    detected_mime_type=validation.detected_mime_type,
                    file_size_bytes=file_size_bytes,
                    width=None,
                    height=None,
                    md5="",
                    sha1="",
                    sha256="",
                    sha512="",
                    phash=None,
                    ahash=None,
                    dhash=None,
                    extracted_metadata=None,
                    uploaded_at=datetime.now(timezone.utc),
                )
            )

            return investigation, image_record

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

        perceptual_hashes, dimensions, perceptual_error = await self._compute_fingerprint(
            str(stored_path)
        )

        self.investigations.add_result(
            InvestigationResult(
                investigation_id=investigation.id,
                source="perceptual_hashing",
                status=(
                    ModuleResultStatus.FAILED
                    if perceptual_error
                    else ModuleResultStatus.SUCCESS
                ),
                data=(
                    {
                        "phash": perceptual_hashes.phash,
                        "ahash": perceptual_hashes.ahash,
                        "dhash": perceptual_hashes.dhash,
                        "width": dimensions[0],
                        "height": dimensions[1],
                    }
                    if perceptual_hashes
                    else {}
                ),
                error_message=perceptual_error,
            )
        )

        extracted_metadata = await asyncio.to_thread(
            extract_metadata,
            path=str(stored_path),
            detected_mime_type=validation.detected_mime_type,
            declared_extension=validation.declared_extension,
        )

        metadata_status = (
            ModuleResultStatus.FAILED
            if extracted_metadata.get("error")
            else ModuleResultStatus.SUCCESS
        )

        self.investigations.add_result(
            InvestigationResult(
                investigation_id=investigation.id,
                source="metadata_extraction",
                status=metadata_status,
                data=extracted_metadata,
                error_message=extracted_metadata.get("error"),
            )
        )

        duplicate_data = self._detect_duplicates(
            user_id=user_id,
            sha256=hashes.sha256,
            phash=perceptual_hashes.phash if perceptual_hashes else None,
        )

        self.investigations.add_result(
            InvestigationResult(
                investigation_id=investigation.id,
                source="duplicate_detection",
                status=ModuleResultStatus.SUCCESS,
                data=duplicate_data,
            )
        )

        image_record = self.images.create(
            ImageFingerprint(
                investigation_id=investigation.id,
                user_id=user_id,
                original_filename=original_filename,
                stored_filename=stored_filename,
                storage_path=str(stored_path),
                detected_mime_type=validation.detected_mime_type,
                file_size_bytes=file_size_bytes,
                width=dimensions[0] if dimensions else None,
                height=dimensions[1] if dimensions else None,
                md5=hashes.md5,
                sha1=hashes.sha1,
                sha256=hashes.sha256,
                sha512=hashes.sha512,
                phash=perceptual_hashes.phash if perceptual_hashes else None,
                ahash=perceptual_hashes.ahash if perceptual_hashes else None,
                dhash=perceptual_hashes.dhash if perceptual_hashes else None,
                extracted_metadata=extracted_metadata,
                uploaded_at=datetime.now(timezone.utc),
            )
        )

        risk_score, risk_notes = self._compute_risk_score(
            extracted_metadata=extracted_metadata,
            duplicate_data=duplicate_data,
            perceptual_error=perceptual_error,
        )

        assessment = _build_reverse_image_assessment(
            duplicate_data=duplicate_data,
            extracted_metadata=extracted_metadata,
            perceptual_error=perceptual_error,
        )
        self.investigations.add_result(
            InvestigationResult(
                investigation_id=investigation.id,
                source="threat_assessment",
                status=ModuleResultStatus.SUCCESS,
                data=assessment.data,
            )
        )

        investigation = self.investigations.update(
            investigation,
            target=hashes.sha256,
            status=InvestigationStatus.COMPLETED,
            risk_score=risk_score,
            risk_level=risk_level_from_score(risk_score),
            summary=self._build_summary(
                assessment_data=assessment.data,
                extracted_metadata=extracted_metadata,
            ),
            completed_at=datetime.now(timezone.utc),
        )

        return investigation, image_record

    async def _compute_fingerprint(
        self,
        path: str,
    ) -> tuple[PerceptualHashes | None, tuple[int, int] | None, str | None]:
        """
        Perceptual hashing + dimension read are CPU-bound Pillow/numpy
        work with no I/O wait, so they're offloaded to a worker thread
        (asyncio.to_thread) rather than blocking the event loop - same
        pattern Milestone 6 uses for its YARA scan.
        """

        try:
            hashes = await asyncio.to_thread(compute_perceptual_hashes, path)

            from PIL import Image

            with Image.open(path) as image:
                dimensions = (image.width, image.height)

            return hashes, dimensions, None

        except Exception as error:
            return None, None, f"Perceptual hashing failed: {error}"

    def _detect_duplicates(
        self,
        *,
        user_id: str,
        sha256: str,
        phash: str | None,
    ) -> dict:

        exact_match = self.images.find_exact_duplicate(
            user_id=user_id,
            sha256=sha256,
        )

        near_match_investigation_id: str | None = None
        near_match_distance: int | None = None
        near_match_similarity: float | None = None

        if phash:

            candidates = self.images.list_by_user(user_id=user_id)

            for candidate in candidates:

                if not candidate.phash or candidate.sha256 == sha256:
                    continue

                distance = hamming_distance(phash, candidate.phash)

                if near_match_distance is None or distance < near_match_distance:
                    near_match_distance = distance
                    near_match_investigation_id = candidate.investigation_id

            if near_match_distance is not None:
                near_match_similarity = similarity_score(near_match_distance)

        return {
            "exact_duplicate_found": exact_match is not None,
            "exact_duplicate_investigation_id": (
                exact_match.investigation_id if exact_match else None
            ),
            "near_duplicate_found": (
                near_match_distance is not None
                and is_near_duplicate(near_match_distance)
            ),
            "closest_match_investigation_id": near_match_investigation_id,
            "closest_match_hamming_distance": near_match_distance,
            "similarity_score": near_match_similarity,
        }

    def _compute_risk_score(
        self,
        *,
        extracted_metadata: dict,
        duplicate_data: dict,
        perceptual_error: str | None,
    ) -> tuple[float, list[str]]:
        """
        Flags OSINT-relevant exposure/correlation signals - not a
        judgment about the image's content, which this module never
        inspects: embedded GPS coordinates (a privacy-exposure signal
        common across OSINT modules), and image reuse across this
        user's own investigation history (a correlation signal an
        analyst would want surfaced, e.g. the same photo reappearing
        under a different alias).
        """

        score = 0.0
        notes: list[str] = []

        if extracted_metadata.get("gps"):
            score += 15
            notes.append("GPS coordinates embedded in image metadata")

        if duplicate_data.get("exact_duplicate_found"):
            score += 10
            notes.append("Identical image already investigated previously")

        elif duplicate_data.get("near_duplicate_found"):
            similarity = duplicate_data.get("similarity_score") or 0
            score += clamp(similarity * 0.1, high=8)
            notes.append(
                f"Visually similar to a previously investigated image "
                f"({similarity}% similarity)"
            )

        if perceptual_error:
            score += 5
            notes.append("Image could not be fully fingerprinted")

        return clamp(score), notes

    def _build_summary(
            self,
            *,
            assessment_data: dict,
            extracted_metadata: dict,
        ) -> str:
            """
            An analyst-style conclusion, matching the production-polish spec's
            example almost field for field.
            """
    
            sentences = ["Image metadata extracted."]
    
            gps = extracted_metadata.get("gps") if extracted_metadata else None
    
            if gps:
                sentences.append(
                    "GPS coordinates were detected in the image's EXIF data."
                )
            else:
                sentences.append("No GPS coordinates detected.")
    
            sentences.append("No public reverse image providers were configured.")
    
            state = assessment_data.get("state")
    
            if state == "image_matches_found":
                reasoning = assessment_data.get("reasoning", [])
                sentences.append(
                    "; ".join(reasoning) + "."
                    if reasoning
                    else "A match was found against a previously investigated image."
                )
            else:
                sentences.append(
                    "No matching public copies were identified from available evidence."
                )
    
            return " ".join(sentences)


# ==========================================================
# Evidence-backed assessment (replaces bare Risk Score as the
# primary conclusion for Reverse Image Investigation - production-
# polish item 1)
# ==========================================================

# No public reverse-image-search provider (Google Lens, Bing Visual
# Search, TinEye, Yandex, SauceNAO, IQDB) is implemented anywhere in
# this repository - confirmed by directory listing. Listed as
# unavailable for transparency; never presented as if any of them ran.
_PUBLIC_REVERSE_IMAGE_PROVIDERS = (
    "google_lens",
    "bing_visual_search",
    "tineye",
    "yandex",
    "saucenao",
    "iqdb",
)


def _build_reverse_image_assessment(
    *,
    duplicate_data: dict | None,
    extracted_metadata: dict,
    perceptual_error: str | None,
) -> IntegrationResult:
    """
    States: image_matches_found, no_public_matches_found,
    metadata_only, investigation_incomplete.

    Only two real signal sources exist in this codebase today:
    internal fingerprint correlation (exact/near-duplicate matches
    against this account's own previously investigated images) and
    metadata/EXIF extraction. There is no public reverse-image-search
    capability at all - "no_public_matches_found" is used honestly
    here to mean "internal correlation checked, nothing found," with
    that distinction stated explicitly in the reasoning rather than
    implied to be a broader web search.
    """

    reasoning: list[str] = []

    duplicate_ran = duplicate_data is not None and "exact_duplicate_found" in (
        duplicate_data or {}
    )
    metadata_ran = bool(extracted_metadata) and extracted_metadata.get("error") is None

    if duplicate_ran and (
        duplicate_data.get("exact_duplicate_found")
        or duplicate_data.get("near_duplicate_found")
    ):
        state = "image_matches_found"
        label = "Image matches found"

        if duplicate_data.get("exact_duplicate_found"):
            reasoning.append(
                "Identical to a previously investigated image in this account's history"
            )
        else:
            similarity = duplicate_data.get("similarity_score")
            reasoning.append(
                f"Near-duplicate match found ({similarity}% similarity) against a "
                "previously investigated image in this account's history"
                if similarity is not None
                else "Near-duplicate match found against a previously investigated image"
            )

    elif duplicate_ran:
        state = "no_public_matches_found"
        label = "No public matches found"
        reasoning.append(
            "No match found against this account's previously investigated images. "
            "No public reverse-image-search provider was consulted - none is "
            "configured in this deployment."
        )

    elif metadata_ran:
        state = "metadata_only"
        label = "Metadata only"
        reasoning.append(
            "Image metadata was extracted, but similarity/duplicate correlation "
            "could not be completed" + (f": {perceptual_error}" if perceptual_error else ".")
        )

    else:
        state = "investigation_incomplete"
        label = "Investigation incomplete"
        reasoning.append(
            "Neither metadata extraction nor duplicate correlation could be completed."
        )

    return IntegrationResult(
    source="threat_assessment",
    status=ModuleResultStatus.SUCCESS,
    data={
        "state": state,
        "label": label,
        "reasoning": reasoning,
        "providers_unavailable": list(_PUBLIC_REVERSE_IMAGE_PROVIDERS),
    },
)
