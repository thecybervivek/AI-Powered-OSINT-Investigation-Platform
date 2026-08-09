import json
import os
import tempfile

import pytest
from PIL import Image

from backend.app.integrations.base import IntegrationResult
from backend.app.models.investigation import ModuleResultStatus
from backend.app.services.reverse_image_service import ReverseImageIntelligenceService
from backend.app.utils.metadata_extraction import extract_metadata
from backend.app.utils.perceptual_hashing import compute_perceptual_hashes
from backend.app.utils.perceptual_hashing import hamming_distance
from backend.app.utils.perceptual_hashing import is_near_duplicate
from backend.app.utils.perceptual_hashing import similarity_score


def _service() -> ReverseImageIntelligenceService:
    # _compute_risk_score/_build_summary touch no database state, so a
    # None db is safe here - same pattern already used by
    # tests/test_phone_intelligence.py and test_file_intelligence_part3.py.
    return ReverseImageIntelligenceService(db=None)


def _write_image(path: str, pixel_fn) -> None:
    """
    Builds a 128x128 RGB image whose pixel value at (x, y) is given by
    `pixel_fn(x, y)` - structured enough that ahash/dhash/phash all have
    real signal to work with (a flat solid color hashes to all-zero
    bits regardless of content, which wouldn't exercise anything).
    """

    image = Image.new("RGB", (128, 128))
    pixels = image.load()

    for x in range(128):
        for y in range(128):
            pixels[x, y] = pixel_fn(x, y)

    image.save(path)


@pytest.fixture
def original_image():

    fd, path = tempfile.mkstemp(suffix=".png")
    os.close(fd)

    _write_image(path, lambda x, y: ((x * 3) % 256, (y * 5) % 256, ((x + y) * 2) % 256))

    yield path
    os.remove(path)


@pytest.fixture
def near_duplicate_image():
    """
    Same underlying pattern as `original_image`, saved at a different
    resolution and as a re-compressed JPEG - simulates a re-upload of
    the same photo, which is exactly what perceptual (not cryptographic)
    hashing is meant to still recognize as related.
    """

    fd, path = tempfile.mkstemp(suffix=".jpg")
    os.close(fd)

    tmp_png = path + ".png"
    _write_image(tmp_png, lambda x, y: ((x * 3) % 256, (y * 5) % 256, ((x + y) * 2) % 256))

    with Image.open(tmp_png) as image:
        image.resize((100, 100)).save(path, quality=80)

    os.remove(tmp_png)

    yield path
    os.remove(path)


@pytest.fixture
def unrelated_image():

    fd, path = tempfile.mkstemp(suffix=".png")
    os.close(fd)

    _write_image(path, lambda x, y: (255 - (x * 3) % 256, (y * y) % 256, (x * y) % 256))

    yield path
    os.remove(path)


# ==========================================================
# compute_perceptual_hashes / hamming_distance (real algorithms)
# ==========================================================

def test_identical_image_has_zero_hamming_distance(original_image):

    hashes = compute_perceptual_hashes(original_image)

    assert hamming_distance(hashes.phash, hashes.phash) == 0
    assert hamming_distance(hashes.ahash, hashes.ahash) == 0
    assert hamming_distance(hashes.dhash, hashes.dhash) == 0


def test_hashes_are_64_bit_hex_strings(original_image):

    hashes = compute_perceptual_hashes(original_image)

    for value in (hashes.phash, hashes.ahash, hashes.dhash):
        assert len(value) == 16  # 64 bits -> 16 hex characters
        int(value, 16)  # raises ValueError if not valid hex


def test_near_duplicate_is_closer_than_unrelated_image(
    original_image,
    near_duplicate_image,
    unrelated_image,
):

    original = compute_perceptual_hashes(original_image)
    near_dup = compute_perceptual_hashes(near_duplicate_image)
    unrelated = compute_perceptual_hashes(unrelated_image)

    distance_to_near_dup = hamming_distance(original.phash, near_dup.phash)
    distance_to_unrelated = hamming_distance(original.phash, unrelated.phash)

    assert distance_to_near_dup < distance_to_unrelated
    assert is_near_duplicate(distance_to_near_dup)
    assert not is_near_duplicate(distance_to_unrelated)


def test_hamming_distance_rejects_mismatched_lengths():

    with pytest.raises(ValueError):
        hamming_distance("ab", "abcd")


def test_similarity_score_boundaries():

    assert similarity_score(0) == 100.0
    assert similarity_score(64) == 0.0
    assert 0.0 <= similarity_score(10) <= 100.0


def test_is_near_duplicate_threshold_boundary():

    assert is_near_duplicate(10) is True
    assert is_near_duplicate(11) is False


# ==========================================================
# ReverseImageIntelligenceService risk scoring (pure logic, no DB)
# ==========================================================

def test_risk_score_zero_when_nothing_notable():

    service = _service()

    score, notes = service._compute_risk_score(
        extracted_metadata={},
        duplicate_data={"exact_duplicate_found": False, "near_duplicate_found": False},
        perceptual_error=None,
    )

    assert score == 0.0
    assert notes == []


def test_risk_score_flags_embedded_gps():

    service = _service()

    score, notes = service._compute_risk_score(
        extracted_metadata={"gps": {"GPSLatitude": 1.0}},
        duplicate_data={"exact_duplicate_found": False, "near_duplicate_found": False},
        perceptual_error=None,
    )

    assert score > 0
    assert any("GPS" in note for note in notes)


def test_risk_score_flags_exact_duplicate():

    service = _service()

    score, notes = service._compute_risk_score(
        extracted_metadata={},
        duplicate_data={"exact_duplicate_found": True, "near_duplicate_found": False},
        perceptual_error=None,
    )

    assert score > 0
    assert any("already investigated" in note.lower() for note in notes)


def test_risk_score_flags_near_duplicate_with_similarity():

    service = _service()

    score, notes = service._compute_risk_score(
        extracted_metadata={},
        duplicate_data={
            "exact_duplicate_found": False,
            "near_duplicate_found": True,
            "similarity_score": 92.5,
        },
        perceptual_error=None,
    )

    assert score > 0
    assert any("similar" in note.lower() for note in notes)


def test_risk_score_flags_perceptual_hashing_failure():

    service = _service()

    score, notes = service._compute_risk_score(
        extracted_metadata={},
        duplicate_data={"exact_duplicate_found": False, "near_duplicate_found": False},
        perceptual_error="Perceptual hashing failed: cannot identify image file",
    )

    assert score > 0
    assert any("fingerprint" in note.lower() for note in notes)


def test_build_summary_reports_no_risk_when_notes_empty():

    service = _service()

    summary = service._build_summary(
        assessment_data={
            "state": "no_public_matches_found",
            "reasoning": [],
        },
        extracted_metadata={},
    )

    assert "No GPS coordinates detected." in summary
    assert "No public reverse image providers were configured." in summary
    assert "No matching public copies were identified" in summary


def test_build_summary_joins_risk_notes():

    service = _service()

    summary = service._build_summary(
        assessment_data={
            "state": "image_matches_found",
            "reasoning": [
                "GPS coordinates embedded in image metadata",
            ],
        },
        extracted_metadata={
            "gps": {
                "latitude": 28.6139,
                "longitude": 77.2090,
            }
        },
    )

    assert "GPS coordinates were detected" in summary
    assert "GPS coordinates embedded in image metadata" in summary

# ==========================================================
# Regression: 502 root cause
# ==========================================================
#
# The reported Reverse Image 502 traced back to metadata_extraction.py
# returning raw PIL EXIF values into a dict that gets stored straight
# into a plain SQLAlchemy `JSON` column (InvestigationResult.data /
# ImageFingerprint.extracted_metadata). Real camera/phone EXIF commonly
# contains `PIL.TiffImagePlugin.IFDRational` (ExposureTime, FNumber,
# FocalLength, GPSLatitude/Longitude/Altitude) and raw `bytes`
# (GPSAltitudeRef and similar GPS sub-tags) - neither of which
# `json.dumps` can serialize, so `db.commit()` raised a `TypeError`
# that the endpoint's blanket `except Exception` turned into an opaque,
# unlogged 502. The prior test suite only ever exercised PIL-generated
# PNGs with zero EXIF, so this path was never covered.


@pytest.fixture
def photo_with_camera_exif():
    """
    A real (re-decoded, not hand-built) JPEG carrying the kind of EXIF
    a phone/camera actually produces: rational tags (ExposureTime,
    FNumber) plus a GPS IFD with rational lat/long/altitude and a raw
    `bytes` GPSAltitudeRef - i.e. exactly the tag shapes that were
    crashing JSON persistence.
    """

    fd, path = tempfile.mkstemp(suffix=".jpg")
    os.close(fd)

    image = Image.new("RGB", (64, 64), color=(120, 40, 200))

    exif = image.getexif()
    exif[33434] = 0.033  # ExposureTime
    exif[33437] = 2.8  # FNumber
    exif[34853] = {  # GPSInfo IFD
        1: "N",
        2: (37.0, 46.0, 30.5),  # GPSLatitude (deg, min, sec)
        3: "W",
        4: (122.0, 25.0, 10.2),  # GPSLongitude
        5: 0,  # GPSAltitudeRef -> round-trips as bytes b"\x00"
        6: 12.5,  # GPSAltitude
    }

    image.save(path, exif=exif)

    yield path
    os.remove(path)


def test_extract_metadata_is_json_serializable_for_real_camera_exif(
    photo_with_camera_exif,
):
    """
    Reproduces the exact failure: without sanitization, this dict
    contains IFDRational/bytes values and `json.dumps` raises
    `TypeError: Object of type IFDRational is not JSON serializable`.
    """

    metadata = extract_metadata(
        path=photo_with_camera_exif,
        detected_mime_type="image/jpeg",
        declared_extension=".jpg",
    )

    # Must not raise - this is what SQLAlchemy's JSON column encoder
    # does on commit.
    json.dumps(metadata)

    assert metadata["supported"] is True
    assert metadata["gps"]["GPSLatitude"] == [37.0, 46.0, 30.5]
    assert isinstance(metadata["exif"]["ExposureTime"], float)


def test_extract_metadata_handles_gps_bytes_subtag(photo_with_camera_exif):
    """
    GPSAltitudeRef round-trips through Pillow as raw `bytes`, which the
    original code only decoded for the top-level EXIF dict, not the
    nested GPS IFD dict. Confirms it's coerced to a JSON-safe string
    rather than crashing or being silently dropped.
    """

    metadata = extract_metadata(
        path=photo_with_camera_exif,
        detected_mime_type="image/jpeg",
        declared_extension=".jpg",
    )

    assert "GPSAltitudeRef" in metadata["gps"]
    assert isinstance(metadata["gps"]["GPSAltitudeRef"], str)


def test_upload_endpoint_succeeds_for_real_photo_with_gps_exif(
    client,
    auth_headers,
    photo_with_camera_exif,
):
    """
    End-to-end regression for the reported 502: uploads a real photo
    carrying camera/GPS EXIF (the exact shape that crashed JSON-column
    persistence) through the actual HTTP endpoint. Before the fix this
    returned 502 with no diagnostic detail; it must now succeed (201)
    and the GPS metadata must round-trip in the response.
    """

    with open(photo_with_camera_exif, "rb") as handle:
        response = client.post(
            "/api/v1/investigations/reverse-image/upload",
            files={"file": ("photo.jpg", handle, "image/jpeg")},
            headers=auth_headers,
        )

    assert response.status_code == 201, response.text

    body = response.json()

    assert body["investigation"]["status"] == "completed"
    assert body["image"]["extracted_metadata"]["gps"]["GPSLatitude"] == [
        37.0,
        46.0,
        30.5,
    ]
