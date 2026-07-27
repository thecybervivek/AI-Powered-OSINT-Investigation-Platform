import os
import tempfile

import pytest
from PIL import Image

from backend.app.integrations.base import IntegrationResult
from backend.app.models.investigation import ModuleResultStatus
from backend.app.services.reverse_image_service import ReverseImageIntelligenceService
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
        filename="photo.jpg",
        sha256="a" * 64,
        risk_notes=[],
    )

    assert "No notable risk signals" in summary
    assert "photo.jpg" in summary


def test_build_summary_joins_risk_notes():

    service = _service()

    summary = service._build_summary(
        filename="photo.jpg",
        sha256="a" * 64,
        risk_notes=["GPS coordinates embedded in image metadata"],
    )

    assert "GPS coordinates embedded" in summary
