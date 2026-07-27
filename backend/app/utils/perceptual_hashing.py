from dataclasses import dataclass

import numpy as np
from PIL import Image
from scipy.fftpack import dct

#: average_hash/phash/dhash are all 8x8-block hashes -> 64 bits each.
_HASH_SIZE = 8
_HASH_BITS = _HASH_SIZE * _HASH_SIZE

#: phash resizes to _HASH_SIZE * _PHASH_OVERSAMPLE before the DCT so the
#: low-frequency 8x8 block actually carries meaningful signal - the
#: standard perceptual-hash construction (same factor libraries such as
#: ImageHash use for their DCT-based phash).
_PHASH_OVERSAMPLE = 4

#: Hamming distance (out of 64 bits) at or below which two images are
#: treated as near-duplicates. 10 is the commonly cited threshold for
#: phash-based duplicate detection - small enough to reject unrelated
#: images, large enough to survive re-compression/resizing/minor edits.
NEAR_DUPLICATE_HAMMING_THRESHOLD = 10


@dataclass(frozen=True)
class PerceptualHashes:

    phash: str
    ahash: str
    dhash: str


def _bits_to_hex(bits: np.ndarray) -> str:
    """
    Packs a flattened boolean array (row-major, MSB first) into a
    zero-padded hex string - e.g. 64 bits -> 16 hex characters.
    """

    flat = bits.flatten()
    bit_string = "".join("1" if bit else "0" for bit in flat)

    return f"{int(bit_string, 2):0{len(bit_string) // 4}x}"


def _average_hash(grayscale: Image.Image) -> str:
    """
    Fastest, most sensitive to global brightness changes: resize to a
    tiny 8x8 thumbnail and mark each pixel against the thumbnail's own
    mean brightness.
    """

    resized = grayscale.resize(
        (_HASH_SIZE, _HASH_SIZE),
        Image.Resampling.LANCZOS,
    )
    pixels = np.asarray(resized, dtype=np.float64)

    return _bits_to_hex(pixels > pixels.mean())


def _difference_hash(grayscale: Image.Image) -> str:
    """
    Robust to the same transformations as phash via a gradient-based
    method instead: resize to 9x8 and mark whether each pixel is
    brighter than its immediate horizontal neighbor.
    """

    resized = grayscale.resize(
        (_HASH_SIZE + 1, _HASH_SIZE),
        Image.Resampling.LANCZOS,
    )
    pixels = np.asarray(resized, dtype=np.float64)

    return _bits_to_hex(pixels[:, 1:] > pixels[:, :-1])


def _perceptual_hash(grayscale: Image.Image) -> str:
    """
    The primary similarity metric used by the risk/duplicate engine:
    resize to a larger 32x32 thumbnail, take a 2D discrete cosine
    transform (concentrates the image's visual structure into its
    low-frequency coefficients), keep only the top-left 8x8 low-
    frequency block, and mark each coefficient against that block's own
    median. This is the standard DCT-based perceptual hash construction
    - robust to scaling, minor color adjustments, and re-compression,
    since those transformations barely disturb low-frequency structure.
    """

    size = _HASH_SIZE * _PHASH_OVERSAMPLE

    resized = grayscale.resize((size, size), Image.Resampling.LANCZOS)
    pixels = np.asarray(resized, dtype=np.float64)

    dct_full = dct(dct(pixels, axis=0, norm="ortho"), axis=1, norm="ortho")
    dct_low_freq = dct_full[:_HASH_SIZE, :_HASH_SIZE]

    return _bits_to_hex(dct_low_freq > np.median(dct_low_freq))


def compute_perceptual_hashes(path: str) -> PerceptualHashes:
    """
    Computes three complementary perceptual hashes for the image at
    `path`, each returned as a hex string suitable for storage/
    comparison. Implemented directly on Pillow + NumPy/SciPy (both
    already project dependencies via Milestone 6's metadata extraction
    and Milestone 4-5's risk-scoring math) rather than adding a
    dedicated perceptual-hashing package for three well-documented,
    ~10-line algorithms.
    """

    with Image.open(path) as image:

        # Perceptual hashing needs pixel data, not a lazy/truncated
        # image handle - force a full decode, then grayscale once and
        # reuse it for all three hashes.
        grayscale = image.convert("L")

        return PerceptualHashes(
            phash=_perceptual_hash(grayscale),
            ahash=_average_hash(grayscale),
            dhash=_difference_hash(grayscale),
        )


def hamming_distance(hash_hex_a: str, hash_hex_b: str) -> int:
    """
    Bit-level Hamming distance between two same-length hex-encoded
    hashes. Lower = more visually similar; 0 = identical hash.
    """

    if len(hash_hex_a) != len(hash_hex_b):
        raise ValueError(
            "Cannot compare hashes of different lengths: "
            f"{len(hash_hex_a)} vs {len(hash_hex_b)} hex characters."
        )

    return bin(int(hash_hex_a, 16) ^ int(hash_hex_b, 16)).count("1")


def similarity_score(distance: int, hash_bits: int = _HASH_BITS) -> float:
    """
    Converts a Hamming distance into an intuitive 0-100 similarity score
    (100 = identical perceptual hash, 0 = maximally different).
    """

    score = (1 - (distance / hash_bits)) * 100

    return round(max(0.0, min(100.0, score)), 2)


def is_near_duplicate(distance: int) -> bool:

    return distance <= NEAR_DUPLICATE_HAMMING_THRESHOLD
