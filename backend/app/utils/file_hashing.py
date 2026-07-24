import hashlib
from dataclasses import dataclass

from backend.app.core.config import settings


@dataclass(frozen=True)
class FileHashes:

    md5: str
    sha1: str
    sha256: str
    sha512: str


def hash_file(path: str) -> FileHashes:
    """
    Computes all four hashes in a single streamed pass over the file so
    a large upload is only read from disk once, not four times.
    """

    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    sha512 = hashlib.sha512()

    chunk_size = settings.FILE_HASH_CHUNK_SIZE_BYTES

    with open(path, "rb") as handle:

        while True:
            chunk = handle.read(chunk_size)

            if not chunk:
                break

            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
            sha512.update(chunk)

    return FileHashes(
        md5=md5.hexdigest(),
        sha1=sha1.hexdigest(),
        sha256=sha256.hexdigest(),
        sha512=sha512.hexdigest(),
    )
