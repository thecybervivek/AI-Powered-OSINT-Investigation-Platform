import os
from datetime import datetime
from datetime import timezone
from typing import Any


def _stat_timeline(path: str) -> dict[str, str]:

    stat_result = os.stat(path)

    def _iso(ts: float) -> str:
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()

    return {
        "filesystem_created_at": _iso(getattr(stat_result, "st_birthtime", stat_result.st_ctime)),
        "filesystem_modified_at": _iso(stat_result.st_mtime),
        "filesystem_accessed_at": _iso(stat_result.st_atime),
    }


# Metadata field names (across every extractor) that represent a
# creation or modification timestamp worth surfacing on the timeline.
_CREATED_KEYS = ("created", "creation_date", "DateTimeOriginal", "DateTime")
_MODIFIED_KEYS = ("modified", "modification_date")


def build_timeline(
    *,
    path: str,
    extracted_metadata: dict[str, Any],
) -> dict[str, Any]:
    """
    Merges filesystem-level timestamps (always available, but reflect
    only when THIS SERVER touched the file) with any authoring
    timestamps embedded in the document/image metadata itself (more
    forensically interesting, but only present for supported types and
    only as reliable as whatever tool last wrote the file).
    """

    timeline: dict[str, Any] = _stat_timeline(path)

    embedded_created = None
    embedded_modified = None

    exif = extracted_metadata.get("exif", {}) if isinstance(extracted_metadata, dict) else {}

    for key in _CREATED_KEYS:

        if extracted_metadata.get(key):
            embedded_created = extracted_metadata[key]
            break

        if exif.get(key):
            embedded_created = str(exif[key])
            break

    for key in _MODIFIED_KEYS:

        if extracted_metadata.get(key):
            embedded_modified = extracted_metadata[key]
            break

    timeline["document_created_at"] = embedded_created
    timeline["document_modified_at"] = embedded_modified

    return timeline
