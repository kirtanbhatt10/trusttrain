"""Safe storage for uploaded artifacts.

* Uploaded files are stored under server-generated names (UUID + vetted
  extension); client-supplied filenames are only kept as metadata.
* Uploads stream to a temporary file inside the uploads directory with a hard
  size limit, then are atomically renamed.
* Archives are rejected outright (no extraction = no zip-slip/zip-bomb).
"""

from __future__ import annotations

import os
import re
import tempfile
import uuid
from pathlib import Path

from fastapi import UploadFile

from app.core.tabular import DatasetFormatError, detect_format

_ARCHIVE_MAGIC = (b"PK\x03\x04", b"\x1f\x8b", b"7z\xbc\xaf", b"Rar!", b"BZh")
_SAFE_NAME = re.compile(r"[^A-Za-z0-9._ -]")


class UploadTooLargeError(ValueError):
    pass


def sanitize_display_name(filename: str | None) -> str:
    name = Path(filename or "dataset").name  # strips any directory components
    name = _SAFE_NAME.sub("_", name).strip(" .") or "dataset"
    return name[:200]


def resolve_inside(base: Path, name: str) -> Path:
    """Join ``name`` to ``base`` and refuse anything that escapes ``base``."""
    base_resolved = base.resolve()
    candidate = (base_resolved / name).resolve()
    if base_resolved != candidate.parent and base_resolved not in candidate.parents:
        raise ValueError("Path escapes storage directory")
    return candidate


async def store_upload(upload: UploadFile, uploads_dir: Path, max_bytes: int) -> tuple[str, str, str, Path]:
    """Persist an upload. Returns (display_name, format, storage_name, path)."""
    display = sanitize_display_name(upload.filename)
    fmt = detect_format(display)
    uploads_dir.mkdir(parents=True, exist_ok=True)
    storage_name = f"{uuid.uuid4().hex}.{fmt}"
    final_path = resolve_inside(uploads_dir, storage_name)
    fd, tmp_name = tempfile.mkstemp(dir=uploads_dir, prefix=".upload-", suffix=".part")
    written = 0
    try:
        with os.fdopen(fd, "wb") as out:
            first = True
            while chunk := await upload.read(1024 * 1024):
                if first:
                    if fmt != "parquet" and any(chunk.startswith(m) for m in _ARCHIVE_MAGIC):
                        raise DatasetFormatError("Archive uploads are not accepted; upload the dataset file directly")
                    first = False
                written += len(chunk)
                if written > max_bytes:
                    raise UploadTooLargeError(f"Upload exceeds the {max_bytes}-byte limit")
                out.write(chunk)
        if written == 0:
            raise DatasetFormatError("Uploaded file is empty")
        os.chmod(tmp_name, 0o600)
        os.replace(tmp_name, final_path)
    except BaseException:
        Path(tmp_name).unlink(missing_ok=True)
        raise
    return display, fmt, storage_name, final_path
