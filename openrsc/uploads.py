from __future__ import annotations

import hashlib
import os
import secrets
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, BinaryIO

from .files import FileAccessError, FileManager


class UploadError(FileAccessError):
    pass


@dataclass
class PendingUpload:
    upload_id: str
    sid: str
    directory: str
    name: str
    total: int
    overwrite: bool
    temp_path: Path
    received: int = 0
    digest: Any = field(default_factory=hashlib.sha256)
    touched: float = field(default_factory=time.monotonic)
    lock: threading.RLock = field(default_factory=threading.RLock)


class UploadManager:
    """Bounded, sequential chunk uploads for proxy-friendly large transfers."""

    def __init__(self, files: FileManager, *, chunk_bytes: int = 8 * 1024 * 1024, idle_seconds: int = 3600) -> None:
        self.files = files
        self.chunk_bytes = chunk_bytes
        self.idle_seconds = idle_seconds
        self._uploads: dict[str, PendingUpload] = {}
        self._lock = threading.RLock()

    def begin(self, sid: str, directory: str, name: str, total: int, overwrite: bool) -> dict[str, object]:
        if total < 0 or total > self.files.max_upload:
            raise UploadError(f"Upload exceeds the {self.files.max_upload}-byte limit")
        target = self.files.child(directory, name)
        if target.path.exists() and not overwrite:
            raise UploadError("Destination already exists")
        if target.path.exists() and target.path.is_dir():
            raise UploadError("A directory already uses that name")
        with self._lock:
            self._purge_locked()
            owned = sum(item.sid == sid for item in self._uploads.values())
            if len(self._uploads) >= 64 or owned >= 8:
                raise UploadError("Too many pending uploads")
            upload_id = secrets.token_urlsafe(24)
            fd, temp_name = tempfile.mkstemp(prefix="chunked-", suffix=".part", dir=self.files.temp_dir)
            os.close(fd)
            self._uploads[upload_id] = PendingUpload(
                upload_id=upload_id,
                sid=sid,
                directory=directory,
                name=name,
                total=total,
                overwrite=overwrite,
                temp_path=Path(temp_name),
            )
        return {"uploadId": upload_id, "chunkBytes": self.chunk_bytes, "received": 0, "total": total}

    def append(self, sid: str, upload_id: str, offset: int, stream: BinaryIO, length: int) -> dict[str, int]:
        pending = self._get(sid, upload_id)
        if length <= 0 or length > self.chunk_bytes:
            raise UploadError(f"Each upload chunk must contain 1 to {self.chunk_bytes} bytes")
        with pending.lock:
            self._assert_active(pending)
            if offset != pending.received:
                raise UploadError(f"Upload offset mismatch; server expects {pending.received}")
            if pending.received + length > pending.total:
                raise UploadError("Chunk exceeds the declared file size")
            digest_before = pending.digest.copy()
            remaining = length
            try:
                with pending.temp_path.open("r+b") as output:
                    output.seek(offset)
                    output.truncate(offset)
                    while remaining:
                        chunk = stream.read(min(1024 * 1024, remaining))
                        if not chunk:
                            raise UploadError("Chunk ended before Content-Length bytes were received")
                        output.write(chunk)
                        pending.digest.update(chunk)
                        remaining -= len(chunk)
                    output.flush()
                pending.received += length
                pending.touched = time.monotonic()
                return {"received": pending.received, "total": pending.total}
            except Exception:
                pending.digest = digest_before
                try:
                    with pending.temp_path.open("r+b") as output:
                        output.truncate(offset)
                except OSError:
                    pass
                raise

    def finish(self, sid: str, upload_id: str) -> tuple[Path, int, str]:
        pending = self._get(sid, upload_id)
        with pending.lock:
            self._assert_active(pending)
            if pending.received != pending.total:
                raise UploadError(f"Upload is incomplete; received {pending.received} of {pending.total} bytes")
            target = self.files.child(pending.directory, pending.name)
            if target.path.exists() and not pending.overwrite:
                raise UploadError("Destination already exists")
            if target.path.exists() and target.path.is_dir():
                raise UploadError("A directory already uses that name")
            with pending.temp_path.open("r+b") as handle:
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(pending.temp_path, target.path)
            digest = pending.digest.hexdigest()
            with self._lock:
                self._uploads.pop(upload_id, None)
            return target.path, pending.total, digest

    def cancel(self, sid: str, upload_id: str) -> bool:
        with self._lock:
            pending = self._uploads.get(upload_id)
            if pending is None or pending.sid != sid:
                return False
        with pending.lock:
            with self._lock:
                if self._uploads.get(upload_id) is not pending:
                    return False
                self._uploads.pop(upload_id, None)
            pending.temp_path.unlink(missing_ok=True)
        return True

    def abort_session(self, sid: str) -> None:
        with self._lock:
            identifiers = [key for key, item in self._uploads.items() if item.sid == sid]
        for upload_id in identifiers:
            self.cancel(sid, upload_id)

    def close_all(self) -> None:
        with self._lock:
            pending = list(self._uploads.values())
            self._uploads.clear()
        for item in pending:
            item.temp_path.unlink(missing_ok=True)

    def _get(self, sid: str, upload_id: str) -> PendingUpload:
        with self._lock:
            self._purge_locked()
            pending = self._uploads.get(upload_id)
            if pending is None or pending.sid != sid:
                raise UploadError("Upload session was not found")
            return pending

    def _assert_active(self, pending: PendingUpload) -> None:
        with self._lock:
            if self._uploads.get(pending.upload_id) is not pending:
                raise UploadError("Upload session was cancelled")

    def _purge_locked(self) -> None:
        cutoff = time.monotonic() - self.idle_seconds
        expired = [key for key, item in self._uploads.items() if item.touched < cutoff]
        for key in expired:
            item = self._uploads.pop(key)
            item.temp_path.unlink(missing_ok=True)
