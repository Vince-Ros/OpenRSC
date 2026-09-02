from __future__ import annotations

import mimetypes
import hashlib
import os
import shutil
import stat
import tempfile
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO

from .config import OpenRSCConfig, expand_root


class FileAccessError(ValueError):
    pass


class FileConflictError(FileAccessError):
    """Raised when a text file changed after the editor loaded it."""

    pass


def _inside(candidate: Path, root: Path) -> bool:
    try:
        return os.path.commonpath([os.path.normcase(candidate), os.path.normcase(root)]) == os.path.normcase(root)
    except ValueError:
        return False


def _safe_leaf(name: str) -> str:
    if not name or name in {".", ".."} or "\x00" in name or "/" in name or "\\" in name:
        raise FileAccessError("Invalid file name")
    if os.name == "nt" and (name.endswith(".") or name.endswith(" ") or ":" in name):
        raise FileAccessError("Invalid Windows file name")
    if os.name == "nt":
        stem = name.split(".", 1)[0].rstrip(" .").upper()
        reserved = {"CON", "PRN", "AUX", "NUL", "CLOCK$", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}
        if stem in reserved:
            raise FileAccessError("Reserved Windows device names cannot be used")
    return name


@dataclass(frozen=True)
class ResolvedPath:
    path: Path
    root: Path


class FileManager:
    def __init__(self, config: OpenRSCConfig, temp_dir: Path) -> None:
        self.config = config
        self.roots = tuple(expand_root(item) for item in config.files["roots"])
        self.temp_dir = temp_dir
        self.temp_dir.mkdir(parents=True, exist_ok=True)
        self.max_upload = int(config.files.get("max_upload_bytes", 4 * 1024**3))
        self.max_preview = int(config.files.get("max_preview_bytes", 2 * 1024**2))
        self.max_members = int(config.files.get("max_archive_members", 20_000))
        self.max_extracted = int(config.files.get("max_extracted_bytes", 8 * 1024**3))

    def public_roots(self) -> list[dict[str, str]]:
        result = []
        for root in self.roots:
            label = root.drive + os.sep if root.drive else root.name or str(root)
            result.append({"label": label, "path": str(root)})
        return result

    def resolve(self, user_path: str, *, must_exist: bool = True) -> ResolvedPath:
        if not user_path or "\x00" in user_path:
            raise FileAccessError("A path is required")
        raw = Path(os.path.expandvars(os.path.expanduser(user_path)))
        try:
            candidate = raw.resolve(strict=must_exist)
        except (OSError, RuntimeError) as exc:
            raise FileAccessError(f"Cannot resolve path: {exc}") from exc
        for root in self.roots:
            if _inside(candidate, root):
                return ResolvedPath(candidate, root)
        raise FileAccessError("Path is outside the configured roots")

    def child(self, directory: str, name: str, *, must_exist: bool = False) -> ResolvedPath:
        parent = self.resolve(directory, must_exist=True)
        if not parent.path.is_dir():
            raise FileAccessError("Destination is not a directory")
        leaf = _safe_leaf(name)
        candidate = (parent.path / leaf).resolve(strict=must_exist)
        if not _inside(candidate, parent.root):
            raise FileAccessError("Destination leaves the configured root")
        return ResolvedPath(candidate, parent.root)

    @staticmethod
    def _entry(path: Path) -> dict[str, object]:
        info = path.stat()
        is_dir = path.is_dir()
        return {
            "name": path.name,
            "path": str(path),
            "kind": "directory" if is_dir else "file",
            "size": None if is_dir else info.st_size,
            "modified": datetime.fromtimestamp(info.st_mtime, timezone.utc).isoformat(),
            "mime": None if is_dir else (mimetypes.guess_type(path.name)[0] or "application/octet-stream"),
        }

    def list_directory(self, user_path: str) -> dict[str, object]:
        resolved = self.resolve(user_path)
        if not resolved.path.is_dir():
            raise FileAccessError("Path is not a directory")
        entries: list[dict[str, object]] = []
        try:
            for child in resolved.path.iterdir():
                try:
                    item = self._entry(child)
                    if child.is_symlink():
                        target = child.resolve(strict=True)
                        item["outside_root"] = not _inside(target, resolved.root)
                    entries.append(item)
                except (OSError, FileAccessError):
                    entries.append({"name": child.name, "path": str(child), "kind": "unavailable"})
        except OSError as exc:
            raise FileAccessError(f"Cannot list directory: {exc}") from exc
        entries.sort(key=lambda item: (item.get("kind") != "directory", str(item.get("name", "")).casefold()))
        parent = resolved.path.parent
        parent_value = str(parent) if _inside(parent, resolved.root) else None
        return {"path": str(resolved.path), "parent": parent_value, "entries": entries}

    def preview_text(self, user_path: str) -> dict[str, object]:
        resolved = self.resolve(user_path)
        if not resolved.path.is_file():
            raise FileAccessError("Path is not a file")
        info = resolved.path.stat()
        size = info.st_size
        if size > self.max_preview:
            raise FileAccessError(f"File is larger than the {self.max_preview}-byte preview limit")
        data = resolved.path.read_bytes()
        if b"\x00" in data[:8192]:
            raise FileAccessError("Binary files cannot be shown as text")
        return {
            "path": str(resolved.path),
            "size": size,
            "text": data.decode("utf-8", "replace"),
            "sha256": hashlib.sha256(data).hexdigest(),
            "modified": datetime.fromtimestamp(info.st_mtime, timezone.utc).isoformat(),
        }

    def write_text(self, user_path: str, text: str, expected_sha256: str) -> dict[str, object]:
        if not isinstance(text, str):
            raise FileAccessError("Text content is required")
        if not isinstance(expected_sha256, str) or len(expected_sha256) != 64:
            raise FileAccessError("A valid file revision is required")
        resolved = self.resolve(user_path)
        if not resolved.path.is_file():
            raise FileAccessError("Path is not a file")
        current = resolved.path.read_bytes()
        if b"\x00" in current[:8192]:
            raise FileAccessError("Binary files cannot be edited as text")
        if hashlib.sha256(current).hexdigest() != expected_sha256.lower():
            raise FileConflictError("This file changed on the host. Reopen it before saving your edits.")
        encoded = text.encode("utf-8")
        if len(encoded) > self.max_preview:
            raise FileAccessError(f"Edited file exceeds the {self.max_preview}-byte text limit")

        mode = stat.S_IMODE(resolved.path.stat().st_mode)
        fd, temp_name = tempfile.mkstemp(prefix=f".{resolved.path.name}.openrsc-", suffix=".tmp", dir=resolved.path.parent)
        try:
            with os.fdopen(fd, "wb") as output:
                output.write(encoded)
                output.flush()
                os.fsync(output.fileno())
            try:
                os.chmod(temp_name, mode)
            except OSError:
                pass
            os.replace(temp_name, resolved.path)
        finally:
            try:
                os.unlink(temp_name)
            except FileNotFoundError:
                pass
        info = resolved.path.stat()
        return {
            "path": str(resolved.path),
            "size": len(encoded),
            "sha256": hashlib.sha256(encoded).hexdigest(),
            "modified": datetime.fromtimestamp(info.st_mtime, timezone.utc).isoformat(),
        }

    def mkdir(self, directory: str, name: str) -> Path:
        target = self.child(directory, name)
        target.path.mkdir()
        return target.path

    def rename(self, source: str, new_name: str) -> Path:
        resolved = self.resolve(source)
        target = self.child(str(resolved.path.parent), new_name)
        if target.path.exists():
            raise FileAccessError("Destination already exists")
        resolved.path.rename(target.path)
        return target.path

    def delete(self, user_path: str, recursive: bool) -> None:
        resolved = self.resolve(user_path)
        if resolved.path == resolved.root:
            raise FileAccessError("A configured root cannot be deleted")
        if resolved.path.is_dir() and not resolved.path.is_symlink():
            if recursive:
                shutil.rmtree(resolved.path)
            else:
                resolved.path.rmdir()
        else:
            resolved.path.unlink()

    def save_upload(self, stream: BinaryIO, directory: str, name: str, length: int, overwrite: bool) -> tuple[Path, str]:
        if length < 0 or length > self.max_upload:
            raise FileAccessError(f"Upload exceeds the {self.max_upload}-byte limit")
        target = self.child(directory, name)
        if target.path.exists() and not overwrite:
            raise FileAccessError("Destination already exists")
        digest = hashlib.sha256()
        fd, temp_name = tempfile.mkstemp(prefix="upload-", suffix=".part", dir=self.temp_dir)
        received = 0
        try:
            with os.fdopen(fd, "wb") as output:
                remaining = length
                while remaining:
                    chunk = stream.read(min(1024 * 1024, remaining))
                    if not chunk:
                        raise FileAccessError("Upload ended before Content-Length bytes were received")
                    output.write(chunk)
                    digest.update(chunk)
                    received += len(chunk)
                    remaining -= len(chunk)
                output.flush()
                os.fsync(output.fileno())
            if received != length:
                raise FileAccessError("Upload length mismatch")
            if target.path.exists() and target.path.is_dir():
                raise FileAccessError("A directory already uses that name")
            os.replace(temp_name, target.path)
            return target.path, digest.hexdigest()
        finally:
            try:
                os.unlink(temp_name)
            except FileNotFoundError:
                pass

    def extract_zip(self, archive_path: str, target_directory: str) -> dict[str, int]:
        archive = self.resolve(archive_path)
        target = self.resolve(target_directory)
        if not archive.path.is_file() or not zipfile.is_zipfile(archive.path):
            raise FileAccessError("Source is not a ZIP archive")
        if not target.path.is_dir():
            raise FileAccessError("Extraction target is not a directory")
        extracted = 0
        count = 0
        with zipfile.ZipFile(archive.path) as package:
            members = package.infolist()
            if len(members) > self.max_members:
                raise FileAccessError("ZIP contains too many entries")
            total = sum(member.file_size for member in members)
            if total > self.max_extracted:
                raise FileAccessError("ZIP expands beyond the configured limit")
            validated: list[tuple[zipfile.ZipInfo, Path]] = []
            for member in members:
                unix_mode = (member.external_attr >> 16) & 0xFFFF
                if stat.S_ISLNK(unix_mode):
                    raise FileAccessError("ZIP symbolic links are not accepted")
                normalized = member.filename.replace("\\", "/")
                pieces = [piece for piece in normalized.split("/") if piece not in {"", "."}]
                if (
                    not pieces
                    or any(piece == ".." or "\x00" in piece for piece in pieces)
                    or ":" in pieces[0]
                    or normalized.startswith("/")
                ):
                    raise FileAccessError("ZIP contains an unsafe path")
                destination = (target.path.joinpath(*pieces)).resolve(strict=False)
                if not _inside(destination, target.root) or not _inside(destination, target.path):
                    raise FileAccessError("ZIP entry leaves the destination")
                validated.append((member, destination))
            for member, destination in validated:
                if member.is_dir():
                    destination.mkdir(parents=True, exist_ok=True)
                    continue
                destination.parent.mkdir(parents=True, exist_ok=True)
                with package.open(member) as source, destination.open("wb") as output:
                    shutil.copyfileobj(source, output, length=1024 * 1024)
                extracted += member.file_size
                count += 1
        return {"files": count, "bytes": extracted}

    def make_archive(self, user_path: str) -> tuple[Path, str]:
        resolved = self.resolve(user_path)
        fd, temp_name = tempfile.mkstemp(prefix="download-", suffix=".zip", dir=self.temp_dir)
        os.close(fd)
        temp_path = Path(temp_name)
        base_name = resolved.path.name or "root"
        try:
            with zipfile.ZipFile(temp_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as package:
                if resolved.path.is_dir():
                    for child in resolved.path.rglob("*"):
                        is_junction = getattr(child, "is_junction", lambda: False)()
                        if child.is_symlink() or is_junction:
                            continue
                        try:
                            canonical = child.resolve(strict=True)
                        except OSError:
                            continue
                        if not _inside(canonical, resolved.root) or not _inside(canonical, resolved.path):
                            continue
                        relative = Path(base_name) / child.relative_to(resolved.path)
                        package.write(child, relative.as_posix())
                else:
                    package.write(resolved.path, base_name)
            return temp_path, base_name + ".zip"
        except Exception:
            temp_path.unlink(missing_ok=True)
            raise
