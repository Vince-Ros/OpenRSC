from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import ipaddress
import secrets
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any


PBKDF2_ITERATIONS = 650_000


class ConfigurationError(RuntimeError):
    pass


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def password_record(password: str, *, iterations: int = PBKDF2_ITERATIONS) -> dict[str, Any]:
    if len(password) < 12:
        raise ConfigurationError("The control-panel password must contain at least 12 characters.")
    salt = secrets.token_bytes(24)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=32)
    return {
        "algorithm": "pbkdf2_sha256",
        "iterations": iterations,
        "salt": _b64(salt),
        "digest": _b64(digest),
    }


def verify_password(password: str, record: dict[str, Any]) -> bool:
    try:
        if record["algorithm"] != "pbkdf2_sha256":
            return False
        iterations = int(record["iterations"])
        if not 100_000 <= iterations <= 10_000_000:
            return False
        salt = _unb64(str(record["salt"]))
        expected = _unb64(str(record["digest"]))
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=len(expected))
        return hmac.compare_digest(actual, expected)
    except (KeyError, TypeError, ValueError):
        return False


def _default_roots() -> list[str]:
    if os.name == "nt":
        return ["%SystemDrive%\\"]
    return [str(Path.home())]


def build_config(password: str, *, roots: list[str] | None = None, port: int = 8787) -> dict[str, Any]:
    return {
        "version": 1,
        "listen": {"host": "127.0.0.1", "port": int(port)},
        "security": {
            "password": password_record(password),
            "session_secret": _b64(secrets.token_bytes(48)),
            "session_ttl_seconds": 8 * 60 * 60,
            "max_active_sessions": 24,
            "login_attempts": 5,
            "login_window_seconds": 5 * 60,
            "login_lock_seconds": 15 * 60,
            "trusted_proxies": ["127.0.0.1", "::1"],
        },
        "files": {
            "roots": roots or _default_roots(),
            "max_upload_bytes": 4 * 1024 * 1024 * 1024,
            "max_preview_bytes": 2 * 1024 * 1024,
            "max_archive_members": 20_000,
            "max_extracted_bytes": 8 * 1024 * 1024 * 1024,
        },
        "terminal": {
            "enabled": True,
            "max_sessions": 8,
            "max_input_chars": 64 * 1024,
            "max_buffer_chars": 2 * 1024 * 1024,
            "idle_seconds": 8 * 60 * 60,
        },
    }


def write_config(path: Path, data: dict[str, Any]) -> None:
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(data, indent=2, sort_keys=True) + "\n"
    fd, temp_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_name, 0o600)
        os.replace(temp_name, path)
        os.chmod(path, 0o600)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


@dataclass(frozen=True)
class OpenRSCConfig:
    path: Path
    raw: dict[str, Any]

    @property
    def host(self) -> str:
        return str(self.raw["listen"]["host"])

    @property
    def port(self) -> int:
        return int(self.raw["listen"]["port"])

    @property
    def security(self) -> dict[str, Any]:
        return self.raw["security"]

    @property
    def files(self) -> dict[str, Any]:
        return self.raw["files"]

    @property
    def terminal(self) -> dict[str, Any]:
        return self.raw["terminal"]


def load_config(path: Path) -> OpenRSCConfig:
    path = path.resolve()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ConfigurationError(f"Configuration file not found: {path}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigurationError(f"Cannot read configuration: {exc}") from exc

    try:
        if int(raw["version"]) != 1:
            raise ValueError("unsupported version")
        host = str(raw["listen"]["host"])
        port = int(raw["listen"]["port"])
        roots = raw["files"]["roots"]
        if not host or not 1 <= port <= 65535:
            raise ValueError("invalid listen address")
        if not isinstance(roots, list) or not roots or not all(isinstance(item, str) and item for item in roots):
            raise ValueError("files.roots must be a non-empty string list")
        secret = _unb64(str(raw["security"]["session_secret"]))
        if len(secret) < 32:
            raise ValueError("session secret is too short")
        record = raw["security"]["password"]
        iterations = int(record["iterations"])
        if (
            record.get("algorithm") != "pbkdf2_sha256"
            or not 100_000 <= iterations <= 10_000_000
            or len(_unb64(str(record["salt"]))) < 16
            or len(_unb64(str(record["digest"]))) != 32
        ):
            raise ValueError("invalid password verifier")
        security = raw["security"]
        if not 60 <= int(security["session_ttl_seconds"]) <= 7 * 24 * 60 * 60:
            raise ValueError("invalid session lifetime")
        if not 1 <= int(security["max_active_sessions"]) <= 1_000:
            raise ValueError("invalid active-session limit")
        for proxy in security.get("trusted_proxies", []):
            ipaddress.ip_address(str(proxy))
        files = raw["files"]
        if not 1 <= int(files["max_upload_bytes"]) <= 16 * 1024**4:
            raise ValueError("invalid upload limit")
        if not 1 <= int(files["max_preview_bytes"]) <= 128 * 1024**2:
            raise ValueError("invalid preview limit")
        if not 1 <= int(files["max_archive_members"]) <= 1_000_000:
            raise ValueError("invalid archive member limit")
        if not 1 <= int(files["max_extracted_bytes"]) <= 32 * 1024**4:
            raise ValueError("invalid extraction limit")
        terminal = raw["terminal"]
        if not isinstance(terminal["enabled"], bool):
            raise ValueError("invalid terminal enabled field")
        if not 1_024 <= int(terminal["max_input_chars"]) <= 1024**2:
            raise ValueError("invalid terminal input limit")
        if not 64 * 1024 <= int(terminal["max_buffer_chars"]) <= 128 * 1024**2:
            raise ValueError("invalid terminal buffer limit")
        if not 1 <= int(terminal.get("max_sessions", 8)) <= 16:
            raise ValueError("invalid terminal session limit")
    except (KeyError, TypeError, ValueError) as exc:
        raise ConfigurationError(f"Invalid configuration: {exc}") from exc
    return OpenRSCConfig(path=path, raw=raw)


def expand_root(value: str) -> Path:
    expanded = os.path.expandvars(os.path.expanduser(value))
    if os.name == "nt" and expanded.startswith("%SystemDrive%"):
        expanded = os.environ.get("SystemDrive", "C:") + expanded[len("%SystemDrive%") :]
    return Path(expanded).resolve()
