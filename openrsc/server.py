from __future__ import annotations

import ctypes
import email.utils
import http.cookies
import ipaddress
import json
import logging
import mimetypes
import os
import shutil
import socket
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote, urlsplit

from . import __version__
from .ai import AIIntegration, AIIntegrationError
from .audit import AuditLog
from .auth import AuthenticationError, AuthService, Session
from .config import OpenRSCConfig
from .files import FileAccessError, FileConflictError, FileManager
from .terminal import TerminalError, TerminalManager
from .uploads import UploadError, UploadManager


LOG = logging.getLogger("openrsc")
STATIC_DIR = Path(__file__).with_name("web")
STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/styles.css": ("styles.css", "text/css; charset=utf-8"),
    "/manifest.webmanifest": ("manifest.webmanifest", "application/manifest+json; charset=utf-8"),
    "/app-icon.svg": ("app-icon.svg", "image/svg+xml"),
    "/apple-touch-icon.png": ("apple-touch-icon.png", "image/png"),
}


def is_administrator() -> bool:
    if os.name == "nt":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


class OpenRSCApplication:
    def __init__(self, config: OpenRSCConfig, data_dir: Path) -> None:
        self.config = config
        self.data_dir = data_dir.resolve()
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.audit = AuditLog(self.data_dir / "logs" / "audit.jsonl")
        self.auth = AuthService(config)
        self.files = FileManager(config, self.data_dir / "tmp")
        self.ai = AIIntegration()
        self.uploads = UploadManager(self.files)
        terminal = config.terminal
        first_root = next((root for root in self.files.roots if root.exists() and root.is_dir()), Path.cwd())
        self.terminals = TerminalManager(
            first_root,
            max_buffer=int(terminal.get("max_buffer_chars", 2 * 1024 * 1024)),
            max_input=int(terminal.get("max_input_chars", 64 * 1024)),
            idle_seconds=int(terminal.get("idle_seconds", 28_800)),
            max_sessions=int(terminal.get("max_sessions", 8)),
        )



        self.terminal_owner = "openrsc-workspace"
        self.started = int(time.time())
        self.admin = is_administrator()
        self.trusted_proxies = {str(value) for value in config.security.get("trusted_proxies", ["127.0.0.1", "::1"])}

    def close(self) -> None:
        self.terminals.close_all()
        self.uploads.close_all()


class OpenRSCServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 128

    def __init__(self, address: tuple[str, int], app: OpenRSCApplication) -> None:
        self.app = app
        self._request_slots = threading.BoundedSemaphore(64)
        super().__init__(address, OpenRSCHandler)

    def process_request(self, request: socket.socket, client_address: tuple[str, int]) -> None:
        if not self._request_slots.acquire(blocking=False):
            try:
                request.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            request.close()
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._request_slots.release()
            raise

    def process_request_thread(self, request: socket.socket, client_address: tuple[str, int]) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._request_slots.release()

    def server_close(self) -> None:
        self.app.close()
        super().server_close()


class OpenRSCHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "OpenRSC"
    sys_version = ""

    @property
    def app(self) -> OpenRSCApplication:
        return self.server.app

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(120)

    def log_message(self, format: str, *args: object) -> None:
        LOG.info("%s %s", self.client_address[0], format % args)

    def version_string(self) -> str:
        return "OpenRSC"

    def do_GET(self) -> None:
        try:
            self._dispatch_get()
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            return
        except Exception:
            LOG.exception("Unhandled GET error")
            self._json_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Internal server error")

    def do_HEAD(self) -> None:
        try:
            self._dispatch_get(head_only=True)
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            return
        except Exception:
            LOG.exception("Unhandled HEAD error")
            self._json_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Internal server error", head_only=True)

    def do_POST(self) -> None:
        try:
            self._dispatch_post()
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            return
        except Exception:
            LOG.exception("Unhandled POST error")
            self._json_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Internal server error")

    def do_OPTIONS(self) -> None:
        self._json_error(HTTPStatus.METHOD_NOT_ALLOWED, "Cross-origin requests are not enabled")

    def _dispatch_get(self, head_only: bool = False) -> None:
        parsed = urlsplit(self.path)
        path = parsed.path
        query = parse_qs(parsed.query, keep_blank_values=True)
        if path == "/healthz":
            self._send_json(HTTPStatus.OK, {"ok": True}, head_only=head_only)
            return
        if path in STATIC_FILES:
            self._serve_static(path, head_only=head_only)
            return
        session = self._require_session()
        if session is None:
            return
        try:
            if path == "/api/session":
                self._send_json(
                    HTTPStatus.OK,
                    {
                        "authenticated": True,
                        "csrf": self.app.auth.csrf_token(session),
                        "expires": session.expires,
                        "version": __version__,
                        "administrator": self.app.admin,
                        "terminalEnabled": bool(self.app.config.terminal.get("enabled", True)),
                        "terminalLimit": self.app.terminals.max_sessions,
                        "roots": self.app.files.public_roots(),
                        "limits": {
                            "uploadBytes": self.app.files.max_upload,
                            "previewBytes": self.app.files.max_preview,
                        },
                        "started": self.app.started,
                    },
                    head_only=head_only,
                )
            elif path == "/api/terminals":
                self._ensure_terminal()
                self._send_json(
                    HTTPStatus.OK,
                    {"terminals": self.app.terminals.list(self.app.terminal_owner), "limit": self.app.terminals.max_sessions},
                    head_only=head_only,
                )
            elif path == "/api/files":
                value = self._one(query, "path")
                self._send_json(HTTPStatus.OK, self.app.files.list_directory(value), head_only=head_only)
            elif path == "/api/ai/status":
                self._send_json(
                    HTTPStatus.OK,
                    self.app.ai.status(refresh=self._one(query, "refresh", "0") == "1"),
                    head_only=head_only,
                )
            elif path == "/api/file/text":
                value = self._one(query, "path")
                self._send_json(HTTPStatus.OK, self.app.files.preview_text(value), head_only=head_only)
            elif path == "/api/file/raw":
                self._serve_file(self._one(query, "path"), inline=self._one(query, "inline", "0") == "1", head_only=head_only)
            elif path == "/api/files/archive":
                if head_only:
                    self._json_error(HTTPStatus.METHOD_NOT_ALLOWED, "HEAD is not available for generated archives", head_only=True)
                else:
                    self._serve_archive(self._one(query, "path"))
            elif path == "/api/terminal/output":
                if not self.app.config.terminal.get("enabled", True):
                    raise TerminalError("Terminal is disabled")
                cursor = int(self._one(query, "cursor", "0"))
                terminal_id = self._one(query, "terminalId", "main")
                self._send_json(
                    HTTPStatus.OK,
                    self.app.terminals.get(self.app.terminal_owner, terminal_id).read(cursor),
                    head_only=head_only,
                )
            else:
                self._json_error(HTTPStatus.NOT_FOUND, "Not found", head_only=head_only)
        except (FileAccessError, TerminalError, ValueError) as exc:
            self._json_error(HTTPStatus.BAD_REQUEST, str(exc), head_only=head_only)
        except FileNotFoundError:
            self._json_error(HTTPStatus.NOT_FOUND, "File or directory not found", head_only=head_only)
        except PermissionError:
            self._json_error(HTTPStatus.FORBIDDEN, "The server account cannot access that path", head_only=head_only)
        except OSError as exc:
            self._json_error(HTTPStatus.INTERNAL_SERVER_ERROR, f"Filesystem operation failed ({exc.errno})", head_only=head_only)

    def _dispatch_post(self) -> None:
        parsed = urlsplit(self.path)
        path = parsed.path
        query = parse_qs(parsed.query, keep_blank_values=True)
        if path == "/api/login":
            self._login()
            return
        session = self._require_session(close_on_failure=True)
        if session is None:
            return
        if not self._same_origin() or not self.app.auth.verify_csrf(session, self.headers.get("X-CSRF-Token", "")):
            self.app.audit.write("csrf_rejected", self._remote_ip(), route=path)
            self.close_connection = True
            self._json_error(HTTPStatus.FORBIDDEN, "Request verification failed")
            return
        try:
            if path == "/api/logout":
                self._read_json(16 * 1024)
                self.app.auth.revoke(session.sid)
                self.app.uploads.abort_session(session.sid)
                self.app.audit.write("logout", self._remote_ip())
                self._send_json(HTTPStatus.OK, {"ok": True}, cookies=self._expired_cookies())
            elif path == "/api/terminals":
                self._ensure_terminal()
                body = self._read_json(16 * 1024)
                created = self.app.terminals.create(self.app.terminal_owner, str(body.get("name", "")))
                self.app.audit.write("terminal_created", self._remote_ip(), terminal=created["id"])
                self._send_json(HTTPStatus.CREATED, {"ok": True, "terminal": created})
            elif path == "/api/ai/launch":
                body = self._read_json(64 * 1024)
                provider = str(body.get("provider", ""))
                if provider not in self.app.ai.PROVIDERS:
                    raise AIIntegrationError("Unknown AI session type")
                resolved = self.app.files.resolve(str(body.get("directory", "")))
                if not resolved.path.is_dir():
                    raise FileAccessError("AI working directory is not a directory")
                if provider == "codex-app":
                    process_id = self.app.ai.open_codex_app(resolved.path)
                    self.app.audit.write("codex_app_opened", self._remote_ip(), path=str(resolved.path), process=process_id)
                    self._send_json(
                        HTTPStatus.CREATED,
                        {"ok": True, "mode": "desktop", "provider": provider, "directory": str(resolved.path), "pid": process_id},
                    )
                else:
                    self._ensure_terminal()
                    name, arguments = self.app.ai.terminal_spec(provider, resolved.path)
                    created = self.app.terminals.create(self.app.terminal_owner, name, directory=resolved.path)
                    terminal_id = str(created["id"])
                    try:
                        self.app.terminals.get(self.app.terminal_owner, terminal_id).send(self.app.ai.shell_command(arguments))
                    except Exception:
                        self.app.terminals.close(self.app.terminal_owner, terminal_id)
                        raise
                    self.app.audit.write(
                        "ai_session_started",
                        self._remote_ip(),
                        provider=provider,
                        terminal=terminal_id,
                        path=str(resolved.path),
                    )
                    self._send_json(
                        HTTPStatus.CREATED,
                        {"ok": True, "mode": "terminal", "provider": provider, "directory": str(resolved.path), "terminal": created},
                    )
            elif path == "/api/terminal/input":
                self._ensure_terminal()
                body = self._read_json(128 * 1024)
                command = str(body.get("input", ""))
                terminal_id = str(body.get("terminalId", "main"))
                self.app.terminals.get(self.app.terminal_owner, terminal_id).send(command)
                self.app.audit.write(
                    "terminal_input",
                    self._remote_ip(),
                    terminal=terminal_id,
                    **AuditLog.command_metadata(command),
                )
                self._send_json(HTTPStatus.ACCEPTED, {"ok": True})
            elif path == "/api/terminal/interrupt":
                self._ensure_terminal()
                body = self._read_json(16 * 1024)
                terminal_id = str(body.get("terminalId", "main"))
                self.app.terminals.get(self.app.terminal_owner, terminal_id).interrupt()
                self.app.audit.write("terminal_interrupt", self._remote_ip(), terminal=terminal_id)
                self._send_json(HTTPStatus.OK, {"ok": True})
            elif path == "/api/terminal/reset":
                self._ensure_terminal()
                body = self._read_json(16 * 1024)
                terminal_id = str(body.get("terminalId", "main"))
                self.app.terminals.get(self.app.terminal_owner, terminal_id).reset()
                self.app.audit.write("terminal_reset", self._remote_ip(), terminal=terminal_id)
                self._send_json(HTTPStatus.OK, {"ok": True})
            elif path == "/api/terminal/rename":
                self._ensure_terminal()
                body = self._read_json(16 * 1024)
                terminal_id = str(body.get("terminalId", ""))
                updated = self.app.terminals.rename(self.app.terminal_owner, terminal_id, str(body.get("name", "")))
                self.app.audit.write("terminal_renamed", self._remote_ip(), terminal=terminal_id)
                self._send_json(HTTPStatus.OK, {"ok": True, "terminal": updated})
            elif path == "/api/terminal/close":
                self._ensure_terminal()
                body = self._read_json(16 * 1024)
                terminal_id = str(body.get("terminalId", ""))
                closed = self.app.terminals.close(self.app.terminal_owner, terminal_id)
                self.app.audit.write("terminal_closed", self._remote_ip(), terminal=terminal_id)
                self._send_json(HTTPStatus.OK, {"ok": True, "closed": closed})
            elif path == "/api/files/upload":
                self._upload(query)
            elif path == "/api/uploads/start":
                body = self._read_json(64 * 1024)
                result = self.app.uploads.begin(
                    session.sid,
                    str(body.get("directory", "")),
                    str(body.get("name", "")),
                    int(body.get("size", -1)),
                    bool(body.get("overwrite", False)),
                )
                self._send_json(HTTPStatus.CREATED, {"ok": True, **result})
            elif path == "/api/uploads/chunk":
                self._upload_chunk(session, query)
            elif path == "/api/uploads/finish":
                body = self._read_json(16 * 1024)
                upload_id = str(body.get("uploadId", ""))
                target, length, digest = self.app.uploads.finish(session.sid, upload_id)
                self.app.audit.write("file_upload", self._remote_ip(), path=str(target), bytes=length, sha256=digest)
                self._send_json(
                    HTTPStatus.CREATED,
                    {"ok": True, "path": str(target), "bytes": length, "sha256": digest},
                )
            elif path == "/api/uploads/cancel":
                body = self._read_json(16 * 1024)
                cancelled = self.app.uploads.cancel(session.sid, str(body.get("uploadId", "")))
                self._send_json(HTTPStatus.OK, {"ok": True, "cancelled": cancelled})
            elif path == "/api/file/text":
                body = self._read_json(self.app.files.max_preview + 64 * 1024)
                target = str(body.get("path", ""))
                content = body.get("text")
                if not isinstance(content, str):
                    raise FileAccessError("Text content is required")
                result = self.app.files.write_text(target, content, str(body.get("expectedSha256", "")))
                self.app.audit.write("file_text_saved", self._remote_ip(), path=target, bytes=result["size"], sha256=result["sha256"])
                self._send_json(HTTPStatus.OK, {"ok": True, **result})
            elif path == "/api/files/mkdir":
                body = self._read_json()
                target = self.app.files.mkdir(str(body.get("directory", "")), str(body.get("name", "")))
                self.app.audit.write("file_mkdir", self._remote_ip(), path=str(target))
                self._send_json(HTTPStatus.CREATED, {"ok": True, "path": str(target)})
            elif path == "/api/files/rename":
                body = self._read_json()
                target = self.app.files.rename(str(body.get("path", "")), str(body.get("name", "")))
                self.app.audit.write("file_rename", self._remote_ip(), path=str(target))
                self._send_json(HTTPStatus.OK, {"ok": True, "path": str(target)})
            elif path == "/api/files/delete":
                body = self._read_json()
                target = str(body.get("path", ""))
                self.app.files.delete(target, bool(body.get("recursive", False)))
                self.app.audit.write("file_delete", self._remote_ip(), path=target)
                self._send_json(HTTPStatus.OK, {"ok": True})
            elif path == "/api/files/extract":
                body = self._read_json()
                archive = str(body.get("archive", ""))
                target = str(body.get("target", ""))
                result = self.app.files.extract_zip(archive, target)
                self.app.audit.write("zip_extract", self._remote_ip(), archive=archive, target=target, **result)
                self._send_json(HTTPStatus.OK, {"ok": True, **result})
            else:
                self.close_connection = True
                self._json_error(HTTPStatus.NOT_FOUND, "Not found")
        except FileConflictError as exc:
            self._json_error(HTTPStatus.CONFLICT, str(exc))
        except (AIIntegrationError, FileAccessError, TerminalError, UploadError, ValueError) as exc:
            if path in {"/api/files/upload", "/api/uploads/chunk"}:
                self.close_connection = True
            self._json_error(HTTPStatus.BAD_REQUEST, str(exc))
        except FileExistsError:
            self._json_error(HTTPStatus.CONFLICT, "Destination already exists")
        except FileNotFoundError:
            self._json_error(HTTPStatus.NOT_FOUND, "File or directory not found")
        except PermissionError:
            self._json_error(HTTPStatus.FORBIDDEN, "The server account cannot perform that operation")
        except OSError as exc:
            self._json_error(HTTPStatus.INTERNAL_SERVER_ERROR, f"Filesystem operation failed ({exc.errno})")

    def _login(self) -> None:
        remote = self._remote_ip()
        locked = self.app.auth.limiter.remaining_lock(remote)
        if locked:
            self._send_json(
                HTTPStatus.TOO_MANY_REQUESTS,
                {"error": "Too many failed attempts", "retryAfter": locked},
                extra_headers={"Retry-After": str(locked)},
            )
            return
        try:
            body = self._read_json(16 * 1024)
        except ValueError as exc:
            self._json_error(HTTPStatus.BAD_REQUEST, str(exc))
            return
        password = body.get("password")
        if not isinstance(password, str) or not self.app.auth.check_password(password):
            delay = self.app.auth.limiter.fail(remote)
            self.app.audit.write("login_failed", remote)
            time.sleep(0.35)
            headers = {"Retry-After": str(delay)} if delay else None
            self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "Invalid credentials"}, extra_headers=headers)
            return
        self.app.auth.limiter.success(remote)
        token, session = self.app.auth.create_session(self.headers.get("User-Agent", ""))
        secure = self._is_https()
        cookie_name = "__Host-openrsc" if secure else "openrsc_session"
        cookie = f"{cookie_name}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={session.expires - int(time.time())}"
        if secure:
            cookie += "; Secure"
        self.app.audit.write("login_success", remote, secure=secure)
        self._send_json(
            HTTPStatus.OK,
            {"ok": True, "csrf": self.app.auth.csrf_token(session), "expires": session.expires},
            cookies=[cookie],
        )

    def _upload(self, query: dict[str, list[str]]) -> None:
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            raise FileAccessError("Content-Length is required for uploads")
        try:
            length = int(raw_length)
        except ValueError as exc:
            raise FileAccessError("Invalid Content-Length") from exc
        directory = self._one(query, "directory")
        name = self._one(query, "name")
        overwrite = self._one(query, "overwrite", "0") == "1"
        target, digest = self.app.files.save_upload(self.rfile, directory, name, length, overwrite)
        self.app.audit.write("file_upload", self._remote_ip(), path=str(target), bytes=length, sha256=digest)
        self._send_json(HTTPStatus.CREATED, {"ok": True, "path": str(target), "bytes": length, "sha256": digest})

    def _upload_chunk(self, session: Session, query: dict[str, list[str]]) -> None:
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            raise UploadError("Content-Length is required for upload chunks")
        try:
            length = int(raw_length)
            offset = int(self._one(query, "offset"))
        except ValueError as exc:
            raise UploadError("Invalid chunk length or offset") from exc
        upload_id = self._one(query, "uploadId")
        result = self.app.uploads.append(session.sid, upload_id, offset, self.rfile, length)
        self._send_json(HTTPStatus.OK, {"ok": True, **result})

    def _ensure_terminal(self) -> None:
        if not self.app.config.terminal.get("enabled", True):
            raise TerminalError("Terminal is disabled")

    def _require_session(self, *, close_on_failure: bool = False) -> Session | None:
        cookie_header = self.headers.get("Cookie", "")
        token = ""
        try:
            parsed = http.cookies.SimpleCookie(cookie_header)
            for name in ("__Host-openrsc", "openrsc_session"):
                if name in parsed:
                    token = parsed[name].value
                    break
        except http.cookies.CookieError:
            pass
        if not token:
            if close_on_failure:
                self.close_connection = True
            self._json_error(HTTPStatus.UNAUTHORIZED, "Authentication required")
            return None
        try:
            return self.app.auth.verify_session(token, self.headers.get("User-Agent", ""))
        except AuthenticationError:
            if close_on_failure:
                self.close_connection = True
            self._json_error(HTTPStatus.UNAUTHORIZED, "Session expired or invalid", cookies=self._expired_cookies())
            return None

    def _same_origin(self) -> bool:
        fetch_site = self.headers.get("Sec-Fetch-Site", "")
        if fetch_site and fetch_site not in {"same-origin", "none"}:
            return False
        origin = self.headers.get("Origin")
        if not origin:
            return True
        parsed = urlsplit(origin)
        expected_scheme = "https" if self._is_https() else "http"
        expected_host = self._external_host()
        return parsed.scheme == expected_scheme and parsed.netloc.casefold() == expected_host.casefold()

    def _is_trusted_proxy(self) -> bool:
        return self.client_address[0] in self.app.trusted_proxies

    def _is_https(self) -> bool:
        if not self._is_trusted_proxy():
            return False
        return self.headers.get("X-Forwarded-Proto", "").split(",", 1)[0].strip().casefold() == "https"

    def _external_host(self) -> str:
        value = self.headers.get("Host", "")
        if self._is_trusted_proxy():
            forwarded = self.headers.get("X-Forwarded-Host", "").split(",", 1)[0].strip()
            if forwarded:
                value = forwarded
        if not value or any(char in value for char in "\r\n/\\"):
            return "invalid.invalid"
        return value

    def _remote_ip(self) -> str:
        direct = self.client_address[0]
        if not self._is_trusted_proxy():
            return direct
        candidates = [
            self.headers.get("CF-Connecting-IP", ""),
            self.headers.get("X-Forwarded-For", "").split(",", 1)[0].strip(),
        ]
        for candidate in candidates:
            try:
                return str(ipaddress.ip_address(candidate))
            except ValueError:
                continue
        return direct

    @staticmethod
    def _one(query: dict[str, list[str]], name: str, default: str | None = None) -> str:
        values = query.get(name)
        if not values:
            if default is not None:
                return default
            raise ValueError(f"Missing query parameter: {name}")
        return values[0]

    def _read_json(self, maximum: int = 1024 * 1024) -> dict[str, Any]:
        if self.headers.get_content_type() != "application/json":
            raise ValueError("Content-Type must be application/json")
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            raise ValueError("Content-Length is required")
        try:
            length = int(raw_length)
        except ValueError as exc:
            raise ValueError("Invalid Content-Length") from exc
        if length < 0 or length > maximum:
            raise ValueError("Request body is too large")
        raw = self.rfile.read(length)
        if len(raw) != length:
            raise ValueError("Incomplete request body")
        try:
            body = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Request body is not valid UTF-8 JSON") from exc
        if not isinstance(body, dict):
            raise ValueError("JSON body must be an object")
        return body

    def _serve_static(self, request_path: str, *, head_only: bool) -> None:
        filename, content_type = STATIC_FILES[request_path]
        path = STATIC_DIR / filename
        try:
            data = path.read_bytes()
        except OSError:
            self._json_error(HTTPStatus.NOT_FOUND, "Static asset not found", head_only=head_only)
            return
        etag = f'"{__version__}-{len(data)}-{int(path.stat().st_mtime)}"'
        if self.headers.get("If-None-Match") == etag:
            self.send_response(HTTPStatus.NOT_MODIFIED)
            self._security_headers(api=False)
            self.send_header("ETag", etag)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(HTTPStatus.OK)
        self._security_headers(api=False)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache")
        self.send_header("ETag", etag)
        self.end_headers()
        if not head_only:
            self.wfile.write(data)

    def _serve_file(self, user_path: str, *, inline: bool, head_only: bool) -> None:
        resolved = self.app.files.resolve(user_path)
        path = resolved.path
        if not path.is_file():
            raise FileAccessError("Path is not a file")
        size = path.stat().st_size
        start, end, status = 0, max(0, size - 1), HTTPStatus.OK
        range_value = self.headers.get("Range")
        if range_value:
            try:
                unit, value = range_value.split("=", 1)
                if unit != "bytes" or "," in value:
                    raise ValueError
                left, right = value.split("-", 1)
                if left:
                    start = int(left)
                    end = int(right) if right else size - 1
                else:
                    suffix = int(right)
                    start = max(0, size - suffix)
                    end = size - 1
                if start < 0 or end < start or start >= size:
                    raise ValueError
                end = min(end, size - 1)
                status = HTTPStatus.PARTIAL_CONTENT
            except ValueError:
                self.send_response(HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE)
                self._security_headers(api=True)
                self.send_header("Content-Range", f"bytes */{size}")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
        content_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        safe_inline = content_type.startswith(("image/", "audio/", "video/")) or content_type == "application/pdf"
        disposition = "inline" if inline and safe_inline else "attachment"
        length = 0 if size == 0 else end - start + 1
        self.send_response(status)
        self._security_headers(api=True, sandbox=disposition == "inline")
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        self.send_header("Accept-Ranges", "bytes")
        self.send_header("Last-Modified", email.utils.formatdate(path.stat().st_mtime, usegmt=True))
        self.send_header("Content-Disposition", f"{disposition}; filename*=UTF-8''{quote(path.name)}")
        if status == HTTPStatus.PARTIAL_CONTENT:
            self.send_header("Content-Range", f"bytes {start}-{end}/{size}")
        self.end_headers()
        if head_only or length == 0:
            return
        with path.open("rb") as handle:
            handle.seek(start)
            remaining = length
            while remaining:
                chunk = handle.read(min(1024 * 1024, remaining))
                if not chunk:
                    break
                self.wfile.write(chunk)
                remaining -= len(chunk)

    def _serve_archive(self, user_path: str) -> None:
        archive, download_name = self.app.files.make_archive(user_path)
        try:
            size = archive.stat().st_size
            self.send_response(HTTPStatus.OK)
            self._security_headers(api=True)
            self.send_header("Content-Type", "application/zip")
            self.send_header("Content-Length", str(size))
            self.send_header("Content-Disposition", f"attachment; filename*=UTF-8''{quote(download_name)}")
            self.end_headers()
            with archive.open("rb") as handle:
                shutil.copyfileobj(handle, self.wfile, length=1024 * 1024)
        finally:
            archive.unlink(missing_ok=True)

    def _security_headers(self, *, api: bool, sandbox: bool = False) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        if sandbox:
            self.send_header("Content-Security-Policy", "sandbox; default-src 'none'")
        else:
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; "
                "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
            )
        if api:
            self.send_header("Cache-Control", "no-store")
        if self._is_https():
            self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

    def _send_json(
        self,
        status: HTTPStatus,
        value: dict[str, Any],
        *,
        cookies: list[str] | None = None,
        extra_headers: dict[str, str] | None = None,
        head_only: bool = False,
    ) -> None:
        data = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self._security_headers(api=True)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        if self.close_connection:
            self.send_header("Connection", "close")
        for cookie in cookies or []:
            self.send_header("Set-Cookie", cookie)
        for key, item in (extra_headers or {}).items():
            if item:
                self.send_header(key, item)
        self.end_headers()
        if not head_only:
            self.wfile.write(data)

    def _json_error(
        self,
        status: HTTPStatus,
        message: str,
        *,
        cookies: list[str] | None = None,
        head_only: bool = False,
    ) -> None:
        if self.wfile.closed:
            return
        self._send_json(status, {"error": message}, cookies=cookies, head_only=head_only)

    @staticmethod
    def _expired_cookies() -> list[str]:
        return [
            "__Host-openrsc=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0",
            "openrsc_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0",
        ]


def create_server(config: OpenRSCConfig, data_dir: Path, *, host: str | None = None, port: int | None = None) -> OpenRSCServer:
    app = OpenRSCApplication(config, data_dir)
    return OpenRSCServer((host or config.host, config.port if port is None else port), app)
