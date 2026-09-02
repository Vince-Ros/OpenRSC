from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse
import zipfile
from http.client import HTTPConnection
from pathlib import Path
from unittest import mock

from openrsc.ai import AIIntegration, AIIntegrationError
from openrsc.ai_cli import codex_event_text
from openrsc.auth import AuthenticationError, AuthService, LoginLimiter
from openrsc.config import OpenRSCConfig, build_config, load_config, password_record, verify_password, write_config
from openrsc.files import FileAccessError, FileManager
from openrsc.server import create_server
from openrsc.terminal import TerminalError, TerminalManager, TerminalSession
from openrsc.uploads import UploadError, UploadManager


TEST_PASSWORD = "correct-horse-for-tests"


def test_config(path: Path, root: Path, *, port: int = 8787) -> OpenRSCConfig:
    raw = build_config(TEST_PASSWORD, roots=[str(root)], port=port)
    raw["security"]["password"] = password_record(TEST_PASSWORD, iterations=100_000)
    raw["security"]["session_ttl_seconds"] = 600
    raw["terminal"]["idle_seconds"] = 60
    write_config(path, raw)
    return load_config(path)


class PasswordAndSessionTests(unittest.TestCase):
    def test_password_verifier_accepts_only_correct_password(self) -> None:
        record = password_record(TEST_PASSWORD, iterations=100_000)
        self.assertTrue(verify_password(TEST_PASSWORD, record))
        self.assertFalse(verify_password("wrong-password-value", record))
        self.assertNotIn(TEST_PASSWORD, json.dumps(record))

    def test_signed_session_csrf_tamper_and_revocation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = test_config(root / "config.json", root)
            auth = AuthService(config)
            token, created = auth.create_session("test-agent", now=1_000)
            verified = auth.verify_session(token, "test-agent", now=1_001)
            self.assertEqual(created.sid, verified.sid)
            csrf = auth.csrf_token(verified)
            self.assertTrue(auth.verify_csrf(verified, csrf))
            self.assertFalse(auth.verify_csrf(verified, csrf + "x"))
            encoded_payload, encoded_signature = token.split(".", 1)
            tampered_signature = ("A" if encoded_signature[0] != "A" else "B") + encoded_signature[1:]
            with self.assertRaises(AuthenticationError):
                auth.verify_session(f"{encoded_payload}.{tampered_signature}", "test-agent", now=1_001)
            with self.assertRaises(AuthenticationError):
                auth.verify_session(token, "different-agent", now=1_001)
            auth.revoke(verified.sid)
            with self.assertRaises(AuthenticationError):
                auth.verify_session(token, "test-agent", now=1_002)

    def test_login_limiter_locks_and_resets(self) -> None:
        limiter = LoginLimiter(3, 60, 120)
        self.assertEqual(limiter.fail("client", now=10), 0)
        self.assertEqual(limiter.fail("client", now=11), 0)
        self.assertEqual(limiter.fail("client", now=12), 120)
        self.assertEqual(limiter.remaining_lock("client", now=13), 119)
        limiter.success("client")
        self.assertEqual(limiter.remaining_lock("client", now=13), 0)


class FileManagerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.root = self.base / "root"
        self.root.mkdir()
        self.config = test_config(self.base / "config.json", self.root)
        self.files = FileManager(self.config, self.base / "tmp")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_list_preview_upload_rename_and_delete(self) -> None:
        (self.root / "alpha.txt").write_text("hello OpenRSC", encoding="utf-8")
        listing = self.files.list_directory(str(self.root))
        self.assertEqual(listing["entries"][0]["name"], "alpha.txt")
        preview = self.files.preview_text(str(self.root / "alpha.txt"))
        self.assertEqual(preview["text"], "hello OpenRSC")
        self.assertEqual(len(preview["sha256"]), 64)
        self.assertIn("modified", preview)
        target, digest = self.files.save_upload(io.BytesIO(b"payload"), str(self.root), "upload.bin", 7, False)
        self.assertEqual(target.read_bytes(), b"payload")
        self.assertEqual(len(digest), 64)
        renamed = self.files.rename(str(target), "renamed.bin")
        self.assertTrue(renamed.exists())
        self.files.delete(str(renamed), recursive=False)
        self.assertFalse(renamed.exists())

    def test_text_edit_is_atomic_and_rejects_stale_revision(self) -> None:
        target = self.root / "settings.ini"
        target.write_text("[server]\nport = 8787\n", encoding="utf-8")
        opened = self.files.preview_text(str(target))
        saved = self.files.write_text(str(target), "[server]\nport = 9090\n", opened["sha256"])
        self.assertEqual(target.read_text(encoding="utf-8"), "[server]\nport = 9090\n")
        self.assertEqual(saved["size"], len("[server]\nport = 9090\n".encode("utf-8")))
        self.assertEqual(self.files.preview_text(str(target))["sha256"], saved["sha256"])
        with self.assertRaises(FileAccessError):
            self.files.write_text(str(target), "stale edit", opened["sha256"])
        self.assertFalse(any(target.parent.glob(f".{target.name}.openrsc-*.tmp")))

    def test_path_escape_and_root_delete_are_rejected(self) -> None:
        outside = self.base / "outside.txt"
        outside.write_text("outside", encoding="utf-8")
        with self.assertRaises(FileAccessError):
            self.files.resolve(str(outside))
        with self.assertRaises(FileAccessError):
            self.files.child(str(self.root), "..\\outside")
        if os.name == "nt":
            with self.assertRaises(FileAccessError):
                self.files.child(str(self.root), "NUL.txt")
        with self.assertRaises(FileAccessError):
            self.files.delete(str(self.root), recursive=True)

    def test_zip_extraction_and_zip_slip_rejection(self) -> None:
        good = self.root / "good.zip"
        with zipfile.ZipFile(good, "w") as package:
            package.writestr("folder/item.txt", "inside")
        result = self.files.extract_zip(str(good), str(self.root))
        self.assertEqual(result["files"], 1)
        self.assertEqual((self.root / "folder" / "item.txt").read_text(), "inside")

        bad = self.root / "bad.zip"
        with zipfile.ZipFile(bad, "w") as package:
            package.writestr("../escape.txt", "escape")
        with self.assertRaises(FileAccessError):
            self.files.extract_zip(str(bad), str(self.root))
        self.assertFalse((self.base / "escape.txt").exists())

        drive_path = self.root / "drive-path.zip"
        with zipfile.ZipFile(drive_path, "w") as package:
            package.writestr("C:/escape.txt", "escape")
        with self.assertRaises(FileAccessError):
            self.files.extract_zip(str(drive_path), str(self.root))

    def test_archive_generation(self) -> None:
        (self.root / "folder").mkdir()
        (self.root / "folder" / "item.txt").write_text("archive", encoding="utf-8")
        archive, name = self.files.make_archive(str(self.root / "folder"))
        try:
            self.assertEqual(name, "folder.zip")
            with zipfile.ZipFile(archive) as package:
                self.assertEqual(package.read("folder/item.txt"), b"archive")
        finally:
            archive.unlink(missing_ok=True)


class TerminalTests(unittest.TestCase):
    def test_persistent_system_shell_returns_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            terminal = TerminalSession(root, max_buffer=128_000, max_input=8_000)
            try:
                marker = "OPENRSC_TERMINAL_TEST_7F2A"
                result_file = root / "terminal-result.txt"
                if os.name == "nt":
                    terminal.send("set OPENRSC_PERSISTENCE=YES")
                    terminal.send(f"echo %OPENRSC_PERSISTENCE%:{marker}>terminal-result.txt")
                else:
                    terminal.send("export OPENRSC_PERSISTENCE=YES")
                    terminal.send(f"echo $OPENRSC_PERSISTENCE:{marker}>terminal-result.txt")
                cursor = 0
                output = ""
                deadline = time.monotonic() + 8
                while not result_file.exists() and time.monotonic() < deadline:
                    result = terminal.read(cursor)
                    cursor = int(result["cursor"])
                    output += str(result["output"])
                    time.sleep(0.05)
                self.assertTrue(result_file.exists(), output)
                self.assertEqual(result_file.read_text().strip(), f"YES:{marker}")
                self.assertIn("OPENRSC_PERSISTENCE", output)
                self.assertIn("$ ", output)
                self.assertTrue(terminal.read(cursor)["running"])
            finally:
                terminal.close()

    def test_manager_keeps_terminal_tabs_independent_and_enforces_limit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manager = TerminalManager(
                root,
                max_buffer=128_000,
                max_input=8_000,
                idle_seconds=60,
                max_sessions=2,
            )
            try:
                first = manager.get("browser-session")
                workspace = root / "selected-workspace"
                workspace.mkdir()
                second_record = manager.create("browser-session", "Build shell", directory=workspace)
                second = manager.get("browser-session", str(second_record["id"]))
                self.assertNotEqual(first.process.pid, second.process.pid)
                self.assertEqual(second_record["directory"], str(workspace.resolve()))
                self.assertEqual([item["name"] for item in manager.list("browser-session")], ["Terminal 1", "Build shell"])
                renamed = manager.rename("browser-session", str(second_record["id"]), "Logs")
                self.assertEqual(renamed["name"], "Logs")
                with self.assertRaises(TerminalError):
                    manager.create("browser-session", "Too many")
                self.assertTrue(manager.close("browser-session", str(second_record["id"])))
                self.assertEqual([item["id"] for item in manager.list("browser-session")], ["main"])
            finally:
                manager.close_all()


class AIIntegrationTests(unittest.TestCase):
    def test_directory_scoped_terminal_specs_and_shell_command(self) -> None:
        integration = AIIntegration()
        with tempfile.TemporaryDirectory(prefix="OpenRSC AI ") as directory:
            workspace = Path(directory).resolve()
            with mock.patch.object(AIIntegration, "_executable", side_effect=lambda name: f"C:\\tools\\{name}.CMD"):
                claude_name, claude_args = integration.terminal_spec("claude-cli", workspace)
                remote_name, remote_args = integration.terminal_spec("claude-remote", workspace)
                codex_name, codex_args = integration.terminal_spec("codex-cli", workspace)
            self.assertEqual((claude_name, remote_name, codex_name), ("Claude CLI", "Claude Remote", "Codex CLI"))
            self.assertEqual(claude_args[-1], str(workspace))
            self.assertEqual(codex_args[-1], str(workspace))
            self.assertIn("--remote-control", remote_args)
            self.assertIn(workspace.name, remote_args[-1])
            command = integration.shell_command([sys.executable, "bridge script.py", "--directory", str(workspace)])
            self.assertIn("bridge script.py", command)
            self.assertIn(str(workspace), command)
            with self.assertRaises(AIIntegrationError):
                integration.terminal_spec("other", workspace)

    def test_codex_json_events_are_rendered_without_raw_protocol(self) -> None:
        thread_id, text = codex_event_text({"type": "thread.started", "thread_id": "thread-123"})
        self.assertEqual((thread_id, text), ("thread-123", None))
        thread_id, text = codex_event_text(
            {"type": "item.completed", "item": {"type": "agent_message", "text": "Finished cleanly."}}
        )
        self.assertEqual((thread_id, text), (None, "Finished cleanly."))
        _, error = codex_event_text({"type": "turn.failed", "message": "network unavailable"})
        self.assertEqual(error, "[Codex error] network unavailable")

    def test_codex_app_receives_selected_directory(self) -> None:
        integration = AIIntegration()
        process = mock.Mock(pid=4242)
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(AIIntegration, "_executable", return_value="C:\\tools\\codex.exe"), \
             mock.patch("openrsc.ai.subprocess.Popen", return_value=process) as popen:
            workspace = Path(directory).resolve()
            self.assertEqual(integration.open_codex_app(workspace), 4242)
            args, kwargs = popen.call_args
            self.assertEqual(args[0], ["C:\\tools\\codex.exe", "app", str(workspace)])
            self.assertEqual(kwargs["cwd"], workspace)


class ChunkedUploadTests(unittest.TestCase):
    def test_sequential_chunks_offset_check_and_finish(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "root"
            root.mkdir()
            config = test_config(base / "config.json", root)
            files = FileManager(config, base / "tmp")
            uploads = UploadManager(files, chunk_bytes=4)
            started = uploads.begin("session", str(root), "chunked.bin", 7, False)
            upload_id = str(started["uploadId"])
            self.assertEqual(uploads.append("session", upload_id, 0, io.BytesIO(b"abcd"), 4)["received"], 4)
            with self.assertRaises(UploadError):
                uploads.append("session", upload_id, 2, io.BytesIO(b"efg"), 3)
            self.assertEqual(uploads.append("session", upload_id, 4, io.BytesIO(b"efg"), 3)["received"], 7)
            target, length, digest = uploads.finish("session", upload_id)
            self.assertEqual((target.read_bytes(), length), (b"abcdefg", 7))
            self.assertEqual(digest, "7d1a54127b222502f5b79b5fb0803061152a44f92b37e23c6527baf665d4da9a")


class HTTPIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.root = self.base / "root"
        self.root.mkdir()
        (self.root / "welcome.txt").write_text("OpenRSC integration", encoding="utf-8")
        config = test_config(self.base / "config.json", self.root, port=8787)
        self.server = create_server(config, self.base / "data", host="127.0.0.1", port=0)
        self.port = int(self.server.server_address[1])
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.connection = HTTPConnection("127.0.0.1", self.port, timeout=10)
        self.user_agent = "OpenRSC-Integration-Test"
        self.cookie = ""
        self.csrf = ""

    def tearDown(self) -> None:
        self.connection.close()
        self.server.shutdown()
        self.thread.join(timeout=5)
        self.server.server_close()
        self.temp.cleanup()

    def request(self, method: str, target: str, body: bytes | None = None, headers: dict[str, str] | None = None):
        actual = {"User-Agent": self.user_agent, **(headers or {})}
        if self.cookie:
            actual["Cookie"] = self.cookie
        self.connection.request(method, target, body=body, headers=actual)
        response = self.connection.getresponse()
        data = response.read()
        payload = json.loads(data) if data and "application/json" in (response.getheader("Content-Type") or "") else data
        return response, payload

    def login(self) -> None:
        body = json.dumps({"password": TEST_PASSWORD}).encode()
        response, payload = self.request("POST", "/api/login", body, {"Content-Type": "application/json"})
        self.assertEqual(response.status, 200, payload)
        self.cookie = response.getheader("Set-Cookie").split(";", 1)[0]
        self.csrf = payload["csrf"]

    def post_json(self, path: str, body: dict[str, object], *, csrf: bool = True):
        headers = {"Content-Type": "application/json", "Origin": f"http://127.0.0.1:{self.port}"}
        if csrf:
            headers["X-CSRF-Token"] = self.csrf
        return self.request("POST", path, json.dumps(body).encode(), headers)

    def test_end_to_end_login_files_terminal_and_logout(self) -> None:
        response, health = self.request("GET", "/healthz")
        self.assertEqual((response.status, health), (200, {"ok": True}))
        response, page = self.request("GET", "/")
        self.assertEqual(response.status, 200)
        self.assertIn(b"OpenRSC", page)
        self.assertIn(b'id="terminalTabs"', page)
        self.assertIn(b"New terminal", page)
        self.assertIn(b"apple-mobile-web-app-capable", page)
        self.assertIn(b'/manifest.webmanifest', page)
        self.assertIn(b'id="icon-terminal"', page)
        self.assertIn(b'href="#icon-send"', page)
        self.assertIn(b'id="composerArea"', page)
        self.assertIn(b'/styles.css?v=20260829.15', page)
        self.assertIn(b'/app.js?v=20260829.13', page)
        self.assertIn(b'class="mobile-action-label">AI</span>', page)
        self.assertIn(b'id="terminalWelcome"', page)
        self.assertIn(b'id="icon-book-open"', page)
        self.assertIn(b'id="icon-undo"', page)
        self.assertIn(b'id="icon-redo"', page)
        self.assertIn(b'id="icon-save"', page)
        self.assertIn(b'id="aiView"', page)
        self.assertIn(b'data-ai-provider="claude-cli"', page)
        self.assertIn(b'data-ai-provider="claude-remote"', page)
        self.assertIn(b'data-ai-provider="codex-cli"', page)
        self.assertIn(b'data-ai-provider="codex-app"', page)
        self.assertIn(b'width="0" height="0"', page)
        self.assertIn(b'.icon-sprite { position: fixed;', page)
        self.assertIn(b'autocapitalize="none"', page)
        self.assertIn(b'enterkeyhint="send"', page)
        self.assertIn("frame-ancestors 'none'", response.getheader("Content-Security-Policy"))

        response, script = self.request("GET", "/app.js")
        self.assertEqual(response.status, 200)
        self.assertIn(b"visualViewport", script)
        self.assertIn(b"syncComposerClearance", script)
        self.assertIn(b'document.activeElement === commandInput', script)
        self.assertIn(b'commandInput.blur()', script)
        self.assertIn(b'input.readOnly = true', script)
        self.assertIn(b'svg.setAttribute("viewBox", "0 0 24 24")', script)
        self.assertIn(b'function syncTerminalWelcome(outputText = "")', script)
        self.assertIn(b'syncTerminalWelcome(terminal?.output || "")', script)
        self.assertIn(b'syncTerminalWelcome(terminal.output)', script)
        self.assertIn(b'syncTerminalWelcome("")', script)
        self.assertIn(b'function highlightedCode(text, language)', script)
        self.assertIn(b'function showCodeEditor()', script)
        self.assertIn(b'function showUnsavedDialog()', script)
        self.assertIn(b'expectedSha256', script)
        self.assertIn(b'Colored source \xc2\xb7 locked', script)
        self.assertIn(b"Don't save", script)
        self.assertIn(b'function launchAI(provider, button)', script)
        self.assertIn(b'openrsc.activeTerminalId', script)
        self.assertIn(b'async function recoverTerminalTranscript(terminal)', script)
        self.assertIn(b'rememberActiveTerminal(state.activeTerminalId)', script)
        self.assertIn(b'window.addEventListener("pageshow"', script)
        self.assertIn(b'"/api/ai/launch"', script)
        self.assertIn(b'"AI sessions", "Claude and Codex workspace launchers"', script)
        response, styles = self.request("GET", "/styles.css")
        self.assertEqual(response.status, 200)
        self.assertIn(b'grid-template-areas: "up root refresh" "path path path"', styles)
        self.assertIn(b'grid-template-columns: minmax(0,1fr) auto', styles)
        self.assertIn(b"--app-height", styles)
        self.assertIn(b"--composer-clearance", styles)
        self.assertIn(b"-webkit-text-fill-color: #f5f5f5", styles)
        self.assertIn(b".command-composer.sending", styles)
        self.assertIn(b".command-composer {", styles)
        self.assertIn(b"background: #0a0a0a", styles)
        self.assertIn(b"--bg: #050505", styles)
        self.assertIn(b"--sidebar: #0b0b0b", styles)
        self.assertIn(b"--surface-2: #121212", styles)
        self.assertIn(b"padding: 7px 2px", styles)
        self.assertIn(b"font: 16px/22px", styles)
        self.assertIn(b".command-composer:focus-within { border-color: #3a3a3a; background: #0a0a0a; }", styles)
        self.assertNotIn(b"body { position: fixed", styles)
        self.assertIn(b"#loginView, #app { position: fixed", styles)
        self.assertIn(b".app-main { min-width: 0; min-height: 0", styles)
        self.assertIn(b".workspace { min-width: 0; min-height: 0; height: 100%; overflow-x: hidden; overflow-y: auto", styles)
        self.assertIn(b"touch-action: pan-y pinch-zoom", styles)
        self.assertIn(b".terminal-output { position: relative", styles)
        self.assertIn(b"overflow-y: auto", styles)
        self.assertIn(b".terminal-stage.has-output .terminal-welcome", styles)
        self.assertIn(b".terminal-welcome[hidden] + .terminal-output { padding-top: 20px; }", styles)
        self.assertIn(b".button.subtle:hover { background: transparent; color: var(--accent); }", styles)
        self.assertIn(b".icon-button:hover { background: transparent; color: var(--accent); }", styles)
        self.assertIn(b".new-terminal:hover { background: transparent; color: var(--accent); }", styles)
        self.assertIn(b".terminal-tab:hover { background: transparent; color: var(--text); }", styles)
        self.assertIn(b".terminal-tab-close:hover { background: transparent; color: #fff !important; }", styles)
        self.assertIn(b".nav-item:hover { background: transparent; color: #fff; }", styles)
        self.assertIn(b".tool-button:hover { background: transparent; color: #fff; }", styles)
        self.assertIn(b".row-actions button:hover { background: transparent; color: #fff; }", styles)
        self.assertIn(b".send-command:hover { background: #fff; color: var(--accent); }", styles)
        self.assertIn(b".modal-card--code", styles)
        self.assertIn(b".modal.modal--code { place-items: stretch; padding: 0", styles)
        self.assertIn(b".code-line-number { position: sticky; left: 0", styles)
        self.assertIn(b"height: var(--app-height); max-height: none", styles)
        self.assertIn(b".code-editor-input", styles)
        self.assertIn(b".tok-keyword", styles)
        self.assertIn(b".tok-variable", styles)
        self.assertIn(b"-webkit-text-fill-color: rgba(0,0,0,0) !important", styles)
        self.assertIn(b".modal.modal--chooser", styles)
        self.assertIn(b'"modal--chooser"', script)
        self.assertIn(b".code-tool:hover, .code-tool--accent:hover { background: transparent", styles)
        self.assertIn(b".ai-provider-grid", styles)
        self.assertIn(b".ai-launch:hover { background: transparent", styles)

        response, manifest = self.request("GET", "/manifest.webmanifest")
        self.assertEqual(response.status, 200)
        if isinstance(manifest, bytes):
            manifest = json.loads(manifest)
        self.assertEqual(manifest["display"], "standalone")
        self.assertEqual(manifest["start_url"], "/")
        response, icon = self.request("GET", "/apple-touch-icon.png")
        self.assertEqual(response.status, 200)
        self.assertEqual(response.getheader("Content-Type"), "image/png")
        self.assertTrue(icon.startswith(b"\x89PNG\r\n\x1a\n"))

        response, _ = self.request("GET", "/api/session")
        self.assertEqual(response.status, 401)

        self.login()
        response, session = self.request("GET", "/api/session")
        self.assertEqual(response.status, 200)
        self.assertEqual(session["csrf"], self.csrf)
        self.assertEqual(len(session["roots"]), 1)

        text_target = "/api/file/text?" + urllib.parse.urlencode({"path": str(self.root / "welcome.txt")})
        response, opened = self.request("GET", text_target)
        self.assertEqual(response.status, 200, opened)
        self.assertEqual(opened["text"], "OpenRSC integration")
        self.assertEqual(len(opened["sha256"]), 64)
        response, saved = self.post_json(
            "/api/file/text",
            {"path": str(self.root / "welcome.txt"), "text": "print('OpenRSC editor')\n", "expectedSha256": opened["sha256"]},
        )
        self.assertEqual(response.status, 200, saved)
        self.assertEqual((self.root / "welcome.txt").read_text(encoding="utf-8"), "print('OpenRSC editor')\n")
        response, conflict = self.post_json(
            "/api/file/text",
            {"path": str(self.root / "welcome.txt"), "text": "stale", "expectedSha256": opened["sha256"]},
        )
        self.assertEqual(response.status, 409, conflict)
        self.assertIn("changed on the host", conflict["error"])

        response, rejected = self.post_json("/api/files/mkdir", {"directory": str(self.root), "name": "blocked"}, csrf=False)
        self.assertEqual(response.status, 403, rejected)
        response, created = self.post_json("/api/files/mkdir", {"directory": str(self.root), "name": "created"})
        self.assertEqual(response.status, 201, created)

        payload = b"binary-payload"
        response, started = self.post_json(
            "/api/uploads/start",
            {"directory": str(self.root), "name": "sent.bin", "size": len(payload), "overwrite": False},
        )
        self.assertEqual(response.status, 201, started)
        split = 6
        first_target = "/api/uploads/chunk?" + urllib.parse.urlencode({"uploadId": started["uploadId"], "offset": 0})
        response, first = self.request(
            "POST",
            first_target,
            payload[:split],
            {"Content-Type": "application/octet-stream", "X-CSRF-Token": self.csrf, "Origin": f"http://127.0.0.1:{self.port}"},
        )
        self.assertEqual(response.status, 200, first)
        second_target = "/api/uploads/chunk?" + urllib.parse.urlencode({"uploadId": started["uploadId"], "offset": split})
        response, second = self.request(
            "POST",
            second_target,
            payload[split:],
            {"Content-Type": "application/octet-stream", "X-CSRF-Token": self.csrf, "Origin": f"http://127.0.0.1:{self.port}"},
        )
        self.assertEqual(response.status, 200, second)
        response, uploaded = self.post_json("/api/uploads/finish", {"uploadId": started["uploadId"]})
        self.assertEqual(response.status, 201, uploaded)
        self.assertEqual((self.root / "sent.bin").read_bytes(), payload)

        listing_target = "/api/files?" + urllib.parse.urlencode({"path": str(self.root)})
        response, listing = self.request("GET", listing_target)
        self.assertEqual(response.status, 200)
        self.assertIn("sent.bin", {item["name"] for item in listing["entries"]})

        marker = "OPENRSC_HTTP_TERMINAL_41B9"
        result_file = self.root / "http-terminal.txt"
        response, accepted = self.post_json("/api/terminal/input", {"input": f"echo {marker}>http-terminal.txt"})
        self.assertEqual(response.status, 202, accepted)
        found = False
        cursor = 0
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            response, result = self.request("GET", f"/api/terminal/output?cursor={cursor}")
            self.assertEqual(response.status, 200)
            cursor = result["cursor"]
            if result_file.exists() and result_file.read_text().strip() == marker:
                found = True
                break
            time.sleep(0.05)
        self.assertTrue(found)

        response, terminals = self.request("GET", "/api/terminals")
        self.assertEqual(response.status, 200, terminals)
        self.assertEqual(len(terminals["terminals"]), 1)
        response, created_terminal = self.post_json("/api/terminals", {"name": "Second shell"})
        self.assertEqual(response.status, 201, created_terminal)
        terminal_id = created_terminal["terminal"]["id"]
        self.assertNotEqual(terminal_id, "main")
        second_marker = "OPENRSC_SECOND_TERMINAL_80D2"
        second_result = self.root / "second-terminal.txt"
        response, accepted = self.post_json(
            "/api/terminal/input",
            {"terminalId": terminal_id, "input": f"echo {second_marker}>second-terminal.txt"},
        )
        self.assertEqual(response.status, 202, accepted)
        deadline = time.monotonic() + 8
        while not second_result.exists() and time.monotonic() < deadline:
            response, _ = self.request(
                "GET",
                "/api/terminal/output?" + urllib.parse.urlencode({"terminalId": terminal_id, "cursor": 0}),
            )
            self.assertEqual(response.status, 200)
            time.sleep(0.05)
        self.assertEqual(second_result.read_text().strip(), second_marker)
        response, renamed = self.post_json(
            "/api/terminal/rename", {"terminalId": terminal_id, "name": "Logs"}
        )
        self.assertEqual((response.status, renamed["terminal"]["name"]), (200, "Logs"))
        response, closed = self.post_json("/api/terminal/close", {"terminalId": terminal_id})
        self.assertEqual((response.status, closed["closed"]), (200, True))

        response, logged_out = self.post_json("/api/logout", {})
        self.assertEqual((response.status, logged_out), (200, {"ok": True}))
        response, _ = self.request("GET", "/api/session")
        self.assertEqual(response.status, 401)

    def test_authenticated_devices_share_openrsc_terminals(self) -> None:
        self.login()
        response, created = self.post_json("/api/terminals", {"name": "test"})
        self.assertEqual(response.status, 201, created)
        terminal_id = created["terminal"]["id"]
        pc_marker = "OPENRSC_PC_SHARED_5D21"
        response, accepted = self.post_json(
            "/api/terminal/input",
            {"terminalId": terminal_id, "input": f"echo {pc_marker}"},
        )
        self.assertEqual(response.status, 202, accepted)

        phone = HTTPConnection("127.0.0.1", self.port, timeout=10)
        phone_agent = "OpenRSC-Phone-Integration-Test"
        try:
            login_body = json.dumps({"password": TEST_PASSWORD}).encode()
            phone.request(
                "POST",
                "/api/login",
                body=login_body,
                headers={"Content-Type": "application/json", "User-Agent": phone_agent},
            )
            phone_login = phone.getresponse()
            phone_payload = json.loads(phone_login.read())
            self.assertEqual(phone_login.status, 200, phone_payload)
            phone_cookie = phone_login.getheader("Set-Cookie").split(";", 1)[0]
            phone_csrf = phone_payload["csrf"]

            phone.request("GET", "/api/terminals", headers={"Cookie": phone_cookie, "User-Agent": phone_agent})
            phone_response = phone.getresponse()
            phone_terminals = json.loads(phone_response.read())
            self.assertEqual(phone_response.status, 200, phone_terminals)
            self.assertIn(terminal_id, {item["id"] for item in phone_terminals["terminals"]})
            self.assertIn("test", {item["name"] for item in phone_terminals["terminals"]})

            output_target = "/api/terminal/output?" + urllib.parse.urlencode({"terminalId": terminal_id, "cursor": 0})
            phone.request("GET", output_target, headers={"Cookie": phone_cookie, "User-Agent": phone_agent})
            output_response = phone.getresponse()
            phone_output = json.loads(output_response.read())
            self.assertEqual(output_response.status, 200, phone_output)
            self.assertIn(pc_marker, phone_output["output"])

            phone_marker = "OPENRSC_PHONE_SHARED_A804"
            phone.request(
                "POST",
                "/api/terminal/input",
                body=json.dumps({"terminalId": terminal_id, "input": f"echo {phone_marker}"}).encode(),
                headers={
                    "Content-Type": "application/json",
                    "Cookie": phone_cookie,
                    "Origin": f"http://127.0.0.1:{self.port}",
                    "User-Agent": phone_agent,
                    "X-CSRF-Token": phone_csrf,
                },
            )
            phone_input = phone.getresponse()
            phone_input_payload = json.loads(phone_input.read())
            self.assertEqual(phone_input.status, 202, phone_input_payload)

            response, pc_output = self.request("GET", output_target)
            self.assertEqual(response.status, 200, pc_output)
            self.assertIn(phone_marker, pc_output["output"])

            phone.request(
                "POST",
                "/api/logout",
                body=b"{}",
                headers={
                    "Content-Type": "application/json",
                    "Cookie": phone_cookie,
                    "Origin": f"http://127.0.0.1:{self.port}",
                    "User-Agent": phone_agent,
                    "X-CSRF-Token": phone_csrf,
                },
            )
            phone_logout = phone.getresponse()
            self.assertEqual(phone_logout.status, 200, phone_logout.read())
        finally:
            phone.close()

        response, pc_terminals = self.request("GET", "/api/terminals")
        self.assertEqual(response.status, 200, pc_terminals)
        self.assertIn(terminal_id, {item["id"] for item in pc_terminals["terminals"]})

    def test_ai_launchers_are_directory_scoped(self) -> None:
        self.login()
        expected_status = {
            "claude": {"installed": True, "authenticated": True, "version": "Claude test", "account": "Connected"},
            "codex": {"installed": True, "authenticated": True, "version": "Codex test", "account": "Connected"},
        }
        self.server.app.ai.status = lambda refresh=False: expected_status
        self.server.app.ai.terminal_spec = lambda provider, directory: (
            "Claude CLI",
            [sys.executable, "-c", "print('OPENRSC_AI_BRIDGE_READY')"],
        )
        self.server.app.ai.open_codex_app = lambda directory: 4242

        response, status = self.request("GET", "/api/ai/status?refresh=1")
        self.assertEqual((response.status, status), (200, expected_status))

        workspace = self.root / "AI workspace"
        workspace.mkdir()
        response, launched = self.post_json(
            "/api/ai/launch", {"provider": "claude-cli", "directory": str(workspace)}
        )
        self.assertEqual(response.status, 201, launched)
        self.assertEqual(launched["mode"], "terminal")
        self.assertEqual(launched["terminal"]["directory"], str(workspace.resolve()))
        terminal_id = launched["terminal"]["id"]
        deadline = time.monotonic() + 5
        output = ""
        while "OPENRSC_AI_BRIDGE_READY" not in output and time.monotonic() < deadline:
            target = "/api/terminal/output?" + urllib.parse.urlencode({"terminalId": terminal_id, "cursor": 0})
            response, terminal = self.request("GET", target)
            self.assertEqual(response.status, 200, terminal)
            output = terminal["output"]
            time.sleep(0.05)
        self.assertIn("OPENRSC_AI_BRIDGE_READY", output)

        response, desktop = self.post_json(
            "/api/ai/launch", {"provider": "codex-app", "directory": str(workspace)}
        )
        self.assertEqual((response.status, desktop["mode"], desktop["pid"]), (201, "desktop", 4242))

        outside = self.base / "outside"
        outside.mkdir()
        response, rejected = self.post_json(
            "/api/ai/launch", {"provider": "codex-app", "directory": str(outside)}
        )
        self.assertEqual(response.status, 400, rejected)
        self.assertIn("outside the configured roots", rejected["error"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
