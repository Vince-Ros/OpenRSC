from __future__ import annotations

import codecs
import os
import secrets
import signal
import subprocess
import threading
import time
from pathlib import Path


class TerminalError(RuntimeError):
    pass


class TerminalSession:
    def __init__(
        self,
        initial_directory: Path,
        max_buffer: int,
        max_input: int,
        *,
        terminal_id: str = "main",
        name: str = "Terminal 1",
    ) -> None:
        self.initial_directory = initial_directory
        self.max_buffer = max_buffer
        self.max_input = max_input
        self.terminal_id = terminal_id
        self.name = name
        self.created = int(time.time())
        self._buffer = ""
        self._base_cursor = 0
        self._lock = threading.RLock()
        self._write_lock = threading.Lock()
        self._closed = False
        self.last_used = time.monotonic()
        self.process: subprocess.Popen[bytes] | None = None
        self._reader: threading.Thread | None = None
        self._start()

    def _append(self, value: str) -> None:
        if not value:
            return
        with self._lock:
            self._buffer += value.replace("\r\r\n", "\r\n")
            if len(self._buffer) > self.max_buffer:
                remove = len(self._buffer) - self.max_buffer
                self._buffer = self._buffer[remove:]
                self._base_cursor += remove

    def _start(self) -> None:
        if self._closed:
            raise TerminalError("Terminal is closed")
        env = os.environ.copy()
        startupinfo = None
        creationflags = 0
        if os.name == "nt":
            executable = env.get("COMSPEC", "cmd.exe")
            command = [executable, "/Q", "/D"]
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE
            creationflags = subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            executable = env.get("SHELL", "/bin/sh")
            command = [executable]
            creationflags = getattr(os, "setsid", lambda: 0) and 0
        try:
            self.process = subprocess.Popen(
                command,
                cwd=self.initial_directory,
                env=env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=0,
                startupinfo=startupinfo,
                creationflags=creationflags,
                start_new_session=os.name != "nt",
            )
        except OSError as exc:
            raise TerminalError(f"Could not start the system shell: {exc}") from exc
        self._append(f"OpenRSC terminal ready (PID {self.process.pid})\r\n")
        self._reader = threading.Thread(target=self._read_loop, name=f"openrsc-terminal-{self.process.pid}", daemon=True)
        self._reader.start()
        if os.name == "nt":
            self._raw_write('@echo off\r\nchcp 65001>nul\r\nprompt $P$G\r\n')

    def _read_loop(self) -> None:
        process = self.process
        if process is None or process.stdout is None:
            return
        decoder = codecs.getincrementaldecoder("utf-8")("replace")
        try:
            while True:
                chunk = os.read(process.stdout.fileno(), 16 * 1024)
                if not chunk:
                    break
                self._append(decoder.decode(chunk))
            self._append(decoder.decode(b"", final=True))
        except (OSError, ValueError):
            pass
        finally:
            code = process.poll()
            if not self._closed:
                self._append(f"\r\n[terminal exited: {code}]\r\n")

    def _raw_write(self, value: str) -> None:
        process = self.process
        if process is None or process.stdin is None or process.poll() is not None:
            raise TerminalError("Terminal process is not running")
        data = value.encode("utf-8")
        with self._write_lock:
            try:
                process.stdin.write(data)
                process.stdin.flush()
            except (BrokenPipeError, OSError) as exc:
                raise TerminalError("Terminal input pipe is closed") from exc

    def send(self, value: str) -> None:
        if not value or "\x00" in value:
            raise TerminalError("Terminal input is empty or invalid")
        if len(value) > self.max_input:
            raise TerminalError(f"Terminal input exceeds {self.max_input} characters")
        self.last_used = time.monotonic()



        self._append(f"$ {value.rstrip()}\r\n")
        suffix = "\r\n" if os.name == "nt" else "\n"
        self._raw_write(value.rstrip("\r\n") + suffix)

    def read(self, cursor: int) -> dict[str, object]:
        self.last_used = time.monotonic()
        with self._lock:
            reset = cursor < self._base_cursor or cursor > self._base_cursor + len(self._buffer)
            if reset:
                cursor = self._base_cursor
            offset = cursor - self._base_cursor
            output = self._buffer[offset:]
            next_cursor = self._base_cursor + len(self._buffer)
        process = self.process
        return {
            "id": self.terminal_id,
            "name": self.name,
            "output": output,
            "cursor": next_cursor,
            "reset": reset,
            "running": bool(process and process.poll() is None),
            "pid": process.pid if process else None,
        }

    def describe(self) -> dict[str, object]:
        process = self.process
        return {
            "id": self.terminal_id,
            "name": self.name,
            "created": self.created,
            "running": bool(process and process.poll() is None),
            "pid": process.pid if process else None,
            "directory": str(self.initial_directory),
        }

    def interrupt(self) -> None:
        self.last_used = time.monotonic()
        self._append("\r\n[interrupt requested; shell will restart]\r\n")
        self._terminate_process_tree()
        self._start()

    def reset(self) -> None:
        self._append("\r\n[shell reset]\r\n")
        self._terminate_process_tree()
        self._start()

    def _terminate_process_tree(self) -> None:
        process = self.process
        if process is None or process.poll() is not None:
            return
        if os.name == "nt":
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                startupinfo=startupinfo,
                creationflags=subprocess.CREATE_NO_WINDOW,
                check=False,
            )
        else:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)
        if self._reader and self._reader is not threading.current_thread():
            self._reader.join(timeout=2)
        for stream in (process.stdin, process.stdout):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass

    def close(self) -> None:
        self._closed = True
        self._terminate_process_tree()


class TerminalManager:
    def __init__(
        self,
        initial_directory: Path,
        *,
        max_buffer: int,
        max_input: int,
        idle_seconds: int,
        max_sessions: int = 8,
    ) -> None:
        self.initial_directory = initial_directory
        self.max_buffer = max_buffer
        self.max_input = max_input
        self.idle_seconds = idle_seconds
        self.max_sessions = max(1, min(int(max_sessions), 16))
        self._sessions: dict[str, dict[str, TerminalSession]] = {}
        self._lock = threading.RLock()

    @staticmethod
    def _validate_id(terminal_id: str | None) -> str:
        value = str(terminal_id or "main")
        if value == "main" or (len(value) == 12 and all(character in "0123456789abcdef" for character in value)):
            return value
        raise TerminalError("Invalid terminal tab identifier")

    @staticmethod
    def _validate_name(name: str | None, fallback: str) -> str:
        value = " ".join(str(name or "").split()).strip()
        if not value:
            value = fallback
        if len(value) > 40 or any(ord(character) < 32 for character in value):
            raise TerminalError("Terminal tab name must be 1 to 40 characters")
        return value

    def _make(self, terminal_id: str, name: str, directory: Path | None = None) -> TerminalSession:
        initial_directory = (directory or self.initial_directory).resolve()
        if not initial_directory.is_dir():
            raise TerminalError("Terminal working directory was not found")
        return TerminalSession(
            initial_directory,
            self.max_buffer,
            self.max_input,
            terminal_id=terminal_id,
            name=name,
        )

    def get(self, sid: str, terminal_id: str | None = None) -> TerminalSession:
        terminal_id = self._validate_id(terminal_id)
        with self._lock:
            self._purge()
            group = self._sessions.setdefault(sid, {})
            session = group.get(terminal_id)
            if session is None:
                if terminal_id != "main":
                    raise TerminalError("Terminal tab was not found")
                if len(group) >= self.max_sessions:
                    raise TerminalError(f"A maximum of {self.max_sessions} terminal tabs is allowed")
                session = self._make("main", "Terminal 1")
                group[terminal_id] = session
            return session

    def create(self, sid: str, name: str | None = None, directory: Path | None = None) -> dict[str, object]:
        with self._lock:
            self._purge()
            group = self._sessions.setdefault(sid, {})
            if len(group) >= self.max_sessions:
                raise TerminalError(f"A maximum of {self.max_sessions} terminal tabs is allowed")
            terminal_id = secrets.token_hex(6)
            while terminal_id in group:
                terminal_id = secrets.token_hex(6)
            label = self._validate_name(name, f"Terminal {len(group) + 1}")
            session = self._make(terminal_id, label, directory)
            group[terminal_id] = session
            return session.describe()

    def list(self, sid: str, *, create_default: bool = True) -> list[dict[str, object]]:
        if create_default:
            self.get(sid, "main")
        with self._lock:
            self._purge()
            return [session.describe() for session in self._sessions.get(sid, {}).values()]

    def rename(self, sid: str, terminal_id: str, name: str) -> dict[str, object]:
        session = self.get(sid, self._validate_id(terminal_id))
        with self._lock:
            session.name = self._validate_name(name, session.name)
            session.last_used = time.monotonic()
            return session.describe()

    def close(self, sid: str, terminal_id: str | None = None) -> bool:
        if terminal_id is None:
            with self._lock:
                group = self._sessions.pop(sid, {})
            sessions = list(group.values())
        else:
            terminal_id = self._validate_id(terminal_id)
            with self._lock:
                group = self._sessions.get(sid, {})
                session = group.pop(terminal_id, None)
                if not group:
                    self._sessions.pop(sid, None)
            sessions = [session] if session else []
        for session in sessions:
            session.close()
        return bool(sessions)

    def close_all(self) -> None:
        with self._lock:
            sessions = [session for group in self._sessions.values() for session in group.values()]
            self._sessions.clear()
        for session in sessions:
            session.close()

    def _purge(self) -> None:
        cutoff = time.monotonic() - self.idle_seconds
        expired: list[TerminalSession] = []
        for sid, group in list(self._sessions.items()):
            for terminal_id, session in list(group.items()):
                if session.last_used < cutoff:
                    expired.append(group.pop(terminal_id))
            if not group:
                self._sessions.pop(sid, None)
        for session in expired:
            session.close()
