from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any


class AIIntegrationError(RuntimeError):
    pass


class AIIntegration:
    """Discover and launch the locally installed Claude and Codex clients."""

    TERMINAL_PROVIDERS = {"claude-cli", "claude-remote", "codex-cli"}
    PROVIDERS = TERMINAL_PROVIDERS | {"codex-app"}

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._cached_status: dict[str, Any] | None = None
        self._cached_at = 0.0

    @staticmethod
    def _startup_options() -> dict[str, Any]:
        if os.name != "nt":
            return {"start_new_session": True}
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = subprocess.SW_HIDE
        return {"startupinfo": startupinfo, "creationflags": subprocess.CREATE_NO_WINDOW}

    @staticmethod
    def _executable(name: str) -> str | None:
        return shutil.which(name)

    def _run(self, command: list[str], timeout: float = 8.0) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
            **self._startup_options(),
        )

    def _provider_status(self, name: str) -> dict[str, Any]:
        executable = self._executable(name)
        if not executable:
            return {"installed": False, "version": "Not installed", "authenticated": False, "account": "Unavailable"}
        try:
            version_result = self._run([executable, "--version"])
            version = (version_result.stdout or version_result.stderr).strip().splitlines()[0]
        except (OSError, subprocess.TimeoutExpired, IndexError):
            version = "Installed"
        authenticated = False
        account = "Sign-in required"
        try:
            if name == "claude":
                result = self._run([executable, "auth", "status", "--json"])
                details = json.loads(result.stdout) if result.returncode == 0 else {}
                authenticated = bool(details.get("loggedIn"))
                account = "Claude account connected" if authenticated else "Sign-in required"
            else:
                result = self._run([executable, "login", "status"])
                authenticated = result.returncode == 0
                account = (result.stdout or result.stderr).strip().splitlines()[0] if authenticated else "Sign-in required"
        except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError, IndexError):
            pass
        return {"installed": True, "version": version, "authenticated": authenticated, "account": account}

    def status(self, *, refresh: bool = False) -> dict[str, Any]:
        with self._lock:
            now = time.monotonic()
            if not refresh and self._cached_status is not None and now - self._cached_at < 20.0:
                return self._cached_status
            result = {
                "claude": self._provider_status("claude"),
                "codex": self._provider_status("codex"),
            }
            self._cached_status = result
            self._cached_at = now
            return result

    def terminal_spec(self, provider: str, directory: Path) -> tuple[str, list[str]]:
        if provider not in self.TERMINAL_PROVIDERS:
            raise AIIntegrationError("Unknown AI session type")
        directory = directory.resolve()
        if provider == "claude-remote":
            executable = self._executable("claude")
            if not executable:
                raise AIIntegrationError("Claude CLI is not installed")
            return "Claude Remote", [executable, "--remote-control", f"OpenRSC - {directory.name or 'workspace'}"]
        cli_name = "claude" if provider == "claude-cli" else "codex"
        if not self._executable(cli_name):
            raise AIIntegrationError(f"{cli_name.title()} CLI is not installed")
        bridge = Path(__file__).with_name("ai_cli.py").resolve()
        label = "Claude CLI" if provider == "claude-cli" else "Codex CLI"
        return label, [sys.executable, str(bridge), "--provider", cli_name, "--directory", str(directory)]

    @staticmethod
    def shell_command(arguments: list[str]) -> str:
        if not arguments or any("\x00" in value for value in arguments):
            raise AIIntegrationError("Invalid AI launch command")
        if os.name == "nt":
            command = subprocess.list2cmdline(arguments)
            if Path(arguments[0]).suffix.lower() in {".bat", ".cmd"}:
                command = "call " + command
            return command
        return shlex.join(arguments)

    def open_codex_app(self, directory: Path) -> int:
        executable = self._executable("codex")
        if not executable:
            raise AIIntegrationError("Codex is not installed")
        try:
            process = subprocess.Popen(
                [executable, "app", str(directory.resolve())],
                cwd=directory,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                **self._startup_options(),
            )
        except OSError as exc:
            raise AIIntegrationError(f"Could not open the Codex app: {exc}") from exc
        return int(process.pid)
