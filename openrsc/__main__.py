from __future__ import annotations

import argparse
import logging
import logging.handlers
import os
import shutil
import subprocess
import threading
import time
from pathlib import Path

from . import __version__
from .config import ConfigurationError, load_config
from .server import create_server, is_administrator


def _project_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _logging(data_dir: Path, verbose: bool) -> None:
    log_dir = data_dir / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    root = logging.getLogger()
    root.setLevel(logging.DEBUG if verbose else logging.INFO)
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    console = logging.StreamHandler()
    console.setFormatter(formatter)
    root.addHandler(console)
    rotating = logging.handlers.RotatingFileHandler(
        log_dir / "openrsc.log", maxBytes=5 * 1024 * 1024, backupCount=4, encoding="utf-8"
    )
    rotating.setFormatter(formatter)
    root.addHandler(rotating)


def _stream_process(process: subprocess.Popen[str], logger: logging.Logger) -> None:
    if process.stdout is None:
        return
    for line in process.stdout:
        logger.info("%s", line.rstrip())


def _start_tunnel(
    port: int,
    token_file: Path | None = None,
    *,
    executable_path: Path | None = None,
    config_file: Path | None = None,
    tunnel_id: str | None = None,
) -> subprocess.Popen[str]:
    executable = str(executable_path.resolve()) if executable_path else shutil.which("cloudflared")
    if not executable or not Path(executable).is_file():
        raise RuntimeError("cloudflared was not found in PATH")
    if config_file is not None:
        config_file = config_file.resolve()
        if not config_file.is_file():
            raise RuntimeError(f"Tunnel configuration file not found: {config_file}")
        command = [
            executable,
            "tunnel",
            "--no-autoupdate",
            "--config",
            str(config_file),
            "run",
        ]
        if tunnel_id:
            command.append(tunnel_id)
    elif token_file is None:
        command = [executable, "tunnel", "--no-autoupdate", "--url", f"http://127.0.0.1:{port}"]
    else:
        token_file = token_file.resolve()
        if not token_file.is_file():
            raise RuntimeError(f"Tunnel token file not found: {token_file}")
        command = [executable, "tunnel", "--no-autoupdate", "run", "--token-file", str(token_file)]
    startupinfo = None
    creationflags = 0
    if os.name == "nt":
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = subprocess.SW_HIDE
        creationflags = subprocess.CREATE_NO_WINDOW
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        startupinfo=startupinfo,
        creationflags=creationflags,
    )
    threading.Thread(
        target=_stream_process, args=(process, logging.getLogger("openrsc.cloudflared")), daemon=True
    ).start()
    return process


class TunnelSupervisor:
    """Keep the Cloudflare connector alive without restarting the local server."""

    def __init__(
        self,
        starter,
        *,
        logger: logging.Logger | None = None,
        check_interval: float = 2.0,
        minimum_backoff: float = 2.0,
        maximum_backoff: float = 30.0,
        pid_path: Path | None = None,
    ) -> None:
        self._starter = starter
        self._logger = logger or logging.getLogger("openrsc.cloudflared")
        self._check_interval = float(check_interval)
        self._minimum_backoff = float(minimum_backoff)
        self._maximum_backoff = float(maximum_backoff)
        self._pid_path = None if pid_path is None else pid_path.resolve()
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._process: subprocess.Popen[str] | None = None
        self._thread: threading.Thread | None = None

    @property
    def process(self) -> subprocess.Popen[str] | None:
        with self._lock:
            return self._process

    def start(self) -> subprocess.Popen[str]:
        process = self._starter()
        with self._lock:
            self._process = process
        self._record_pid(process)
        self._thread = threading.Thread(target=self._monitor, name="openrsc-tunnel-supervisor", daemon=True)
        self._thread.start()
        return process

    def _record_pid(self, process: subprocess.Popen[str]) -> None:
        if self._pid_path is None:
            return
        self._pid_path.parent.mkdir(parents=True, exist_ok=True)
        self._pid_path.write_text(str(process.pid) + "\n", encoding="ascii")

    def _monitor(self) -> None:
        delay = self._minimum_backoff
        started_at = time.monotonic()
        while not self._stop.wait(self._check_interval):
            process = self.process
            if process is not None and process.poll() is None:
                if time.monotonic() - started_at >= 60.0:
                    delay = self._minimum_backoff
                continue
            exit_code = None if process is None else process.poll()
            self._logger.warning("cloudflared exited with status %s; restarting in %.1f seconds", exit_code, delay)
            if self._stop.wait(delay):
                return
            try:
                replacement = self._starter()
            except (OSError, RuntimeError) as exc:
                self._logger.error("cloudflared restart failed: %s", exc)
                delay = min(self._maximum_backoff, max(self._minimum_backoff, delay * 2))
                continue
            with self._lock:
                self._process = replacement
            self._record_pid(replacement)
            started_at = time.monotonic()
            self._logger.info("cloudflared restarted with PID %s", replacement.pid)
            delay = min(self._maximum_backoff, max(self._minimum_backoff, delay * 2))

    def stop(self) -> None:
        self._stop.set()
        process = self.process
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        if self._thread is not None:
            self._thread.join(timeout=max(5.0, self._check_interval * 2))
        if self._pid_path is not None:
            try:
                if process is None or self._pid_path.read_text(encoding="ascii").strip() == str(process.pid):
                    self._pid_path.unlink()
            except OSError:
                pass


def build_parser() -> argparse.ArgumentParser:
    root = _project_root()
    parser = argparse.ArgumentParser(description="OpenRSC secure remote control centre")
    parser.add_argument("--config", type=Path, default=root / "config" / "openrsc.json")
    parser.add_argument("--data", type=Path, default=root / "data")
    parser.add_argument("--host", help="listen address override")
    parser.add_argument("--port", type=int, help="listen port override")
    parser.add_argument("--allow-network", action="store_true", help="allow a non-loopback listen address")
    parser.add_argument("--tunnel", action="store_true", help="start a cloudflared quick tunnel alongside OpenRSC")
    parser.add_argument("--tunnel-token-file", type=Path, help="run a remotely managed cloudflared tunnel from a token file")
    parser.add_argument("--cloudflared-executable", type=Path, help="explicit cloudflared executable path")
    parser.add_argument("--cloudflared-config", type=Path, help="run a locally managed tunnel from this config file")
    parser.add_argument("--cloudflared-tunnel-id", help="tunnel UUID/name used with --cloudflared-config")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--version", action="version", version=f"OpenRSC {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    data_dir = args.data.resolve()
    _logging(data_dir, args.verbose)
    log = logging.getLogger("openrsc")
    try:
        config = load_config(args.config)
    except ConfigurationError as exc:
        log.error("%s", exc)
        log.error("Create it with: python scripts/configure_password.py")
        return 2
    host = args.host or config.host
    port = args.port if args.port is not None else config.port
    loopback_names = {"127.0.0.1", "::1", "localhost"}
    if host not in loopback_names and not args.allow_network:
        log.error("Refusing a non-loopback bind without --allow-network")
        return 2
    modes = int(args.tunnel) + int(args.tunnel_token_file is not None) + int(args.cloudflared_config is not None)
    if modes > 1:
        log.error("Choose one tunnel mode: --tunnel, --tunnel-token-file, or --cloudflared-config")
        return 2
    if args.cloudflared_tunnel_id and not args.cloudflared_config:
        log.error("--cloudflared-tunnel-id requires --cloudflared-config")
        return 2
    if modes and host not in loopback_names:
        log.error("The built-in cloudflared mode requires a loopback listen address")
        return 2

    try:
        server = create_server(config, data_dir, host=host, port=port)
    except OSError as exc:
        log.error("Cannot listen on %s:%s: %s", host, port, exc)
        return 3
    actual_port = int(server.server_address[1])
    pid_path = data_dir / "openrsc.pid"
    pid_path.write_text(str(os.getpid()) + "\n", encoding="ascii")
    tunnel: TunnelSupervisor | None = None
    try:
        if modes:
            tunnel = TunnelSupervisor(
                lambda: _start_tunnel(
                    actual_port,
                    args.tunnel_token_file,
                    executable_path=args.cloudflared_executable,
                    config_file=args.cloudflared_config,
                    tunnel_id=args.cloudflared_tunnel_id,
                ),
                logger=logging.getLogger("openrsc.cloudflared"),
                pid_path=data_dir / "cloudflared.pid",
            )
            tunnel.start()
        log.info("OpenRSC %s listening at http://%s:%s", __version__, host, actual_port)
        log.info("Administrator token: %s", "active" if is_administrator() else "not elevated")
        log.info("Configured roots: %s", ", ".join(str(root) for root in server.app.files.roots))
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        log.info("Shutdown requested")
    except RuntimeError as exc:
        log.error("%s", exc)
        return 4
    finally:
        server.server_close()
        if tunnel:
            tunnel.stop()
        try:
            if pid_path.read_text(encoding="ascii").strip() == str(os.getpid()):
                pid_path.unlink()
        except OSError:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
