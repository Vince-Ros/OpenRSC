from __future__ import annotations

import argparse
import getpass
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import webbrowser
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import launcher
from openrsc.config import ConfigurationError, build_config, load_config, password_record, write_config


PROJECT = Path(__file__).resolve().parent
CONFIG_PATH = PROJECT / "config" / "openrsc.json"
SETTINGS_PATH = PROJECT / "config" / "setup.json"
DATA_PATH = PROJECT / "data"


class SetupError(RuntimeError):
    pass


@dataclass
class SetupSettings:
    port: int = 8787
    tunnel_enabled: bool = True
    hostname: str = ""
    tunnel_name: str = ""
    recovery_enabled: bool = True
    startup_enabled: bool = False
    open_browser: bool = True
    roots: list[str] = field(default_factory=lambda: ["%SystemDrive%\\"] if os.name == "nt" else [str(Path.home())])
    max_terminals: int = 8
    terminal_idle_hours: int = 8
    session_hours: int = 8

    @classmethod
    def from_mapping(cls, value: dict[str, Any]) -> "SetupSettings":
        hosting = value.get("hosting", {})
        reliability = value.get("reliability", {})
        access = value.get("access", {})
        interface = value.get("interface", {})
        return cls(
            port=int(hosting.get("port", 8787)),
            tunnel_enabled=bool(hosting.get("tunnel_enabled", True)),
            hostname=str(hosting.get("hostname", "")),
            tunnel_name=str(hosting.get("tunnel_name", "")),
            recovery_enabled=bool(reliability.get("recovery_enabled", True)),
            startup_enabled=bool(reliability.get("startup_enabled", False)),
            open_browser=bool(interface.get("open_browser", True)),
            roots=[str(item) for item in access.get("roots", [])] or cls().roots,
            max_terminals=int(access.get("max_terminals", 8)),
            terminal_idle_hours=int(access.get("terminal_idle_hours", 8)),
            session_hours=int(access.get("session_hours", 8)),
        )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "version": 1,
            "hosting": {
                "port": self.port,
                "tunnel_enabled": self.tunnel_enabled,
                "hostname": self.hostname,
                "tunnel_name": self.tunnel_name,
            },
            "reliability": {
                "recovery_enabled": self.recovery_enabled,
                "startup_enabled": self.startup_enabled,
            },
            "interface": {"open_browser": self.open_browser},
            "access": {
                "roots": list(self.roots),
                "max_terminals": self.max_terminals,
                "terminal_idle_hours": self.terminal_idle_hours,
                "session_hours": self.session_hours,
            },
        }

    def validate(self, *, require_roots: bool = True) -> "SetupSettings":
        if not 1 <= int(self.port) <= 65535:
            raise SetupError("The local port must be between 1 and 65535.")
        if self.hostname:
            self.hostname = launcher.validate_hostname(self.hostname)
        if self.tunnel_name:
            self.tunnel_name = launcher.sanitize_tunnel_name(self.tunnel_name)
        else:
            self.tunnel_name = launcher.sanitize_tunnel_name(socket.gethostname())
        self.roots = [item.strip() for item in self.roots if item.strip()]
        if not self.roots:
            raise SetupError("Add at least one file root that OpenRSC may access.")
        if require_roots:
            missing = [item for item in self.roots if not Path(os.path.expandvars(item)).expanduser().is_dir()]
            if missing:
                raise SetupError("These file roots were not found: " + ", ".join(missing))
        if not 1 <= int(self.max_terminals) <= 16:
            raise SetupError("Terminal tabs must be between 1 and 16.")
        if not 1 <= int(self.terminal_idle_hours) <= 168:
            raise SetupError("Terminal idle time must be between 1 and 168 hours.")
        if not 1 <= int(self.session_hours) <= 168:
            raise SetupError("Login session time must be between 1 and 168 hours.")
        return self


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(value, indent=2, sort_keys=True) + "\n"
    descriptor, temporary = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def detected_settings(
    *,
    config_path: Path = CONFIG_PATH,
    settings_path: Path = SETTINGS_PATH,
    environment: dict[str, str] | None = None,
) -> SetupSettings:
    if settings_path.is_file():
        try:
            data = json.loads(settings_path.read_text(encoding="utf-8"))
            if int(data.get("version")) != 1:
                raise ValueError("unsupported version")
            return SetupSettings.from_mapping(data).validate(require_roots=False)
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
            raise SetupError(f"Cannot read setup preferences: {exc}") from exc

    settings = SetupSettings()
    if config_path.is_file():
        config = load_config(config_path)
        settings.port = config.port
        settings.roots = list(config.files["roots"])
        settings.max_terminals = int(config.terminal.get("max_sessions", 8))
        settings.terminal_idle_hours = max(1, int(config.terminal.get("idle_seconds", 28_800)) // 3600)
        settings.session_hours = max(1, int(config.security.get("session_ttl_seconds", 28_800)) // 3600)
    tunnel = launcher.load_cloudflare_state(settings.port, repair=False)
    settings.tunnel_enabled = bool(tunnel)
    if tunnel:
        settings.hostname = str(tunnel.get("hostname", ""))
        settings.tunnel_name = str(tunnel.get("tunnel_name", ""))
    try:
        startup = launcher.startup_entry_path(environment)
        settings.startup_enabled = startup.is_file()
        if startup.is_file():
            payload = startup.read_text(encoding="utf-16", errors="replace")
            settings.recovery_enabled = "--supervise" in payload
    except (OSError, launcher.LauncherError):
        settings.startup_enabled = False
    return settings.validate(require_roots=False)


def save_settings(settings: SetupSettings, path: Path = SETTINGS_PATH) -> Path:
    settings.validate(require_roots=False)
    _atomic_json(path, settings.to_mapping())
    return path.resolve()


def apply_openrsc_config(
    settings: SetupSettings,
    *,
    password: str | None = None,
    config_path: Path = CONFIG_PATH,
) -> Path:
    settings.validate()
    if config_path.is_file():
        raw = json.loads(config_path.read_text(encoding="utf-8"))
        raw["listen"] = {"host": "127.0.0.1", "port": int(settings.port)}
        raw.setdefault("files", {})["roots"] = list(settings.roots)
        raw.setdefault("terminal", {})["max_sessions"] = int(settings.max_terminals)
        raw["terminal"]["idle_seconds"] = int(settings.terminal_idle_hours) * 3600
        raw.setdefault("security", {})["session_ttl_seconds"] = int(settings.session_hours) * 3600
        if password is not None:
            raw["security"]["password"] = password_record(password)
    else:
        if password is None:
            raise SetupError("Set an OpenRSC password before saving a fresh configuration.")
        raw = build_config(password, roots=list(settings.roots), port=settings.port)
        raw["terminal"]["max_sessions"] = int(settings.max_terminals)
        raw["terminal"]["idle_seconds"] = int(settings.terminal_idle_hours) * 3600
        raw["security"]["session_ttl_seconds"] = int(settings.session_hours) * 3600
    write_config(config_path, raw)
    load_config(config_path)
    if config_path.resolve() == CONFIG_PATH.resolve():
        launcher.load_cloudflare_state(settings.port)
    return config_path.resolve()


def apply_startup(
    settings: SetupSettings,
    *,
    environment: dict[str, str] | None = None,
    python_executable: Path | None = None,
    project: Path = PROJECT,
    config_path: Path = CONFIG_PATH,
    data_path: Path = DATA_PATH,
) -> Path:
    entry = launcher.startup_entry_path(environment)
    if not settings.startup_enabled:
        entry.unlink(missing_ok=True)
        launcher._record_startup_choice(data_path, False)
        return entry
    payload = launcher.startup_payload(
        project=project,
        python_executable=python_executable,
        config=config_path,
        data=data_path,
        port=settings.port,
        no_tunnel=not settings.tunnel_enabled,
        supervise=settings.recovery_enabled,
    )
    launcher._atomic_write(entry, payload.encode("utf-16"), mode=0o600)
    launcher._record_startup_choice(data_path, True)
    return entry


def apply_all(
    settings: SetupSettings,
    *,
    password: str | None = None,
    settings_path: Path = SETTINGS_PATH,
    config_path: Path = CONFIG_PATH,
    data_path: Path = DATA_PATH,
    environment: dict[str, str] | None = None,
    python_executable: Path | None = None,
) -> dict[str, Path]:
    config = apply_openrsc_config(settings, password=password, config_path=config_path)
    preferences = save_settings(settings, settings_path)
    startup = apply_startup(
        settings,
        environment=environment,
        python_executable=python_executable,
        config_path=config_path,
        data_path=data_path,
    )
    return {"config": config, "settings": preferences, "startup": startup}


def configure_tunnel(
    settings: SetupSettings,
    *,
    reauthenticate: bool = False,
    overwrite_dns: bool = False,
) -> dict[str, Any]:
    if not settings.tunnel_enabled:
        raise SetupError("Enable Cloudflare Tunnel before configuring a public hostname.")
    launcher.ensure_local_cloudflared()
    state = launcher.setup_cloudflare(
        hostname=settings.hostname or None,
        tunnel_name=settings.tunnel_name or None,
        port=settings.port,
        overwrite_dns=overwrite_dns,
        reconfigure=True,
        reauth=reauthenticate,
    )
    settings.hostname = str(state["hostname"])
    settings.tunnel_name = str(state["tunnel_name"])
    save_settings(settings)
    return state


def build_launch_command(settings: SetupSettings, *, python_executable: str | None = None) -> list[str]:
    settings.validate(require_roots=False)
    command = [
        python_executable or sys.executable,
        str((PROJECT / "launcher.py").resolve()),
        "--config",
        str(CONFIG_PATH.resolve()),
        "--data",
        str(DATA_PATH.resolve()),
        "--port",
        str(settings.port),
        "--no-elevate",
        "--no-browser",
        "--no-startup-prompt",
    ]
    if settings.recovery_enabled:
        command.append("--supervise")
    if not settings.tunnel_enabled:
        command.append("--no-tunnel")
    return command


def _read_pid(path: Path) -> int | None:
    try:
        return int(path.read_text(encoding="ascii").strip())
    except (OSError, ValueError):
        return None


def _pid_alive(pid: int | None) -> bool:
    if not pid:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _health(url: str, timeout: float = 2.0) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            return response.status == 200
    except (OSError, urllib.error.URLError):
        return False


def runtime_status(settings: SetupSettings | None = None) -> dict[str, Any]:
    settings = settings or detected_settings()
    supervisor = _read_pid(DATA_PATH / "openrsc-supervisor.pid")
    server = _read_pid(DATA_PATH / "openrsc.pid")
    tunnel_pid = _read_pid(DATA_PATH / "cloudflared.pid")
    tunnel = launcher.load_cloudflare_state(settings.port, repair=False) if settings.tunnel_enabled else None
    public_url = "https://" + str(tunnel["hostname"]) if tunnel else ""
    try:
        startup_path = launcher.startup_entry_path()
        startup_enabled = startup_path.is_file()
    except launcher.LauncherError:
        startup_path = Path("unavailable")
        startup_enabled = False
    return {
        "configured": CONFIG_PATH.is_file(),
        "settings_file": SETTINGS_PATH.is_file(),
        "startup_enabled": startup_enabled,
        "startup_path": str(startup_path),
        "recovery_enabled": settings.recovery_enabled,
        "tunnel_enabled": settings.tunnel_enabled,
        "hostname": str(tunnel["hostname"]) if tunnel else "",
        "supervisor_pid": supervisor,
        "supervisor_running": _pid_alive(supervisor),
        "server_pid": server,
        "server_running": _pid_alive(server),
        "tunnel_pid": tunnel_pid,
        "tunnel_running": _pid_alive(tunnel_pid),
        "local_url": f"http://127.0.0.1:{settings.port}",
        "local_health": _health(f"http://127.0.0.1:{settings.port}/healthz"),
        "public_url": public_url,
        "public_health": _health(public_url + "/healthz", 4.0) if public_url else False,
    }


def format_status(status: dict[str, Any]) -> str:
    mark = lambda value: "OK" if value else "OFF"
    lines = [
        "OpenRSC setup status",
        f"  Configuration       {mark(status['configured'])}",
        f"  Windows startup     {mark(status['startup_enabled'])}",
        f"  Crash/net recovery  {mark(status['recovery_enabled'])}",
        f"  Server process      {mark(status['server_running'])}  PID {status['server_pid'] or '-'}",
        f"  Local health        {mark(status['local_health'])}  {status['local_url']}",
        f"  Cloudflare Tunnel   {mark(status['tunnel_enabled'])}",
        f"  Tunnel process      {mark(status['tunnel_running'])}  PID {status['tunnel_pid'] or '-'}",
    ]
    if status["public_url"]:
        lines.append(f"  Public health       {mark(status['public_health'])}  {status['public_url']}")
    return "\n".join(lines)


def start_openrsc(settings: SetupSettings, *, open_panel: bool | None = None) -> dict[str, Any]:
    settings.validate()
    if not CONFIG_PATH.is_file():
        raise SetupError("Save the setup before starting OpenRSC.")
    current = runtime_status(settings)
    if current["server_running"]:
        return {"started": False, "reason": "already-running", **current}
    if settings.tunnel_enabled and not launcher.load_cloudflare_state(settings.port):
        raise SetupError("Configure Cloudflare Tunnel before starting tunnel hosting.")
    DATA_PATH.mkdir(parents=True, exist_ok=True)
    log_path = DATA_PATH / "logs" / "setup-start.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    creationflags = 0
    startupinfo = None
    if os.name == "nt":
        creationflags = subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = subprocess.SW_HIDE
    with log_path.open("a", encoding="utf-8", buffering=1) as log:
        process = subprocess.Popen(
            build_launch_command(settings),
            cwd=str(PROJECT),
            stdout=log,
            stderr=subprocess.STDOUT,
            creationflags=creationflags,
            startupinfo=startupinfo,
        )
    deadline = time.monotonic() + 25
    local_url = f"http://127.0.0.1:{settings.port}"
    while time.monotonic() < deadline:
        if _health(local_url + "/healthz", 1.0):
            break
        if process.poll() is not None:
            raise SetupError(f"OpenRSC exited with status {process.returncode}. Check {log_path}.")
        time.sleep(0.4)
    else:
        raise SetupError(f"OpenRSC did not become healthy. Check {log_path}.")
    state = launcher.load_cloudflare_state(settings.port) if settings.tunnel_enabled else None
    url = "https://" + str(state["hostname"]) if state else local_url
    if settings.open_browser if open_panel is None else bool(open_panel):
        webbrowser.open(url)
    return {"started": True, "launcher_pid": process.pid, "url": url, **runtime_status(settings)}


def stop_openrsc() -> dict[str, Any]:
    output = ""
    script = PROJECT / "stop-openrsc.ps1"
    if os.name == "nt" and script.is_file():
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script)],
            cwd=str(PROJECT),
            capture_output=True,
            text=True,
            check=False,
        )
        output = (result.stdout + result.stderr).strip()


        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            supervisor_pid = _read_pid(DATA_PATH / "openrsc-supervisor.pid")
            server_pid = _read_pid(DATA_PATH / "openrsc.pid")
            if not _pid_alive(supervisor_pid) and not _pid_alive(server_pid):
                break
            time.sleep(0.25)
        tunnel_pid = _read_pid(DATA_PATH / "cloudflared.pid")
        if _pid_alive(tunnel_pid):
            subprocess.run(["taskkill.exe", "/PID", str(tunnel_pid), "/T", "/F"], capture_output=True, check=False)
    else:
        for name in ("openrsc-supervisor.pid", "openrsc.pid", "cloudflared.pid"):
            pid = _read_pid(DATA_PATH / name)
            if _pid_alive(pid):
                try:
                    os.kill(int(pid), 15)
                except OSError:
                    pass
    for name in ("openrsc-supervisor.pid", "openrsc.pid", "cloudflared.pid"):
        path = DATA_PATH / name
        if not _pid_alive(_read_pid(path)):
            path.unlink(missing_ok=True)
    status = runtime_status()
    return {"stopped": not status["server_running"] and not status["supervisor_running"], "output": output, **status}


def _prompt_password() -> str:
    first = getpass.getpass("New OpenRSC password (12+ characters): ")
    second = getpass.getpass("Repeat password: ")
    if first != second:
        raise SetupError("The passwords did not match.")
    password_record(first)
    return first


def run_gui() -> int:
    try:
        import tkinter as tk
        from tkinter import messagebox, simpledialog, ttk
    except ImportError as exc:
        raise SetupError("Tkinter is unavailable. Use setup_openrsc.py --status or --apply.") from exc

    settings = detected_settings()
    root = tk.Tk()
    root.title("OpenRSC Setup")
    root.geometry("820x700")
    root.minsize(720, 620)
    root.configure(bg="#090909")
    style = ttk.Style(root)
    style.theme_use("clam")
    style.configure(".", background="#090909", foreground="#e8e8e8", fieldbackground="#111111")
    style.configure("TFrame", background="#090909")
    style.configure("Card.TLabelframe", background="#0e0e0e", bordercolor="#292929", relief="solid")
    style.configure("Card.TLabelframe.Label", background="#090909", foreground="#7ddbc2", font=("Segoe UI", 10, "bold"))
    style.configure("TLabel", background="#090909", foreground="#d8d8d8", font=("Segoe UI", 10))
    style.configure("Muted.TLabel", foreground="#8b8b8b")
    style.configure("TCheckbutton", background="#0e0e0e", foreground="#e5e5e5", font=("Segoe UI", 10))
    style.configure("TEntry", fieldbackground="#111111", foreground="#f2f2f2", bordercolor="#333333", insertcolor="#7ddbc2")
    style.configure("TButton", background="#181818", foreground="#f0f0f0", bordercolor="#333333", padding=(12, 8))
    style.map("TButton", foreground=[("active", "#7ddbc2")], background=[("active", "#181818")])
    style.configure("Accent.TButton", background="#10a37f", foreground="#ffffff", bordercolor="#10a37f")
    style.map("Accent.TButton", background=[("active", "#10a37f")], foreground=[("active", "#ffffff")])

    canvas = tk.Canvas(root, bg="#090909", highlightthickness=0)
    scroll = ttk.Scrollbar(root, orient="vertical", command=canvas.yview)
    body = ttk.Frame(canvas, padding=22)
    body_id = canvas.create_window((0, 0), window=body, anchor="nw")
    canvas.configure(yscrollcommand=scroll.set)
    canvas.pack(side="left", fill="both", expand=True)
    scroll.pack(side="right", fill="y")
    body.bind("<Configure>", lambda _event: canvas.configure(scrollregion=canvas.bbox("all")))
    canvas.bind("<Configure>", lambda event: canvas.itemconfigure(body_id, width=event.width))

    ttk.Label(body, text="OpenRSC Setup", font=("Segoe UI", 22, "bold")).pack(anchor="w")
    ttk.Label(body, text="Hosting, recovery, startup, access, and health in one place.", style="Muted.TLabel").pack(anchor="w", pady=(2, 18))

    port = tk.StringVar(value=str(settings.port))
    tunnel = tk.BooleanVar(value=settings.tunnel_enabled)
    hostname = tk.StringVar(value=settings.hostname)
    tunnel_name = tk.StringVar(value=settings.tunnel_name)
    recovery = tk.BooleanVar(value=settings.recovery_enabled)
    startup = tk.BooleanVar(value=settings.startup_enabled)
    browser = tk.BooleanVar(value=settings.open_browser)
    terminals = tk.StringVar(value=str(settings.max_terminals))
    idle = tk.StringVar(value=str(settings.terminal_idle_hours))
    session = tk.StringVar(value=str(settings.session_hours))
    pending_password: dict[str, str | None] = {"value": None}

    def section(title: str) -> ttk.LabelFrame:
        frame = ttk.LabelFrame(body, text=title, style="Card.TLabelframe", padding=16)
        frame.pack(fill="x", pady=(0, 12))
        frame.columnconfigure(1, weight=1)
        return frame

    hosting = section("Hosting")
    ttk.Checkbutton(hosting, text="Host through Cloudflare Tunnel", variable=tunnel).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 10))
    ttk.Label(hosting, text="Local port").grid(row=1, column=0, sticky="w", padx=(0, 12), pady=5)
    ttk.Entry(hosting, textvariable=port, width=14).grid(row=1, column=1, sticky="ew", pady=5)
    ttk.Label(hosting, text="Public hostname").grid(row=2, column=0, sticky="w", padx=(0, 12), pady=5)
    ttk.Entry(hosting, textvariable=hostname).grid(row=2, column=1, sticky="ew", pady=5)
    ttk.Label(hosting, text="Tunnel name").grid(row=3, column=0, sticky="w", padx=(0, 12), pady=5)
    ttk.Entry(hosting, textvariable=tunnel_name).grid(row=3, column=1, sticky="ew", pady=5)

    reliability = section("Reliability")
    ttk.Checkbutton(reliability, text="Restart the server and tunnel after crashes or network outages", variable=recovery).pack(anchor="w", pady=4)
    ttk.Checkbutton(reliability, text="Start OpenRSC automatically when I sign in to Windows", variable=startup).pack(anchor="w", pady=4)
    ttk.Checkbutton(reliability, text="Open the control panel after a manual start", variable=browser).pack(anchor="w", pady=4)

    access = section("Access and limits")
    ttk.Label(access, text="Allowed file roots (one per line)").grid(row=0, column=0, columnspan=2, sticky="w")
    roots = tk.Text(access, height=4, bg="#111111", fg="#eeeeee", insertbackground="#7ddbc2", relief="solid", bd=1, highlightthickness=0)
    roots.insert("1.0", "\n".join(settings.roots))
    roots.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(5, 10))
    ttk.Label(access, text="Maximum terminal tabs").grid(row=2, column=0, sticky="w", pady=5)
    ttk.Entry(access, textvariable=terminals, width=12).grid(row=2, column=1, sticky="ew", pady=5)
    ttk.Label(access, text="Terminal idle timeout (hours)").grid(row=3, column=0, sticky="w", pady=5)
    ttk.Entry(access, textvariable=idle, width=12).grid(row=3, column=1, sticky="ew", pady=5)
    ttk.Label(access, text="Login session duration (hours)").grid(row=4, column=0, sticky="w", pady=5)
    ttk.Entry(access, textvariable=session, width=12).grid(row=4, column=1, sticky="ew", pady=5)

    status_box = tk.Text(body, height=10, bg="#070707", fg="#b9c7c3", relief="solid", bd=1, font=("Consolas", 9), state="disabled")
    status_box.pack(fill="x", pady=(0, 12))

    def collect() -> SetupSettings:
        return SetupSettings(
            port=int(port.get()),
            tunnel_enabled=tunnel.get(),
            hostname=hostname.get().strip(),
            tunnel_name=tunnel_name.get().strip(),
            recovery_enabled=recovery.get(),
            startup_enabled=startup.get(),
            open_browser=browser.get(),
            roots=[item.strip() for item in roots.get("1.0", "end").splitlines() if item.strip()],
            max_terminals=int(terminals.get()),
            terminal_idle_hours=int(idle.get()),
            session_hours=int(session.get()),
        ).validate()

    def show_status(text: str) -> None:
        status_box.configure(state="normal")
        status_box.delete("1.0", "end")
        status_box.insert("1.0", text)
        status_box.configure(state="disabled")

    def refresh_status() -> None:
        try:
            show_status(format_status(runtime_status(collect())))
        except Exception as exc:
            show_status("Status error: " + str(exc))

    def choose_password() -> None:
        first = simpledialog.askstring("OpenRSC password", "New password (12+ characters):", show="*", parent=root)
        if first is None:
            return
        second = simpledialog.askstring("OpenRSC password", "Repeat the password:", show="*", parent=root)
        if first != second:
            messagebox.showerror("Password", "The passwords did not match.", parent=root)
            return
        try:
            password_record(first)
        except ConfigurationError as exc:
            messagebox.showerror("Password", str(exc), parent=root)
            return
        pending_password["value"] = first
        messagebox.showinfo("Password", "The new password will be applied when you save.", parent=root)

    def save_action(*, quiet: bool = False) -> SetupSettings | None:
        try:
            chosen = collect()
            if not CONFIG_PATH.is_file() and pending_password["value"] is None:
                choose_password()
                if pending_password["value"] is None:
                    return None
            apply_all(chosen, password=pending_password["value"])
            pending_password["value"] = None
            if not quiet:
                messagebox.showinfo("OpenRSC Setup", "Configuration saved.", parent=root)
            refresh_status()
            return chosen
        except Exception as exc:
            messagebox.showerror("OpenRSC Setup", str(exc), parent=root)
            return None

    def run_background(label: str, function) -> None:
        show_status(label + "…")
        def worker() -> None:
            try:
                result = function()
                message = result if isinstance(result, str) else json.dumps(result, indent=2, default=str)
                root.after(0, lambda: show_status(message))
            except Exception as exc:
                root.after(0, lambda: messagebox.showerror("OpenRSC Setup", str(exc), parent=root))
                root.after(0, refresh_status)
        threading.Thread(target=worker, daemon=True).start()

    def tunnel_action() -> None:
        chosen = save_action(quiet=True)
        if chosen is None:
            return
        reauth = messagebox.askyesno("Cloudflare", "Authenticate and select a Cloudflare zone again?", parent=root)
        overwrite = messagebox.askyesno("Cloudflare", "Replace an existing DNS record if this hostname already exists?", parent=root)
        run_background(
            "Configuring Cloudflare Tunnel",
            lambda: "Cloudflare connected: https://" + str(configure_tunnel(chosen, reauthenticate=reauth, overwrite_dns=overwrite)["hostname"]),
        )

    def start_action() -> None:
        chosen = save_action(quiet=True)
        if chosen is not None:
            def start_message() -> str:
                result = start_openrsc(chosen)
                url = result.get("url") or result.get("public_url") or result["local_url"]
                state = "already running" if result.get("reason") == "already-running" else "started"
                return f"OpenRSC {state}: {url}"

            run_background("Starting OpenRSC", start_message)

    def stop_action() -> None:
        run_background("Stopping OpenRSC", lambda: format_status(stop_openrsc()))

    actions = ttk.Frame(body)
    actions.pack(fill="x", pady=(0, 18))
    ttk.Button(actions, text="Save configuration", style="Accent.TButton", command=save_action).pack(side="left", padx=(0, 8))
    ttk.Button(actions, text="Configure Cloudflare", command=tunnel_action).pack(side="left", padx=(0, 8))
    ttk.Button(actions, text="Change password", command=choose_password).pack(side="left", padx=(0, 8))
    ttk.Button(actions, text="Start", command=start_action).pack(side="left", padx=(0, 8))
    ttk.Button(actions, text="Stop", command=stop_action).pack(side="left", padx=(0, 8))
    ttk.Button(actions, text="Check status", command=refresh_status).pack(side="left")

    refresh_status()
    root.mainloop()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Configure, verify, start, and stop OpenRSC")
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument("--status", action="store_true", help="print configuration and runtime status")
    actions.add_argument("--apply", action="store_true", help="save supplied settings without opening the GUI")
    actions.add_argument("--start", action="store_true", help="start the saved OpenRSC configuration")
    actions.add_argument("--stop", action="store_true", help="stop the OpenRSC process tree")
    actions.add_argument("--configure-tunnel", action="store_true", help="configure the Cloudflare named tunnel")
    actions.add_argument("--save-detected", action="store_true", help="write preferences detected from the current installation")
    parser.add_argument("--port", type=int)
    parser.add_argument("--tunnel", choices=("on", "off"))
    parser.add_argument("--hostname")
    parser.add_argument("--tunnel-name")
    parser.add_argument("--recovery", choices=("on", "off"))
    parser.add_argument("--startup", choices=("on", "off"))
    parser.add_argument("--open-browser", choices=("on", "off"))
    parser.add_argument("--root", action="append", dest="roots")
    parser.add_argument("--max-terminals", type=int)
    parser.add_argument("--terminal-idle-hours", type=int)
    parser.add_argument("--session-hours", type=int)
    parser.add_argument("--set-password", action="store_true", help="prompt securely for a new panel password")
    parser.add_argument("--reauth-cloudflare", action="store_true")
    parser.add_argument("--overwrite-dns", action="store_true")
    return parser


def _apply_overrides(settings: SetupSettings, args: argparse.Namespace) -> SetupSettings:
    for name in ("port", "hostname", "tunnel_name", "max_terminals", "terminal_idle_hours", "session_hours"):
        value = getattr(args, name)
        if value is not None:
            setattr(settings, name, value)
    if args.roots is not None:
        settings.roots = list(args.roots)
    for argument, attribute in (
        ("tunnel", "tunnel_enabled"),
        ("recovery", "recovery_enabled"),
        ("startup", "startup_enabled"),
        ("open_browser", "open_browser"),
    ):
        value = getattr(args, argument)
        if value is not None:
            setattr(settings, attribute, value == "on")
    return settings.validate()


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if not any((args.status, args.apply, args.start, args.stop, args.configure_tunnel, args.save_detected)):
            return run_gui()
        settings = detected_settings()
        settings = _apply_overrides(settings, args)
        password = _prompt_password() if args.set_password else None
        if args.status:
            print(format_status(runtime_status(settings)))
            return 0
        if args.save_detected:
            print("SETUP_SETTINGS=%s" % save_settings(settings))
            return 0
        if args.apply:
            result = apply_all(settings, password=password)
            print("SETUP_RESULT=APPLIED config=%s settings=%s startup=%s" % (result["config"], result["settings"], result["startup"]))
            return 0
        if args.configure_tunnel:
            apply_all(settings, password=password)
            state = configure_tunnel(settings, reauthenticate=args.reauth_cloudflare, overwrite_dns=args.overwrite_dns)
            print("TUNNEL_RESULT=CONFIGURED url=https://%s" % state["hostname"])
            return 0
        if args.start:
            result = start_openrsc(settings)
            print("START_RESULT=%s url=%s" % ("STARTED" if result["started"] else "ALREADY_RUNNING", result.get("url") or result["local_url"]))
            return 0
        if args.stop:
            result = stop_openrsc()
            print("STOP_RESULT=%s" % ("STOPPED" if result["stopped"] else "STILL_RUNNING"))
            if result["output"]:
                print(result["output"])
            return 0 if result["stopped"] else 2
        return 0
    except (SetupError, ConfigurationError, launcher.LauncherError, OSError, ValueError) as exc:
        print("SETUP_ERROR: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
