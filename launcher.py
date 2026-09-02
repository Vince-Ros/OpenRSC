
"""OpenRSC bootstrapper and project-local Cloudflare Tunnel manager.

The launcher intentionally keeps every Cloudflare artifact under ``cloudflare``
in this source tree.  In particular, cloudflared receives an isolated HOME and
USERPROFILE while authenticating, so it never reads or writes the operator's
normal ``~/.cloudflared`` directory.
"""

from __future__ import print_function

import argparse
import base64
import getpass
import hashlib
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import uuid
import webbrowser
from pathlib import Path


MINIMUM_PYTHON = (3, 11)
PYTHON_WINGET_ID = "Python.Python.3.14"
CLOUDFLARED_RELEASE_API = "https://api.github.com/repos/cloudflare/cloudflared/releases/latest"
USER_AGENT = "OpenRSC-launcher/1.1 (+https://github.com/cloudflare/cloudflared)"
PROJECT = Path(__file__).resolve().parent
CLOUDFLARE = PROJECT / "cloudflare"
CLOUDFLARED = CLOUDFLARE / "bin" / ("cloudflared.exe" if os.name == "nt" else "cloudflared")
CERT_FILE = CLOUDFLARE / "cert.pem"
CONFIG_FILE = CLOUDFLARE / "config.yml"
STATE_FILE = CLOUDFLARE / "state.json"
RELEASE_FILE = CLOUDFLARE / "bin" / "release.json"
PROFILE_DIR = CLOUDFLARE / "profile"
CREDENTIALS_DIR = CLOUDFLARE / "credentials"
STARTUP_ENTRY_NAME = "OpenRSC.vbs"
STARTUP_CHOICE_NAME = "startup-choice.json"
INTERNET_PROBE_URL = "https://www.cloudflare.com/cdn-cgi/trace"


class LauncherError(RuntimeError):
    pass


def _hidden_subprocess_kwargs():
    """Keep non-interactive Windows helper processes from opening consoles."""
    if os.name != "nt":
        return {}
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startupinfo.wShowWindow = subprocess.SW_HIDE
    return {
        "startupinfo": startupinfo,
        "creationflags": subprocess.CREATE_NO_WINDOW,
    }


class RecoveryTracker:
    """Turn health observations into rate-limited supervisor actions."""

    def __init__(self, failure_limit=3, recovery_grace=20.0, restart_cooldown=300.0):
        self.failure_limit = int(failure_limit)
        self.recovery_grace = float(recovery_grace)
        self.restart_cooldown = float(restart_cooldown)
        self.local_failures = 0
        self.public_failures = 0
        self.internet_down = False
        self.recovery_until = 0.0
        self.cooldown_until = 0.0

    def observe(self, *, local_ok, public_ok=None, internet_ok=None, now=None):
        now = time.monotonic() if now is None else float(now)
        if local_ok:
            self.local_failures = 0
        else:
            self.local_failures += 1
            if self.local_failures >= self.failure_limit:
                self.local_failures = 0
                return "restart-local"
            return "local-retry"

        if public_ok is None:
            return "healthy"
        if public_ok:
            self.public_failures = 0
            self.internet_down = False
            self.recovery_until = 0.0
            return "healthy"
        if internet_ok is False:
            self.public_failures = 0
            self.internet_down = True
            self.recovery_until = 0.0
            return "offline"
        if self.internet_down:
            self.internet_down = False
            self.public_failures = 0
            self.recovery_until = now + self.recovery_grace
            return "network-restored"
        if now < self.recovery_until:
            return "recovery-grace"
        self.public_failures += 1
        if self.public_failures >= self.failure_limit:
            self.public_failures = 0
            if now < self.cooldown_until:
                return "cooldown"
            self.cooldown_until = now + self.restart_cooldown
            return "restart-public"
        return "public-retry"


def _atomic_write(path, payload, mode=0o600):
    path = Path(path).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, str(path))
        os.chmod(str(path), mode)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _atomic_json(path, value):
    payload = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    _atomic_write(path, payload)


def _sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _powershell_literal(value):
    return "'" + str(value).replace("'", "''") + "'"


def _is_administrator():
    if os.name != "nt":
        return os.geteuid() == 0
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def startup_entry_path(environment=None):
    environment = os.environ if environment is None else environment
    appdata = environment.get("APPDATA")
    if not appdata:
        raise LauncherError("APPDATA is unavailable; the Windows Startup folder cannot be located")
    return (
        Path(appdata)
        / "Microsoft"
        / "Windows"
        / "Start Menu"
        / "Programs"
        / "Startup"
        / STARTUP_ENTRY_NAME
    )


def _startup_pythonw(python_executable=None):
    executable = Path(python_executable or sys.executable).resolve()
    if executable.name.casefold() in {"python.exe", "python_d.exe"}:
        candidate = executable.with_name(executable.name.replace("python", "pythonw", 1))
        if python_executable is not None or candidate.is_file():
            return candidate
    return executable


def startup_payload(
    *,
    project=PROJECT,
    python_executable=None,
    config=None,
    data=None,
    port=8787,
    no_tunnel=False,
    supervise=True,
):
    project = Path(project).resolve()
    command = [
        str(_startup_pythonw(python_executable)),
        str((project / "launcher.py").resolve()),
        "--no-elevate",
        "--no-browser",
        "--no-startup-prompt",
        "--config",
        str(Path(config or project / "config" / "openrsc.json").resolve()),
        "--data",
        str(Path(data or project / "data").resolve()),
        "--port",
        str(int(port)),
    ]
    if supervise:
        command.append("--supervise")
    if no_tunnel:
        command.append("--no-tunnel")
    command_line = subprocess.list2cmdline(command).replace('"', '""')
    working_directory = str(project).replace('"', '""')
    return (
        'Set shell = CreateObject("WScript.Shell")\r\n'
        'shell.CurrentDirectory = "' + working_directory + '"\r\n'
        'shell.Run "' + command_line + '", 0, False\r\n'
    )


def _startup_choice_path(data):
    return Path(data).resolve() / STARTUP_CHOICE_NAME


def _record_startup_choice(data, enabled):
    _atomic_json(
        _startup_choice_path(data),
        {"asked": True, "enabled": bool(enabled), "version": 1},
    )


def install_startup(args, *, environment=None, python_executable=None):
    if os.name != "nt" and environment is None:
        raise LauncherError("Windows startup registration is available only on Windows")
    entry = startup_entry_path(environment)
    payload = startup_payload(
        python_executable=python_executable,
        config=args.config,
        data=args.data,
        port=args.port,
        no_tunnel=args.no_tunnel,
    )


    _atomic_write(entry, payload.encode("utf-16"), mode=0o600)
    _record_startup_choice(args.data, True)
    return entry


def remove_startup(args, *, environment=None):
    if os.name != "nt" and environment is None:
        raise LauncherError("Windows startup registration is available only on Windows")
    entry = startup_entry_path(environment)
    entry.unlink(missing_ok=True)
    _record_startup_choice(args.data, False)
    return entry


def maybe_prompt_startup(args, *, input_function=input, is_tty=None):
    if os.name != "nt" or args.no_startup_prompt or args.supervise:
        return None
    if args.check_only or args.install_only:
        return None
    is_tty = sys.stdin.isatty() if is_tty is None else bool(is_tty)
    if not is_tty:
        return None
    entry = startup_entry_path()
    if entry.is_file() or _startup_choice_path(args.data).is_file():
        return entry if entry.is_file() else None
    answer = input_function(
        "Add OpenRSC to Windows startup so it automatically recovers after a reboot? [Y/n]: "
    ).strip().casefold()
    enabled = answer in {"", "y", "yes"}
    if enabled:
        entry = install_startup(args)
        print("[ok] Windows startup enabled: %s" % entry)
        return entry
    _record_startup_choice(args.data, False)
    print("[ok] Windows startup was left disabled")
    return None


def _relaunch_elevated(argv):
    if os.name != "nt" or _is_administrator():
        return None
    powershell = shutil.which("powershell.exe") or shutil.which("powershell")
    if not powershell:
        raise LauncherError("PowerShell is required to request administrator elevation")
    child_args = [str(Path(__file__).resolve())] + list(argv) + ["--elevated-child"]
    argument_line = subprocess.list2cmdline(child_args)
    command = (
        "$p=Start-Process -FilePath "
        + _powershell_literal(sys.executable)
        + " -ArgumentList "
        + _powershell_literal(argument_line)
        + " -WorkingDirectory "
        + _powershell_literal(PROJECT)
        + " -Verb RunAs -WindowStyle Normal -Wait -PassThru; exit $p.ExitCode"
    )
    result = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-Command", command], check=False
    )
    return int(result.returncode)


def _python_command(minimum=MINIMUM_PYTHON):
    candidates = []
    if os.name == "nt":
        candidates.extend([["py", "-3"], ["python"]])
    else:
        candidates.extend([["python3"], ["python"]])
    for candidate in candidates:
        try:
            result = subprocess.run(
                candidate
                + [
                    "-c",
                    "import sys;print(str(sys.version_info[0])+'.'+str(sys.version_info[1]));"
                    "raise SystemExit(0 if sys.version_info >= (3,11) else 9)",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                check=False,
            )
        except OSError:
            continue
        if result.returncode == 0:
            return candidate
    return None


def ensure_supported_python(argv):
    if sys.version_info >= MINIMUM_PYTHON:
        return None
    if os.name != "nt":
        raise LauncherError("OpenRSC requires Python 3.11 or newer")
    winget = shutil.which("winget")
    if not winget:
        raise LauncherError("Python 3.11+ is missing and winget was not found")
    print("[install] Python 3.11+ is missing; installing the current Python release with winget...")
    result = subprocess.run(
        [
            winget,
            "install",
            "--id",
            PYTHON_WINGET_ID,
            "--exact",
            "--source",
            "winget",
            "--silent",
            "--accept-package-agreements",
            "--accept-source-agreements",
        ],
        check=False,
    )
    if result.returncode != 0:
        raise LauncherError("winget could not install Python (exit %s)" % result.returncode)
    command = _python_command()
    if not command:
        raise LauncherError("Python was installed but a Python 3.11+ command was not discovered")
    return subprocess.call(command + [str(Path(__file__).resolve())] + list(argv))


def cloudflared_asset_name(system_name=None, machine=None):
    system_name = (system_name or platform.system()).casefold()
    machine = (machine or platform.machine()).casefold()
    if machine in {"amd64", "x86_64", "x64"}:
        architecture = "amd64"
    elif machine in {"arm64", "aarch64"}:
        architecture = "arm64"
    elif machine in {"x86", "i386", "i686"}:
        architecture = "386"
    else:
        raise LauncherError("Unsupported processor architecture: %s" % machine)
    if system_name == "windows":
        return "cloudflared-windows-%s.exe" % architecture
    raise LauncherError("The automatic cloudflared binary installer currently targets Windows")


def extract_release_checksum(release_body, asset_name):
    pattern = r"(?im)^\s*" + re.escape(asset_name) + r"\s*:\s*([0-9a-f]{64})\s*$"
    match = re.search(pattern, release_body or "")
    if not match:
        raise LauncherError("The Cloudflare release did not publish a SHA-256 for %s" % asset_name)
    return match.group(1).lower()


def _request_json(url, headers=None, timeout=30):
    actual = {"Accept": "application/vnd.github+json", "User-Agent": USER_AGENT}
    actual.update(headers or {})
    request = urllib.request.Request(url, headers=actual)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.load(response)


def _latest_cloudflared_release():
    release = _request_json(CLOUDFLARED_RELEASE_API)
    asset_name = cloudflared_asset_name()
    assets = {item.get("name"): item for item in release.get("assets", [])}
    asset = assets.get(asset_name)
    if not asset:
        raise LauncherError("Cloudflare's latest release has no %s asset" % asset_name)
    download_url = str(asset.get("browser_download_url", ""))
    if not download_url.startswith("https://github.com/cloudflare/cloudflared/releases/"):
        raise LauncherError("Cloudflare release returned an unexpected download URL")
    return {
        "asset": asset_name,
        "download_url": download_url,
        "sha256": extract_release_checksum(release.get("body", ""), asset_name),
        "version": str(release.get("tag_name", "unknown")),
    }


def _download_verified_binary(release, target):
    target = Path(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix="cloudflared.", suffix=".download", dir=str(target.parent))
    os.close(descriptor)
    try:
        request = urllib.request.Request(release["download_url"], headers={"User-Agent": USER_AGENT})
        digest = hashlib.sha256()
        total = 0
        with urllib.request.urlopen(request, timeout=90) as response, open(temporary, "wb") as output:
            while True:
                block = response.read(1024 * 1024)
                if not block:
                    break
                total += len(block)
                if total > 256 * 1024 * 1024:
                    raise LauncherError("cloudflared download exceeded the 256 MiB limit")
                output.write(block)
                digest.update(block)
            output.flush()
            os.fsync(output.fileno())
        actual = digest.hexdigest()
        if actual != release["sha256"]:
            raise LauncherError(
                "cloudflared SHA-256 mismatch (expected %s, got %s)" % (release["sha256"], actual)
            )
        os.chmod(temporary, 0o700)
        os.replace(temporary, str(target))
        os.chmod(str(target), 0o700)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def verify_authenticode(path):
    if os.name != "nt":
        return "not-applicable"
    powershell = shutil.which("powershell.exe") or shutil.which("powershell")
    if not powershell:
        raise LauncherError("PowerShell is required to verify the cloudflared Authenticode signature")






    environment = os.environ.copy()
    system_root = environment.get("SystemRoot") or environment.get("WINDIR") or r"C:\Windows"
    environment["PSModulePath"] = str(
        Path(system_root) / "System32" / "WindowsPowerShell" / "v1.0" / "Modules"
    )
    expression = (
        "$ErrorActionPreference='Stop'; Import-Module Microsoft.PowerShell.Security -ErrorAction Stop; "
        + "$s=Get-AuthenticodeSignature -LiteralPath "
        + _powershell_literal(Path(path).resolve())
        + "; [pscustomobject]@{Status=[string]$s.Status;"
        + "Subject=[string]$s.SignerCertificate.Subject}|ConvertTo-Json -Compress"
    )
    result = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-Command", expression],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=environment,
        check=False,
        **_hidden_subprocess_kwargs(),
    )
    try:
        record = json.loads(result.stdout.strip())
    except json.JSONDecodeError as exc:
        raise LauncherError("Could not read the cloudflared Authenticode result") from exc
    status = str(record.get("Status", ""))
    subject = str(record.get("Subject", ""))
    if result.returncode != 0 or status != "Valid" or "Cloudflare" not in subject:
        raise LauncherError("cloudflared Authenticode verification failed: %s" % (status or "unknown"))
    return subject


def cloudflared_version(executable):
    try:
        result = subprocess.run(
            [str(executable), "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
            check=False,
            **_hidden_subprocess_kwargs(),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise LauncherError("The project-local cloudflared executable could not run") from exc
    output = result.stdout.strip()
    if result.returncode != 0 or not output.casefold().startswith("cloudflared version "):
        raise LauncherError("The project-local cloudflared executable failed its version check")
    return output


def ensure_local_cloudflared(update=False):
    CLOUDFLARED.parent.mkdir(parents=True, exist_ok=True)
    if CLOUDFLARED.is_file() and not update:
        version = cloudflared_version(CLOUDFLARED)
        verify_authenticode(CLOUDFLARED)
        if RELEASE_FILE.is_file():
            try:
                metadata = json.loads(RELEASE_FILE.read_text(encoding="utf-8"))
                expected = str(metadata["sha256"]).lower()
            except (OSError, KeyError, ValueError, json.JSONDecodeError):
                expected = ""
            if expected and _sha256(CLOUDFLARED) != expected:
                raise LauncherError("The local cloudflared binary no longer matches its recorded SHA-256")
        print("[ok] project-local %s" % version)
        return CLOUDFLARED

    release = _latest_cloudflared_release()
    print("[install] downloading cloudflared %s to %s" % (release["version"], CLOUDFLARED))
    _download_verified_binary(release, CLOUDFLARED)
    signer = verify_authenticode(CLOUDFLARED)
    version = cloudflared_version(CLOUDFLARED)
    _atomic_json(
        RELEASE_FILE,
        {
            "asset": release["asset"],
            "sha256": release["sha256"],
            "signer": signer,
            "source": release["download_url"],
            "version": release["version"],
        },
    )
    print("[ok] installed and verified %s" % version)
    return CLOUDFLARED


def sanitize_tunnel_name(value):
    value = re.sub(r"[^a-z0-9-]+", "-", str(value).casefold()).strip("-")
    value = re.sub(r"-+", "-", value)
    if not value:
        value = "host"
    if not value.startswith("openrsc-"):
        value = "openrsc-" + value
    return value[:63].rstrip("-")


def validate_hostname(value):
    value = str(value).strip().rstrip(".").casefold()
    if "://" in value or any(char in value for char in "/\\:*?\r\n\t "):
        raise LauncherError("Enter a DNS hostname only, without a scheme, path, wildcard, or port")
    try:
        ascii_name = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise LauncherError("The public hostname is not valid IDNA") from exc
    if len(ascii_name) > 253 or "." not in ascii_name:
        raise LauncherError("Enter a complete public hostname such as openrsc.example.com")
    label_pattern = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
    if not all(label_pattern.fullmatch(label) for label in ascii_name.split(".")):
        raise LauncherError("The public hostname contains an invalid DNS label")
    return ascii_name


def _isolated_cloudflare_env():
    PROFILE_DIR.mkdir(parents=True, exist_ok=True)
    environment = os.environ.copy()
    profile = str(PROFILE_DIR.resolve())
    environment["HOME"] = profile
    environment["USERPROFILE"] = profile
    environment["HOMEDRIVE"] = Path(profile).drive or environment.get("HOMEDRIVE", "")
    environment["HOMEPATH"] = profile[len(Path(profile).drive) :] if Path(profile).drive else profile
    environment["XDG_CONFIG_HOME"] = str((PROFILE_DIR / ".config").resolve())
    environment.pop("TUNNEL_ORIGIN_CERT", None)
    environment.pop("TUNNEL_CRED_FILE", None)
    environment.pop("TUNNEL_TOKEN", None)
    return environment


def _run_cloudflared(arguments, capture=False, check=True, timeout=None):
    command = [str(CLOUDFLARED.resolve())] + [str(value) for value in arguments]
    try:
        result = subprocess.run(
            command,
            env=_isolated_cloudflare_env(),
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise LauncherError("cloudflared command timed out") from exc
    if check and result.returncode != 0:
        details = (result.stderr or result.stdout or "").strip().splitlines()
        suffix = ": " + details[-1][:500] if details else ""
        raise LauncherError("cloudflared command failed (exit %s)%s" % (result.returncode, suffix))
    return result


def _decode_origin_cert(path):
    text = Path(path).read_text(encoding="ascii")
    match = re.search(
        r"-----BEGIN ARGO TUNNEL TOKEN-----\s*(.*?)\s*-----END ARGO TUNNEL TOKEN-----",
        text,
        re.DOTALL,
    )
    if not match:
        raise LauncherError("The local Cloudflare certificate has no tunnel authorization token")
    compact = re.sub(r"\s+", "", match.group(1))
    try:
        decoded = base64.b64decode(compact, validate=True)
        value = json.loads(decoded.decode("utf-8"))
    except (ValueError, UnicodeError, json.JSONDecodeError) as exc:
        raise LauncherError("The local Cloudflare certificate could not be decoded") from exc
    if not all(value.get(key) for key in ("zoneID", "accountID", "apiToken")):
        raise LauncherError("The local Cloudflare certificate is missing required fields")
    return value


def selected_zone_name(cert_path):
    """Return the zone chosen in Cloudflare login, or None if lookup is unavailable."""
    try:
        cert = _decode_origin_cert(cert_path)
        if cert.get("endpoint"):
            return None
        url = "https://api.cloudflare.com/client/v4/zones/%s" % cert["zoneID"]
        request = urllib.request.Request(
            url,
            headers={
                "Accept": "application/json",
                "Authorization": "Bearer %s" % cert["apiToken"],
                "User-Agent": USER_AGENT,
            },
        )
        with urllib.request.urlopen(request, timeout=20) as response:
            envelope = json.load(response)
        if envelope.get("success") and isinstance(envelope.get("result"), dict):
            name = str(envelope["result"].get("name", "")).strip().casefold()
            return validate_hostname("openrsc." + name).split(".", 1)[1] if name else None
    except (LauncherError, OSError, KeyError, TypeError, urllib.error.URLError, json.JSONDecodeError):
        return None
    return None


def _ensure_origin_certificate(force_login=False):
    if CERT_FILE.is_file() and CERT_FILE.stat().st_size > 0 and not force_login:
        _decode_origin_cert(CERT_FILE)
        print("[ok] using project-local Cloudflare authorization: %s" % CERT_FILE)
        return
    if force_login and CERT_FILE.exists():
        backup = CERT_FILE.with_name("cert.previous.%s.pem" % int(time.time()))
        CERT_FILE.replace(backup)
    login_home = PROFILE_DIR / ".cloudflared"
    login_cert = login_home / "cert.pem"
    if login_cert.exists():
        login_cert.unlink()
    login_home.mkdir(parents=True, exist_ok=True)
    print("[auth] Cloudflare will open a browser. Sign in and select the domain/zone for OpenRSC.")
    _run_cloudflared(["tunnel", "login"], capture=False, check=True)
    candidates = [login_cert, PROFILE_DIR / "cert.pem"]
    generated = next((path for path in candidates if path.is_file() and path.stat().st_size > 0), None)
    if generated is None:
        raise LauncherError("Cloudflare login completed without creating the project-local cert.pem")
    _decode_origin_cert(generated)
    CERT_FILE.parent.mkdir(parents=True, exist_ok=True)
    generated.replace(CERT_FILE)
    os.chmod(CERT_FILE, 0o600)
    print("[ok] Cloudflare authorization saved inside OpenRSC: %s" % CERT_FILE)


def _credential_tunnel_id(path):
    try:
        record = json.loads(Path(path).read_text(encoding="utf-8"))
        value = record.get("TunnelID") or record.get("tunnelID") or record.get("tunnel_id")
        return str(uuid.UUID(str(value)))
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise LauncherError("Invalid tunnel credentials file: %s" % path) from exc


def _find_named_tunnel(name):
    result = _run_cloudflared(
        ["tunnel", "--origincert", CERT_FILE, "list", "--output", "json", "--name", name],
        capture=True,
        check=True,
        timeout=45,
    )
    try:
        records = json.loads(result.stdout or "[]")
    except json.JSONDecodeError as exc:
        raise LauncherError("cloudflared returned an invalid tunnel list") from exc



    if records is None:
        records = []
    if not isinstance(records, list):
        raise LauncherError("cloudflared returned an unexpected tunnel list")
    matches = [item for item in records if str(item.get("name", "")).casefold() == name.casefold()]
    if not matches:
        return None
    value = matches[0].get("id") or matches[0].get("ID")
    try:
        return str(uuid.UUID(str(value)))
    except (ValueError, TypeError) as exc:
        raise LauncherError("Cloudflare returned an invalid tunnel identifier") from exc


def _ensure_tunnel(tunnel_name):
    CREDENTIALS_DIR.mkdir(parents=True, exist_ok=True)
    tunnel_id = _find_named_tunnel(tunnel_name)
    if tunnel_id:
        credential = CREDENTIALS_DIR / (tunnel_id + ".json")
        valid_credential = False
        if credential.is_file():
            try:
                valid_credential = _credential_tunnel_id(credential) == tunnel_id
            except LauncherError:
                valid_credential = False
        if not valid_credential:
            if credential.exists():
                credential.replace(
                    credential.with_name(credential.stem + ".invalid.%s.json" % int(time.time()))
                )
            _run_cloudflared(
                [
                    "tunnel",
                    "--origincert",
                    CERT_FILE,
                    "token",
                    "--cred-file",
                    credential,
                    tunnel_id,
                ],
                capture=True,
                check=True,
                timeout=45,
            )
        if _credential_tunnel_id(credential) != tunnel_id:
            raise LauncherError("The local credentials do not match the selected Cloudflare tunnel")
        print("[ok] reusing Cloudflare tunnel %s (%s)" % (tunnel_name, tunnel_id))
        return tunnel_id, credential

    temporary = CREDENTIALS_DIR / ("new-%s.json" % uuid.uuid4().hex)
    result = _run_cloudflared(
        [
            "tunnel",
            "--origincert",
            CERT_FILE,
            "create",
            "--output",
            "json",
            "--credentials-file",
            temporary,
            tunnel_name,
        ],
        capture=True,
        check=True,
        timeout=60,
    )
    tunnel_id = _credential_tunnel_id(temporary)
    credential = CREDENTIALS_DIR / (tunnel_id + ".json")
    if credential.exists():
        temporary.unlink(missing_ok=True)
    else:
        temporary.replace(credential)
    os.chmod(credential, 0o600)
    try:
        output = json.loads(result.stdout or "{}")
    except json.JSONDecodeError:
        output = {}
    returned = output.get("id") or output.get("ID") if isinstance(output, dict) else None
    if returned:
        try:
            returned_id = str(uuid.UUID(str(returned)))
        except ValueError as exc:
            raise LauncherError("Cloudflare returned an invalid created-tunnel identifier") from exc
        if returned_id != tunnel_id:
            raise LauncherError("Cloudflare's created tunnel did not match its credentials")
    print("[ok] created Cloudflare tunnel %s (%s)" % (tunnel_name, tunnel_id))
    return tunnel_id, credential


def _choose_hostname(requested, zone):
    if requested:
        hostname = validate_hostname(requested)
    else:
        default = "openrsc.%s" % zone if zone else ""
        if not sys.stdin.isatty():
            raise LauncherError("Cloudflare setup needs --hostname when standard input is not interactive")
        while True:
            prompt = "Public hostname"
            if default:
                prompt += " [%s]" % default
            prompt += ": "
            entered = input(prompt).strip() or default
            try:
                hostname = validate_hostname(entered)
                break
            except LauncherError as exc:
                print("[input] %s" % exc)
    if zone and hostname != zone and not hostname.endswith("." + zone):
        raise LauncherError("The hostname must be inside the Cloudflare zone selected during login (%s)" % zone)
    return hostname


def _route_dns(tunnel_id, hostname, overwrite=False):
    arguments = ["tunnel", "--origincert", CERT_FILE, "route", "dns"]
    if overwrite:
        arguments.append("--overwrite-dns")
    arguments.extend([tunnel_id, hostname])
    result = _run_cloudflared(arguments, capture=True, check=False, timeout=45)
    if result.returncode == 0:
        if (result.stdout or "").strip():
            print((result.stdout or "").strip())
        return
    details = ((result.stderr or "") + "\n" + (result.stdout or "")).strip()
    if not overwrite and sys.stdin.isatty():
        answer = input("A DNS record already exists or routing failed. Replace that hostname record? [y/N]: ").strip()
        if answer.casefold() in {"y", "yes"}:
            return _route_dns(tunnel_id, hostname, overwrite=True)
    last = details.splitlines()[-1][:500] if details else "unknown Cloudflare error"
    raise LauncherError("Could not route %s to the tunnel: %s" % (hostname, last))


def cloudflared_config_payload(tunnel_id, credential_file, hostname, port, cert_file=CERT_FILE):
    tunnel_id = str(uuid.UUID(str(tunnel_id)))
    hostname = validate_hostname(hostname)
    port = int(port)
    if not 1 <= port <= 65535:
        raise LauncherError("The OpenRSC port must be between 1 and 65535")

    quote = lambda value: json.dumps(str(Path(value).resolve()) if isinstance(value, Path) else str(value))
    return "\n".join(
        [
            "tunnel: " + json.dumps(tunnel_id),
            "credentials-file: " + quote(Path(credential_file)),
            "origincert: " + quote(Path(cert_file)),
            "no-autoupdate: true",
            'metrics: "127.0.0.1:0"',
            "ingress:",
            "  - hostname: " + json.dumps(hostname),
            '    service: "http://127.0.0.1:%s"' % port,
            '  - service: "http_status:404"',
            "",
        ]
    )


def write_cloudflared_config(path, tunnel_id, credential_file, hostname, port, cert_file=CERT_FILE):
    payload = cloudflared_config_payload(tunnel_id, credential_file, hostname, port, cert_file)
    _atomic_write(path, payload.encode("utf-8"))
    return payload


def _relative_cloudflare_path(path):
    return Path(path).resolve().relative_to(CLOUDFLARE.resolve()).as_posix()


def _local_state_path(value):
    candidate = (CLOUDFLARE / str(value)).resolve()
    try:
        candidate.relative_to(CLOUDFLARE.resolve())
    except ValueError as exc:
        raise LauncherError("Cloudflare state referenced a path outside the OpenRSC directory") from exc
    return candidate


def load_cloudflare_state(port=None, repair=True):
    if not STATE_FILE.is_file():
        return None
    try:
        state = json.loads(STATE_FILE.read_text(encoding="utf-8"))
        if int(state.get("version")) != 1:
            raise ValueError("unsupported state version")
        state["tunnel_id"] = str(uuid.UUID(str(state["tunnel_id"])))
        state["hostname"] = validate_hostname(state["hostname"])
        credential = _local_state_path(state["credentials_file"])
        config = _local_state_path(state["config_file"])
        if not credential.is_file() or not config.is_file():
            raise ValueError("state files are missing")
        if _credential_tunnel_id(credential) != state["tunnel_id"]:
            raise ValueError("credentials identify a different tunnel")
        state["credential_path"] = credential
        state["config_path"] = config
        actual_port = int(port) if port is not None else int(state.get("origin_port", 0))
        expected_config = cloudflared_config_payload(
            state["tunnel_id"], credential, state["hostname"], actual_port, CERT_FILE
        )
        needs_repair = config.read_text(encoding="utf-8") != expected_config
        port_changed = int(state.get("origin_port", 0)) != actual_port
        if needs_repair or port_changed:
            if repair:
                _atomic_write(config, expected_config.encode("utf-8"))
                state["origin_port"] = actual_port
                persisted = {key: value for key, value in state.items() if not key.endswith("_path")}
                _atomic_json(STATE_FILE, persisted)
            else:
                state["needs_repair"] = True
        return state
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError, LauncherError):
        return None


def setup_cloudflare(hostname=None, tunnel_name=None, port=8787, overwrite_dns=False, reconfigure=False, reauth=False):
    existing = None if reconfigure else load_cloudflare_state(port)
    if existing:
        print("[ok] existing domain connection detected: https://%s" % existing["hostname"])
        return existing

    _ensure_origin_certificate(force_login=reauth)
    zone = selected_zone_name(CERT_FILE)
    if zone:
        print("[ok] Cloudflare domain selected: %s" % zone)
    tunnel_name = sanitize_tunnel_name(tunnel_name or socket.gethostname())
    tunnel_id, credential = _ensure_tunnel(tunnel_name)
    hostname = _choose_hostname(hostname, zone)
    _route_dns(tunnel_id, hostname, overwrite=overwrite_dns)
    write_cloudflared_config(CONFIG_FILE, tunnel_id, credential, hostname, port, CERT_FILE)
    state = {
        "config_file": _relative_cloudflare_path(CONFIG_FILE),
        "credentials_file": _relative_cloudflare_path(credential),
        "hostname": hostname,
        "origin_port": int(port),
        "tunnel_id": tunnel_id,
        "tunnel_name": tunnel_name,
        "version": 1,
    }
    _atomic_json(STATE_FILE, state)
    state["credential_path"] = credential
    state["config_path"] = CONFIG_FILE
    print("[ok] domain connected: https://%s" % hostname)
    return state


def _restrict_runtime_permissions(config_path, data_path):
    paths = [Path(config_path), CLOUDFLARE, Path(data_path)]
    for path in paths:
        if path.is_dir():
            try:
                os.chmod(path, 0o700)
            except OSError:
                pass
        elif path.is_file():
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
    if os.name != "nt":
        return
    domain = os.environ.get("USERDOMAIN", "")
    username = os.environ.get("USERNAME", "")
    identity = "%s\\%s" % (domain, username) if domain and username else username
    if not identity:
        raise LauncherError("The current Windows identity could not be determined for ACL setup")
    for path in paths:
        if not path.exists():
            continue
        directory = path.is_dir()
        command = [
            "icacls",
            str(path.resolve()),
            "/inheritance:r",
            "/grant:r",
            "%s:(OI)(CI)(F)" % identity if directory else "%s:(F)" % identity,
            "*S-1-5-18:(OI)(CI)(F)" if directory else "*S-1-5-18:(F)",
            "*S-1-5-32-544:(OI)(CI)(F)" if directory else "*S-1-5-32-544:(F)",
        ]
        result = subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            **_hidden_subprocess_kwargs(),
        )
        if result.returncode != 0:
            raise LauncherError("Could not restrict the ACL for %s" % path)
        if directory:



            result = subprocess.run(
                ["icacls", str(path.resolve()) + "\\*", "/reset", "/T", "/C", "/Q"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                **_hidden_subprocess_kwargs(),
            )
            if result.returncode != 0:
                raise LauncherError("Could not propagate the protected ACL for %s" % path)


def _ensure_openrsc_config(config_path, port):
    config_path = Path(config_path).resolve()
    sys.path.insert(0, str(PROJECT))
    from openrsc.config import ConfigurationError, build_config, load_config, write_config

    if config_path.is_file():
        config = load_config(config_path)
        print("[ok] OpenRSC configuration: %s" % config_path)
        return config
    if not sys.stdin.isatty():
        raise LauncherError("OpenRSC configuration is missing; run launcher.py interactively once")
    print("[setup] Create the OpenRSC panel password. Input is hidden and the plaintext is not stored.")
    first = getpass.getpass("New OpenRSC password: ")
    second = getpass.getpass("Repeat OpenRSC password: ")
    if first != second:
        raise LauncherError("The OpenRSC passwords did not match")
    try:
        write_config(config_path, build_config(first, port=port))
        return load_config(config_path)
    except ConfigurationError as exc:
        raise LauncherError(str(exc)) from exc


def _open_when_ready(url, no_browser):
    if no_browser:
        return

    def worker():
        time.sleep(5)
        try:
            webbrowser.open(url, new=2)
        except Exception:
            pass

    threading.Thread(target=worker, name="openrsc-browser", daemon=True).start()


def _check_only(args):
    ok = True
    print("CHECK python=%s.%s status=ok" % sys.version_info[:2])
    try:
        sys.path.insert(0, str(PROJECT))
        from openrsc.config import load_config

        load_config(args.config)
        print("CHECK openrsc_config=ok")
    except Exception as exc:
        print("CHECK openrsc_config=failed result=%s" % exc)
        ok = False
    if not args.no_tunnel:
        try:
            version = cloudflared_version(CLOUDFLARED)
            verify_authenticode(CLOUDFLARED)
            metadata = json.loads(RELEASE_FILE.read_text(encoding="utf-8"))
            if _sha256(CLOUDFLARED) != str(metadata["sha256"]).casefold():
                raise LauncherError("local binary hash does not match release.json")
            print("CHECK cloudflared=ok result=%s" % version)
        except Exception as exc:
            print("CHECK cloudflared=failed result=%s" % exc)
            ok = False
        state = load_cloudflare_state(args.port, repair=False)
        if state and not state.get("needs_repair"):
            print("CHECK domain=ok result=https://%s" % state["hostname"])
        else:
            print("CHECK domain=%s" % ("needs-repair" if state else "not-configured"))
            ok = False
    print("CHECK_RESULT=%s" % ("OK" if ok else "INCOMPLETE"))
    return 0 if ok else 1


def _probe_url(url, timeout=4.0):
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=float(timeout)) as response:
            return 200 <= int(getattr(response, "status", response.getcode())) < 400
    except (OSError, ValueError, urllib.error.URLError):
        return False


def _supervised_child_command(args):
    executable = Path(sys.executable).resolve()
    if executable.name.casefold() in {"pythonw.exe", "pythonw_d.exe"}:
        candidate = executable.with_name(executable.name.replace("pythonw", "python", 1))
        if candidate.is_file():
            executable = candidate
    command = [
        str(executable),
        str(Path(__file__).resolve()),
        "--config",
        str(args.config.resolve()),
        "--data",
        str(args.data.resolve()),
        "--port",
        str(int(args.port)),
        "--no-elevate",
        "--no-browser",
        "--no-startup-prompt",
        "--supervised-child",
    ]
    if args.no_tunnel:
        command.append("--no-tunnel")
    if args.verbose:
        command.append("--verbose")
    return command


def _supervisor_lock(path):
    path = Path(path).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    stream = path.open("a+b")
    if stream.tell() == 0:
        stream.write(b"0")
        stream.flush()
    stream.seek(0)
    try:
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (OSError, IOError) as exc:
        stream.close()
        raise LauncherError("another OpenRSC supervisor is already running") from exc
    return stream


def _terminate_process_tree(process):
    if process is None or process.poll() is not None:
        return
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            **_hidden_subprocess_kwargs(),
        )
    else:
        process.terminate()
        try:
            process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            process.kill()


def _stop_recorded_tunnel(data):
    pid_path = Path(data).resolve() / "cloudflared.pid"
    try:
        pid = int(pid_path.read_text(encoding="ascii").strip())
    except (OSError, ValueError):
        return
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/PID", str(pid), "/T", "/F"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            **_hidden_subprocess_kwargs(),
        )
    else:
        try:
            os.kill(pid, 15)
        except OSError:
            pass
    try:
        if pid_path.read_text(encoding="ascii").strip() == str(pid):
            pid_path.unlink()
    except OSError:
        pass


def _ensure_supervisor_stdio(data):
    if sys.stdout is not None and sys.stderr is not None:
        return None
    log_dir = Path(data).resolve() / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    stream = (log_dir / "supervisor-console.log").open("a", encoding="utf-8", buffering=1)
    if sys.stdout is None:
        sys.stdout = stream
    if sys.stderr is None:
        sys.stderr = stream
    return stream


def _run_supervisor(args, *, probe=_probe_url, sleep=time.sleep, monotonic=time.monotonic):
    data = args.data.resolve()
    log_dir = data / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    pid_path = data / "openrsc-supervisor.pid"
    lock = _supervisor_lock(data / "openrsc-supervisor.lock")
    pid_path.write_text(str(os.getpid()) + "\n", encoding="ascii")
    tracker = RecoveryTracker()
    child = None
    delay_index = 0
    delays = (2, 5, 10, 20, 30, 60)
    public_url = None
    if not args.no_tunnel:
        state = load_cloudflare_state(args.port)
        if state:
            public_url = "https://%s/healthz" % state["hostname"]
    local_url = "http://127.0.0.1:%s/healthz" % args.port
    child_log_path = log_dir / "supervisor-child.log"
    supervisor_log_path = log_dir / "supervisor.log"

    def record(message):
        stamp = time.strftime("%Y-%m-%d %H:%M:%S")
        with supervisor_log_path.open("a", encoding="utf-8") as stream:
            stream.write("%s %s\n" % (stamp, message))

    try:
        record("SUPERVISOR started pid=%s local=%s public=%s" % (os.getpid(), local_url, public_url or "disabled"))
        while True:
            started = monotonic()
            creationflags = 0
            startupinfo = None
            if os.name == "nt":
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                startupinfo.wShowWindow = subprocess.SW_HIDE
                creationflags = subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP
            with child_log_path.open("a", encoding="utf-8", buffering=1) as child_log:
                command = _supervised_child_command(args)
                child = subprocess.Popen(
                    command,
                    cwd=str(PROJECT),
                    stdout=child_log,
                    stderr=subprocess.STDOUT,
                    startupinfo=startupinfo,
                    creationflags=creationflags,
                )
                record("CHILD started pid=%s command=%s" % (child.pid, subprocess.list2cmdline(command)))
                reason = None
                next_probe = started + 20.0
                while child.poll() is None:
                    sleep(2.0)
                    now = monotonic()
                    if now < next_probe:
                        continue
                    next_probe = now + 10.0
                    local_ok = probe(local_url, timeout=4.0)
                    public_ok = None
                    internet_ok = None
                    if local_ok and public_url:
                        public_ok = probe(public_url, timeout=6.0)
                        if not public_ok:
                            internet_ok = probe(INTERNET_PROBE_URL, timeout=5.0)
                    action = tracker.observe(
                        local_ok=local_ok,
                        public_ok=public_ok,
                        internet_ok=internet_ok,
                        now=now,
                    )
                    if action == "offline":
                        record("HEALTH internet=offline action=wait-for-recovery")
                    elif action == "network-restored":
                        record("HEALTH internet=restored action=grace")
                    elif action in {"restart-local", "restart-public"}:
                        reason = action
                        record("HEALTH action=%s" % action)
                        break
                returncode = child.poll()
                if reason:
                    _terminate_process_tree(child)
                    returncode = child.poll()
                uptime = monotonic() - started
                record("CHILD stopped pid=%s exit=%s reason=%s uptime=%.1f" % (child.pid, returncode, reason or "process-exit", uptime))
                _stop_recorded_tunnel(data)
            if uptime >= 120.0:
                delay_index = 0
            delay = delays[min(delay_index, len(delays) - 1)]
            delay_index = min(delay_index + 1, len(delays) - 1)
            record("CHILD restart-in=%ss" % delay)
            sleep(float(delay))
    except KeyboardInterrupt:
        record("SUPERVISOR interrupted")
        return 130
    finally:
        _terminate_process_tree(child)
        try:
            if pid_path.read_text(encoding="ascii").strip() == str(os.getpid()):
                pid_path.unlink()
        except OSError:
            pass
        lock.close()


def build_parser():
    parser = argparse.ArgumentParser(
        description="Install, configure, and launch OpenRSC with a project-local Cloudflare Tunnel"
    )
    parser.add_argument("--config", type=Path, default=PROJECT / "config" / "openrsc.json")
    parser.add_argument("--data", type=Path, default=PROJECT / "data")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--hostname", help="public hostname, for example openrsc.example.com")
    parser.add_argument("--tunnel-name", help="Cloudflare tunnel name (default: openrsc-COMPUTERNAME)")
    parser.add_argument("--overwrite-dns", action="store_true", help="replace an existing DNS record for --hostname")
    parser.add_argument("--reconfigure-cloudflare", action="store_true", help="configure the tunnel/hostname again")
    parser.add_argument("--reauth-cloudflare", action="store_true", help="authenticate and select a Cloudflare zone again")
    parser.add_argument("--update-cloudflared", action="store_true", help="download and verify the latest cloudflared release")
    parser.add_argument("--install-only", action="store_true", help="install/check prerequisites without Cloudflare login or launch")
    parser.add_argument("--check-only", action="store_true", help="report readiness without installation, login, or launch")
    parser.add_argument("--no-tunnel", action="store_true", help="run only the loopback OpenRSC origin")
    parser.add_argument("--no-elevate", action="store_true", help="run without requesting administrator elevation")
    parser.add_argument("--no-browser", action="store_true", help="do not open the panel in the default browser")
    parser.add_argument("--supervise", action="store_true", help="keep OpenRSC running and recover failed health checks")
    parser.add_argument("--install-startup", action="store_true", help="enable hidden per-user Windows startup and exit")
    parser.add_argument("--remove-startup", action="store_true", help="disable per-user Windows startup and exit")
    parser.add_argument("--startup-status", action="store_true", help="report Windows startup registration and exit")
    parser.add_argument("--no-startup-prompt", action="store_true", help="do not offer Windows startup registration")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--elevated-child", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--supervised-child", action="store_true", help=argparse.SUPPRESS)
    return parser


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        relaunched = ensure_supported_python(argv)
        if relaunched is not None:
            return int(relaunched)
        args = build_parser().parse_args(argv)
        if not 1 <= int(args.port) <= 65535:
            raise LauncherError("--port must be between 1 and 65535")
        startup_actions = int(args.install_startup) + int(args.remove_startup) + int(args.startup_status)
        if startup_actions > 1:
            raise LauncherError("choose only one startup management action")
        args.data.resolve().mkdir(parents=True, exist_ok=True)
        if args.install_startup:
            entry = install_startup(args)
            print("STARTUP_RESULT=INSTALLED path=%s" % entry)
            return 0
        if args.remove_startup:
            entry = remove_startup(args)
            print("STARTUP_RESULT=REMOVED path=%s" % entry)
            return 0
        if args.startup_status:
            entry = startup_entry_path()
            print("STARTUP_RESULT=%s path=%s" % ("ENABLED" if entry.is_file() else "DISABLED", entry))
            return 0
        if args.reauth_cloudflare:
            args.reconfigure_cloudflare = True
        if args.check_only:
            return _check_only(args)
        maybe_prompt_startup(args)
        if os.name == "nt" and not args.no_elevate and not args.elevated_child:
            relaunched = _relaunch_elevated(argv)
            if relaunched is not None:
                return relaunched

        if args.supervise and not args.supervised_child:
            _ensure_supervisor_stdio(args.data)
            return _run_supervisor(args)

        CLOUDFLARE.mkdir(parents=True, exist_ok=True)
        config = _ensure_openrsc_config(args.config, args.port)
        executable = None
        if not args.no_tunnel or args.install_only or args.update_cloudflared:
            executable = ensure_local_cloudflared(update=args.update_cloudflared)
        _restrict_runtime_permissions(args.config, args.data)
        if args.install_only:
            print("INSTALL_RESULT=OK python=%s.%s cloudflared=%s" % (sys.version_info[0], sys.version_info[1], executable))
            return 0

        state = None
        if not args.no_tunnel:
            state = setup_cloudflare(
                hostname=args.hostname,
                tunnel_name=args.tunnel_name,
                port=args.port,
                overwrite_dns=args.overwrite_dns,
                reconfigure=args.reconfigure_cloudflare,
                reauth=args.reauth_cloudflare,
            )
            _restrict_runtime_permissions(args.config, args.data)

        sys.path.insert(0, str(PROJECT))
        from openrsc.__main__ import main as server_main

        command = [
            "--config",
            str(args.config.resolve()),
            "--data",
            str(args.data.resolve()),
            "--port",
            str(args.port),
        ]
        if args.verbose:
            command.append("--verbose")
        if state:
            command.extend(
                [
                    "--cloudflared-executable",
                    str(executable.resolve()),
                    "--cloudflared-config",
                    str(state["config_path"].resolve()),
                    "--cloudflared-tunnel-id",
                    state["tunnel_id"],
                ]
            )
            public_url = "https://%s" % state["hostname"]
        else:
            public_url = "http://127.0.0.1:%s" % args.port
        print("[start] OpenRSC panel: %s" % public_url)
        print("[start] administrator=%s" % ("yes" if _is_administrator() else "no"))
        _open_when_ready(public_url, args.no_browser)
        return int(server_main(command))
    except KeyboardInterrupt:
        print("\n[stop] OpenRSC launcher interrupted")
        return 130
    except (LauncherError, OSError, ValueError, urllib.error.URLError) as exc:
        print("LAUNCHER_ERROR: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
