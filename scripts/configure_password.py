
from __future__ import annotations

import argparse
import getpass
import json
import os
import subprocess
import sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT))

from openrsc.config import ConfigurationError, build_config, password_record, write_config


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="Create or update the local OpenRSC security configuration")
    result.add_argument("--config", type=Path, default=PROJECT / "config" / "openrsc.json")
    result.add_argument("--root", action="append", dest="roots", help="allowed filesystem root; may be repeated")
    result.add_argument("--port", type=int)
    result.add_argument("--password-stdin", action="store_true", help="read one password line from standard input")
    result.add_argument("--force", action="store_true", help="replace an existing configuration")
    return result


def read_password(stdin: bool) -> str:
    if stdin:
        value = sys.stdin.readline().rstrip("\r\n")
        if not value:
            raise ConfigurationError("No password was supplied on standard input")
        return value
    first = getpass.getpass("New OpenRSC password: ")
    second = getpass.getpass("Repeat password: ")
    if first != second:
        raise ConfigurationError("Passwords did not match")
    return first


def restrict_windows_acl(path: Path) -> bool:
    if os.name != "nt":
        return True
    domain = os.environ.get("USERDOMAIN", "")
    username = os.environ.get("USERNAME", "")
    identity = f"{domain}\\{username}" if domain and username else username
    if not identity:
        return False
    result = subprocess.run(
        [
            "icacls",
            str(path),
            "/inheritance:r",
            "/grant:r",
            f"{identity}:(F)",
            "*S-1-5-18:(F)",
            "*S-1-5-32-544:(F)",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    path = args.config.resolve()
    try:
        password = read_password(args.password_stdin)
        if path.exists() and not args.force:
            current = json.loads(path.read_text(encoding="utf-8"))
            current["security"]["password"] = password_record(password)
            current["security"]["session_secret"] = build_config(password)["security"]["session_secret"]
            if args.roots:
                current["files"]["roots"] = args.roots
            if args.port is not None:
                current["listen"]["port"] = args.port
            data = current
            action = "updated"
        else:
            data = build_config(password, roots=args.roots, port=args.port or 8787)
            action = "created"
        write_config(path, data)
        acl_restricted = restrict_windows_acl(path)
    except (ConfigurationError, OSError, json.JSONDecodeError, KeyError) as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2
    print(f"OpenRSC configuration {action}: {path}")
    print("The password is stored only as a salted PBKDF2-SHA256 verifier.")
    print(f"Private configuration ACL: {'restricted' if acl_restricted else 'review required'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
