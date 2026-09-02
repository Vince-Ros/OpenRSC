
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT))

from openrsc.config import load_config, verify_password
import launcher


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify an OpenRSC source-tree installation")
    parser.add_argument("--config", type=Path, default=PROJECT / "config" / "openrsc.json")
    parser.add_argument("--password-stdin", action="store_true")
    args = parser.parse_args()
    try:
        config = load_config(args.config)
        required = [
            PROJECT / "launcher.py",
            PROJECT / "launch-openrsc.cmd",
            PROJECT / "run_openrsc.py",
            PROJECT / "cloudflare" / "README.md",
            PROJECT / "openrsc" / "server.py",
            PROJECT / "openrsc" / "web" / "index.html",
            PROJECT / "openrsc" / "web" / "app.js",
            PROJECT / "openrsc" / "web" / "styles.css",
        ]
        missing = [str(path) for path in required if not path.is_file()]
        if missing:
            raise RuntimeError("Missing required files: " + ", ".join(missing))
        if args.password_stdin:
            password = sys.stdin.readline().rstrip("\r\n")
            if not verify_password(password, config.security["password"]):
                raise RuntimeError("Password does not match the configured verifier")
            if password and password in args.config.read_text(encoding="utf-8"):
                raise RuntimeError("Plaintext password is present in the configuration")
        executable = PROJECT / "cloudflare" / "bin" / ("cloudflared.exe" if os.name == "nt" else "cloudflared")
        release_path = PROJECT / "cloudflare" / "bin" / "release.json"
        if not executable.is_file() or not release_path.is_file():
            raise RuntimeError("Project-local cloudflared is missing; run: python launcher.py --install-only --no-elevate")
        release = json.loads(release_path.read_text(encoding="utf-8"))
        digest = hashlib.sha256(executable.read_bytes()).hexdigest()
        if digest != str(release.get("sha256", "")).casefold():
            raise RuntimeError("Project-local cloudflared does not match release.json")
        version = launcher.cloudflared_version(executable)
        launcher.verify_authenticode(executable)
        print("INSTALL_VERIFY_OK")
        print(f"listen={config.host}:{config.port}")
        print(f"roots={len(config.files['roots'])}")
        print("password_storage=pbkdf2_sha256")
        print("third_party_python_dependencies=0")
        print(f"cloudflared={version}")
        print(f"cloudflared_sha256={digest}")
        print("cloudflared_signature=Valid")
        print("cloudflare_runtime=project-local")
        return 0
    except Exception as exc:
        print(f"INSTALL_VERIFY_FAILED: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
