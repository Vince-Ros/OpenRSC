from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any, TextIO


def codex_event_text(event: dict[str, Any]) -> tuple[str | None, str | None]:
    """Return (thread id, printable text) for a Codex JSONL event."""

    event_type = str(event.get("type", ""))
    thread_id = str(event.get("thread_id", "")) or None if event_type == "thread.started" else None
    item = event.get("item") if isinstance(event.get("item"), dict) else {}
    item_type = str(item.get("type", ""))
    if event_type == "item.completed" and item_type in {"agent_message", "reasoning"}:
        text = item.get("text") or item.get("content")
        return thread_id, str(text).strip() if text else None
    if event_type in {"error", "turn.failed"}:
        message = event.get("message") or event.get("error") or item.get("text")
        return thread_id, f"[Codex error] {message}" if message else "[Codex request failed]"
    return thread_id, None


def _startup_options() -> dict[str, Any]:
    if os.name != "nt":
        return {}
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startupinfo.wShowWindow = subprocess.SW_HIDE
    return {"startupinfo": startupinfo, "creationflags": subprocess.CREATE_NO_WINDOW}


def _stream(command: list[str], directory: Path, *, json_events: bool, output: TextIO) -> tuple[int, str | None]:
    process = subprocess.Popen(
        command,
        cwd=directory,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
        **_startup_options(),
    )
    thread_id = None
    printed = False
    assert process.stdout is not None
    for raw_line in process.stdout:
        line = raw_line.rstrip("\r\n")
        if not json_events:
            print(line, file=output, flush=True)
            printed = printed or bool(line)
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            if line:
                print(line, file=output, flush=True)
                printed = True
            continue
        found_thread, text = codex_event_text(event) if isinstance(event, dict) else (None, None)
        thread_id = found_thread or thread_id
        if text:
            print(text, file=output, flush=True)
            printed = True
    returncode = process.wait()
    if returncode and not printed:
        print(f"[CLI exited with status {returncode}]", file=output, flush=True)
    return returncode, thread_id


def run_prompt(provider: str, executable: str, directory: Path, prompt: str, session_id: str | None, output: TextIO) -> tuple[int, str | None]:
    if provider == "claude":
        new_session = session_id is None
        session_id = session_id or str(uuid.uuid4())
        session_args = ["--session-id", session_id] if new_session else ["--resume", session_id]
        command = [executable, "-p", "--output-format", "text", *session_args, prompt]
        code, _ = _stream(command, directory, json_events=False, output=output)
        return code, session_id
    command = [
        executable,
        "exec",
        "--json",
        "--color",
        "never",
        "--sandbox",
        "workspace-write",
        "--skip-git-repo-check",
    ]
    if session_id:
        command = [executable, "exec", "resume", "--json", "--skip-git-repo-check", session_id, prompt]
    else:
        command.extend(["--cd", str(directory), prompt])
    code, found_thread = _stream(command, directory, json_events=True, output=output)
    return code, found_thread or session_id


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="OpenRSC browser-friendly AI CLI bridge")
    parser.add_argument("--provider", choices=("claude", "codex"), required=True)
    parser.add_argument("--directory", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    directory = args.directory.resolve()
    if not directory.is_dir():
        print("Selected working directory no longer exists.", flush=True)
        return 2
    executable = shutil.which(args.provider)
    if not executable:
        print(f"{args.provider.title()} CLI is not installed.", flush=True)
        return 3
    label = "Claude Code" if args.provider == "claude" else "Codex"
    print(f"{label} CLI ready in {directory}", flush=True)
    print("Enter a prompt. Use /new for a fresh session or /exit to return to the shell.", flush=True)
    session_id = None
    while True:
        try:
            prompt = input(f"{args.provider}> ").strip()
        except EOFError:
            print("", flush=True)
            break
        if not prompt:
            continue
        if prompt.lower() in {"/exit", "exit", "quit"}:
            break
        if prompt.lower() == "/new":
            session_id = None
            print("Started a fresh session.", flush=True)
            continue
        try:
            code, updated_session = run_prompt(args.provider, executable, directory, prompt, session_id, sys.stdout)
            if code == 0:
                session_id = updated_session
        except KeyboardInterrupt:
            print("\nRequest interrupted.", flush=True)
        except OSError as exc:
            print(f"CLI launch failed: {exc}", flush=True)
    print(f"{label} CLI closed.", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
