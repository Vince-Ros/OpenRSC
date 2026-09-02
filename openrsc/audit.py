from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class AuditLog:
    """Small JSON-lines audit log. Terminal text is represented only by length and hash."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    @staticmethod
    def command_metadata(command: str) -> dict[str, Any]:
        return {
            "input_chars": len(command),
            "input_sha256": hashlib.sha256(command.encode("utf-8", "replace")).hexdigest(),
        }

    def write(self, event: str, remote: str, **fields: Any) -> None:
        record = {
            "time": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "event": event,
            "remote": remote,
            **fields,
        }
        line = json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n"
        with self._lock:
            with self.path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(line)

