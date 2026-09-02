from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Any

from .config import OpenRSCConfig, _unb64, verify_password


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class AuthenticationError(ValueError):
    pass


@dataclass(frozen=True)
class Session:
    sid: str
    expires: int


class LoginLimiter:
    def __init__(self, attempts: int, window_seconds: int, lock_seconds: int) -> None:
        self.attempts = attempts
        self.window = window_seconds
        self.lock_seconds = lock_seconds
        self._failures: dict[str, deque[float]] = defaultdict(deque)
        self._locked_until: dict[str, float] = {}
        self._lock = threading.Lock()

    def remaining_lock(self, key: str, now: float | None = None) -> int:
        now = now if now is not None else time.monotonic()
        with self._lock:
            self._maintenance(now)
            until = self._locked_until.get(key, 0.0)
            if until <= now:
                self._locked_until.pop(key, None)
                return 0
            return max(1, int(until - now + 0.999))

    def fail(self, key: str, now: float | None = None) -> int:
        now = now if now is not None else time.monotonic()
        with self._lock:
            self._maintenance(now)
            events = self._failures[key]
            while events and events[0] <= now - self.window:
                events.popleft()
            events.append(now)
            if len(events) >= self.attempts:
                self._locked_until[key] = now + self.lock_seconds
                events.clear()
                return self.lock_seconds
            return 0

    def success(self, key: str) -> None:
        with self._lock:
            self._failures.pop(key, None)
            self._locked_until.pop(key, None)

    def _maintenance(self, now: float) -> None:
        if len(self._failures) < 10_000:
            return
        stale = [key for key, events in self._failures.items() if not events or events[-1] <= now - self.window]
        for key in stale:
            self._failures.pop(key, None)
        expired = [key for key, until in self._locked_until.items() if until <= now]
        for key in expired:
            self._locked_until.pop(key, None)
        if len(self._failures) > 10_000:
            oldest = sorted(self._failures, key=lambda item: self._failures[item][-1])[: len(self._failures) - 10_000]
            for key in oldest:
                self._failures.pop(key, None)


class AuthService:
    def __init__(self, config: OpenRSCConfig) -> None:
        security = config.security
        self._password = security["password"]
        self._secret = _unb64(str(security["session_secret"]))
        self._ttl = int(security.get("session_ttl_seconds", 28_800))
        self._max_sessions = int(security.get("max_active_sessions", 24))
        self._sessions: dict[str, tuple[int, str]] = {}
        self._lock = threading.RLock()
        password_workers = max(1, min(4, (os.cpu_count() or 2) // 2))
        self._password_slots = threading.BoundedSemaphore(password_workers)
        self.limiter = LoginLimiter(
            int(security.get("login_attempts", 5)),
            int(security.get("login_window_seconds", 300)),
            int(security.get("login_lock_seconds", 900)),
        )

    @staticmethod
    def _ua_hash(user_agent: str) -> str:
        return hashlib.sha256(user_agent.encode("utf-8", "replace")).hexdigest()[:24]

    def check_password(self, password: str) -> bool:
        if not self._password_slots.acquire(blocking=False):
            return False
        try:
            return verify_password(password, self._password)
        finally:
            self._password_slots.release()

    def _sign(self, payload: bytes) -> bytes:
        return hmac.new(self._secret, b"session\0" + payload, hashlib.sha256).digest()

    def create_session(self, user_agent: str, now: int | None = None) -> tuple[str, Session]:
        now = int(time.time()) if now is None else int(now)
        sid = secrets.token_urlsafe(24)
        expires = now + self._ttl
        ua_hash = self._ua_hash(user_agent)
        payload = json.dumps(
            {"v": 1, "sid": sid, "iat": now, "exp": expires, "ua": ua_hash},
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        token = _b64(payload) + "." + _b64(self._sign(payload))
        with self._lock:
            self._purge(now)
            if len(self._sessions) >= self._max_sessions:
                oldest = min(self._sessions, key=lambda item: self._sessions[item][0])
                self._sessions.pop(oldest, None)
            self._sessions[sid] = (expires, ua_hash)
        return token, Session(sid=sid, expires=expires)

    def verify_session(self, token: str, user_agent: str, now: int | None = None) -> Session:
        now = int(time.time()) if now is None else int(now)
        try:
            encoded_payload, encoded_signature = token.split(".", 1)
            payload = _decode(encoded_payload)
            supplied = _decode(encoded_signature)
            if not hmac.compare_digest(supplied, self._sign(payload)):
                raise AuthenticationError("invalid signature")
            data = json.loads(payload)
            sid = str(data["sid"])
            issued = int(data["iat"])
            expires = int(data["exp"])
            ua_hash = str(data["ua"])
            if data.get("v") != 1 or issued > now + 60 or expires <= now:
                raise AuthenticationError("expired session")
            if not hmac.compare_digest(ua_hash, self._ua_hash(user_agent)):
                raise AuthenticationError("client mismatch")
            with self._lock:
                self._purge(now)
                stored = self._sessions.get(sid)
                if stored != (expires, ua_hash):
                    raise AuthenticationError("revoked session")
            return Session(sid=sid, expires=expires)
        except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
            if isinstance(exc, AuthenticationError):
                raise
            raise AuthenticationError("invalid session") from exc

    def csrf_token(self, session: Session) -> str:
        return _b64(hmac.new(self._secret, b"csrf\0" + session.sid.encode("ascii"), hashlib.sha256).digest())

    def verify_csrf(self, session: Session, token: str) -> bool:
        return hmac.compare_digest(self.csrf_token(session), token or "")

    def revoke(self, sid: str) -> None:
        with self._lock:
            self._sessions.pop(sid, None)

    def _purge(self, now: int) -> None:
        expired = [sid for sid, (expires, _) in self._sessions.items() if expires <= now]
        for sid in expired:
            self._sessions.pop(sid, None)
