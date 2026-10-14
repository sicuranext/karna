"""Auth + change-audit for the dashboard.

Model: one administrator account (email + password). On first run no account
exists; registering it requires a one-time setup token, printed to the API
container log (or supplied with KARNA_DASH_SETUP_TOKEN), so that whoever first
reaches a freshly deployed console cannot claim it. Once the account exists
the token is deleted and registration is closed.

No DB: a JSON file on the data volume holds the credential + signing secret;
changes are appended as JSON lines. Passwords are hashed with scrypt; sessions
are stateless HMAC-signed bearer tokens (no cookie → no CSRF surface).
Everything here is stdlib only.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import time

from cryptography.fernet import Fernet, InvalidToken

DATA_DIR = os.getenv("KARNA_DASH_DATA", "/data")
SETUP_TOKEN_ENV = "KARNA_DASH_SETUP_TOKEN"
SECRET_MIN_LENGTH = 32
AUTH_FILE = os.path.join(DATA_DIR, "auth.json")
CHANGES_FILE = os.path.join(DATA_DIR, "changes.jsonl")
TOKEN_TTL = int(os.getenv("KARNA_DASH_TOKEN_TTL", str(12 * 3600)))

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_SCRYPT = dict(n=2 ** 14, r=8, p=1, dklen=32)


class AuthError(Exception):
    def __init__(self, status: int, detail: str):
        self.status = status
        self.detail = detail


def _load() -> dict | None:
    """The auth state, None when it does not exist yet.

    A file that exists but cannot be read or parsed is an error, never "no
    account": treating it as missing would reopen registration and overwrite
    the signing secret and the credential key."""
    try:
        with open(AUTH_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as exc:
        raise AuthError(500, "The console's auth state cannot be read; check the data volume.") from exc
    if not isinstance(data, dict):
        raise AuthError(500, "The console's auth state is malformed; check the data volume.")
    return data


def _save(data: dict) -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    tmp = AUTH_FILE + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(data, fh)
    os.replace(tmp, AUTH_FILE)


def _secret() -> bytes:
    """Signing secret: env override, else generated once and persisted."""
    env = os.getenv("KARNA_DASH_SECRET")
    if env:
        if len(env) < SECRET_MIN_LENGTH:
            raise AuthError(500, f"KARNA_DASH_SECRET must be at least {SECRET_MIN_LENGTH} characters.")
        return env.encode()
    data = _load() or {}
    s = data.get("secret")
    if not s:
        s = secrets.token_hex(32)
        data["secret"] = s
        _save(data)
    return s.encode()


def _credential_key() -> bytes:
    """Encryption key for provider credentials; env override supports secret stores."""
    env = os.getenv("KARNA_DASH_CREDENTIAL_KEY")
    if env:
        try:
            Fernet(env.encode("ascii"))
        except (ValueError, TypeError) as exc:
            raise AuthError(500, "KARNA_DASH_CREDENTIAL_KEY is not a valid Fernet key.") from exc
        return env.encode("ascii")
    data = _load() or {}
    key = data.get("credential_key")
    if not key:
        key = Fernet.generate_key().decode("ascii")
        data["credential_key"] = key
        _save(data)
    return key.encode("ascii")


def encrypt_credential(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("credential must be a non-empty string")
    return Fernet(_credential_key()).encrypt(value.encode("utf-8")).decode("ascii")


def decrypt_credential(value: str) -> str:
    try:
        return Fernet(_credential_key()).decrypt(value.encode("ascii")).decode("utf-8")
    except (InvalidToken, UnicodeError, ValueError, TypeError) as exc:
        raise AuthError(500, "The saved provider credential cannot be decrypted.") from exc


def account_exists() -> bool:
    try:
        d = _load()
    except AuthError:
        return True          # unreadable state: keep registration closed
    return bool(d and d.get("email") and d.get("hash"))


def _hash_password(password: str, salt: bytes) -> str:
    return hashlib.scrypt(password.encode(), salt=salt, **_SCRYPT).hex()


def ensure_setup_token() -> tuple[str | None, bool]:
    """The one-time setup token while no admin exists: (token, from_env).

    Generated once and kept in the auth state until the admin registers, so a
    restart before registration keeps the same token."""
    if account_exists():
        return None, False
    env = (os.getenv(SETUP_TOKEN_ENV) or "").strip()
    if env:
        return env, True
    data = _load() or {}
    token = data.get("setup_token")
    if not isinstance(token, str) or not token:
        token = secrets.token_urlsafe(24)
        data["setup_token"] = token
        _save(data)
    return token, False


def register(email: str, password: str, setup_token: str = "") -> str:
    if account_exists():
        raise AuthError(409, "Registration is closed — an admin already exists.")
    expected, _ = ensure_setup_token()
    supplied = setup_token.strip() if isinstance(setup_token, str) else ""
    if not expected or not supplied or not hmac.compare_digest(supplied.encode(), expected.encode()):
        raise AuthError(403, "Invalid setup token. Find it in the API container log (see the README).")
    if not isinstance(email, str) or not isinstance(password, str):
        raise AuthError(422, "Email and password must be text.")
    email = (email or "").strip().lower()
    if not _EMAIL_RE.match(email):
        raise AuthError(422, "Enter a valid email address.")
    if not isinstance(password, str) or len(password) < 10:
        raise AuthError(422, "Password must be at least 10 characters.")
    salt = secrets.token_bytes(16)
    data = _load() or {}
    data.update({
        "email": email,
        "salt": salt.hex(),
        "hash": _hash_password(password, salt),
        "created_at": int(time.time()),
    })
    data.pop("setup_token", None)
    if "secret" not in data:
        data["secret"] = secrets.token_hex(32)
    _save(data)
    return issue_token(email)


# Hashed against when the email is wrong, so a wrong email costs the same
# scrypt run as a wrong password and response time does not reveal the account.
_DUMMY_SALT = secrets.token_bytes(16)


def check_login(email: str, password: str) -> str:
    """Blocking (scrypt): call it from a worker thread."""
    if not isinstance(email, str) or not isinstance(password, str):
        raise AuthError(422, "Email and password must be text.")
    d = _load()
    email = email.strip().lower()
    known = bool(d and d.get("email") == email and d.get("salt"))
    got = _hash_password(password, bytes.fromhex(d["salt"]) if known else _DUMMY_SALT)
    if not known or not hmac.compare_digest(d.get("hash", ""), got):
        raise AuthError(401, "Invalid email or password.")
    return issue_token(email)


def change_password(email: str, current: str, new: str) -> str:
    """Replace the password and revoke every session; returns a fresh token. Blocking."""
    if not isinstance(current, str) or not isinstance(new, str):
        raise AuthError(422, "Passwords must be text.")
    d = _load()
    if not d or d.get("email") != email:
        raise AuthError(401, "Authentication required")
    if not hmac.compare_digest(d.get("hash", ""), _hash_password(current, bytes.fromhex(d["salt"]))):
        raise AuthError(403, "The current password is not correct.")
    if len(new) < 10:
        raise AuthError(422, "Password must be at least 10 characters.")
    salt = secrets.token_bytes(16)
    d.update({"salt": salt.hex(), "hash": _hash_password(new, salt),
              "token_version": int(d.get("token_version", 0)) + 1})
    _save(d)
    return issue_token(email)


def revoke_sessions() -> None:
    """Invalidate every token issued so far (sign out everywhere)."""
    d = _load()
    if not d:
        return
    d["token_version"] = int(d.get("token_version", 0)) + 1
    _save(d)


class Throttle:
    """Failed-attempt limiter for login, registration and password change.

    One counter for the whole console, not per client: the console is meant to
    be reachable from trusted addresses only, and a per-address count can be
    dodged by anything able to pick its source address. After `free` failures
    inside `window` seconds, each new failure doubles a lockout for every
    attempt (30 s, 60 s, ... capped at `cap`). A success clears it. In memory:
    the API runs as one process, and restarting it clears a lockout."""

    def __init__(self, free=10, window=900, cap=900):
        self.free, self.window, self.cap = free, window, cap
        self.fails: list[float] = []
        self.until = 0.0

    def wait(self, now: float | None = None) -> int:
        """Seconds before another attempt is allowed (0 = go)."""
        now = time.time() if now is None else now
        return max(int(self.until - now + 0.999), 0)

    def failure(self, now: float | None = None) -> None:
        now = time.time() if now is None else now
        self.fails = [t for t in self.fails if now - t < self.window][-1000:] + [now]
        if len(self.fails) > self.free:
            self.until = now + min(30 * 2 ** (len(self.fails) - self.free - 1), self.cap)

    def success(self) -> None:
        self.fails = []
        self.until = 0.0


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def issue_token(email: str) -> str:
    version = int((_load() or {}).get("token_version", 0))
    payload = json.dumps({"sub": email, "exp": int(time.time()) + TOKEN_TTL, "ver": version},
                         separators=(",", ":")).encode()
    sig = hmac.new(_secret(), payload, hashlib.sha256).digest()
    return _b64(payload) + "." + _b64(sig)


def verify_token(token: str | None) -> str | None:
    if not token or "." not in token:
        return None
    p, s = token.split(".", 1)
    try:
        payload = _unb64(p)
        sig = _unb64(s)
    except (ValueError, TypeError):
        return None
    expected = hmac.new(_secret(), payload, hashlib.sha256).digest()
    if not hmac.compare_digest(sig, expected):
        return None
    try:
        data = json.loads(payload)
    except ValueError:
        return None
    if int(data.get("exp", 0)) < int(time.time()):
        return None
    # the account could have changed email; only accept the current admin
    d = _load()
    if not d or d.get("email") != data.get("sub"):
        return None
    # sign-out and password change bump the version: older tokens stop working
    if int(data.get("ver", 0)) != int(d.get("token_version", 0)):
        return None
    return data.get("sub")


def append_change(entry: dict) -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    entry = {"ts": int(time.time()), **entry}
    with open(CHANGES_FILE, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, separators=(",", ":")) + "\n")


def read_changes(limit: int = 100) -> list[dict]:
    try:
        with open(CHANGES_FILE, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
    except OSError:
        return []
    out = []
    for ln in lines[-limit:]:
        try:
            out.append(json.loads(ln))
        except ValueError:
            continue
    out.reverse()
    return out
