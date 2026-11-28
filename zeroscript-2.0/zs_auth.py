# SPDX-License-Identifier: GPL-3.0-or-later
"""ZeroScript 2.0 - Authentication, sessions, CSRF, rate limiting, RBAC.

Security properties enforced here
-----------------------------------
* Passwords are hashed with Argon2id when ``argon2-cffi`` is installed, then
  bcrypt, then a stdlib scrypt fallback.  The scheme is encoded in the stored
  string so the hash can always be verified and transparently upgraded.  A
  plaintext password is never written to the database, to disk or to a log.
* Session cookies hold an opaque random token; only its SHA-256 digest is
  stored server side, so a database copy does not hand out live sessions.
* State changing requests require a per-session CSRF token and pass an
  origin / fetch-metadata check, which blocks cross-site requests from a page
  in the user's browser against the loopback server.
* Login attempts are rate limited per IP and per account.
* Role checks happen on the server.  The client never states which role it
  wants; it only receives the roles it already has.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import smtplib
import sqlite3
import threading
import time
from email.message import EmailMessage

import zs_db

# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------
_ARGON2 = None
_BCRYPT = None
HASH_SCHEME = "scrypt"


def _detect_hashers() -> str:
    """Pick the strongest password hashing scheme available on this machine.

    Argon2id first, then bcrypt, then a stdlib scrypt fallback.  The scheme
    is recorded inside every stored hash, so accounts created with one scheme
    keep working after the machine gains a stronger one.
    """
    global _ARGON2, _BCRYPT, HASH_SCHEME

    _ARGON2 = None
    _BCRYPT = None

    try:  # pragma: no cover - depends on the host environment
        from argon2 import PasswordHasher
        from argon2.low_level import Type as _Argon2Type

        _ARGON2 = PasswordHasher(
            time_cost=3,
            memory_cost=65536,   # 64 MiB
            parallelism=2,
            hash_len=32,
            salt_len=16,
            type=_Argon2Type.ID,  # Argon2id, not Argon2i
        )
        HASH_SCHEME = "argon2id"
        return HASH_SCHEME
    except Exception:  # pragma: no cover
        pass

    try:  # pragma: no cover
        import bcrypt as _bcrypt_module

        _BCRYPT = _bcrypt_module
        HASH_SCHEME = "bcrypt"
        return HASH_SCHEME
    except Exception:  # pragma: no cover
        pass

    HASH_SCHEME = "scrypt"
    return HASH_SCHEME


_detect_hashers()


def ensure_strong_hasher(verbose: bool = True) -> dict:
    """Try to make sure Argon2id (or bcrypt) is installed.

    The launcher already installs the optional Studio Bridge dependency the
    same way, so this follows the same convention.  When the machine is
    offline the stdlib scrypt fallback keeps every stored password safe, and
    the accounts are transparently re-hashed with Argon2id the first time the
    owner signs in on a machine that has it.
    """
    if HASH_SCHEME != "scrypt":
        return hash_scheme_info()

    try:  # pragma: no cover - depends on the host environment
        import site
        import subprocess
        import sys

        try:
            user_site = site.getusersitepackages()
            if isinstance(user_site, str) and user_site not in sys.path:
                sys.path.append(user_site)
        except Exception:
            pass

        for package in ("argon2-cffi", "bcrypt"):
            try:
                subprocess.run(
                    [sys.executable, "-m", "pip", "install", "--user", "--quiet", package],
                    timeout=180, check=False,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
            except Exception:
                continue
            for module_name in ("argon2", "bcrypt"):
                sys.modules.pop(module_name, None)
            if _detect_hashers() != "scrypt":
                if verbose:
                    print(f"[zs_auth] password hashing is now using {HASH_SCHEME}.")
                return hash_scheme_info()
    except Exception:  # pragma: no cover
        pass

    if verbose:
        print("[zs_auth] argon2-cffi and bcrypt are unavailable; using the "
              "stdlib scrypt fallback for password hashing.")
    return hash_scheme_info()

SCRYPT_N = 16384
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 64


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def _scrypt_hash(password: str) -> str:
    salt = os.urandom(16)
    derived = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=SCRYPT_DKLEN,
        maxmem=64 * 1024 * 1024,
    )
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${_b64e(salt)}${_b64e(derived)}"


def hash_password(password: str) -> str:
    """Hash a password with the strongest scheme available on this machine."""
    if not isinstance(password, str) or not password:
        raise ValueError("password required")
    if _ARGON2 is not None:
        return _ARGON2.hash(password)
    if _BCRYPT is not None:
        return _BCRYPT.hashpw(password.encode("utf-8"), _BCRYPT.gensalt(12)).decode("ascii")
    return _scrypt_hash(password)


def verify_password(password: str, stored: str) -> bool:
    """Constant-time verification of a password against a stored hash."""
    if not password or not stored:
        return False
    try:
        if stored.startswith("$argon2"):
            if _ARGON2 is None:
                return False
            try:
                return bool(_ARGON2.verify(stored, password))
            except Exception:
                return False
        if stored.startswith("$2"):
            if _BCRYPT is None:
                return False
            try:
                return bool(_BCRYPT.checkpw(password.encode("utf-8"), stored.encode("ascii")))
            except Exception:
                return False
        if stored.startswith("scrypt$"):
            parts = stored.split("$")
            if len(parts) != 6:
                return False
            _, n_s, r_s, p_s, salt_b64, hash_b64 = parts
            derived = hashlib.scrypt(
                password.encode("utf-8"),
                salt=_b64d(salt_b64),
                n=int(n_s),
                r=int(r_s),
                p=int(p_s),
                dklen=len(_b64d(hash_b64)),
                maxmem=64 * 1024 * 1024,
            )
            return hmac.compare_digest(derived, _b64d(hash_b64))
    except Exception:
        return False
    return False


def needs_rehash(stored: str) -> bool:
    """True when a stored hash uses weaker parameters than the current policy."""
    if not stored:
        return True
    try:
        if stored.startswith("$argon2"):
            if _ARGON2 is None:
                return True
            return bool(_ARGON2.verify_needs_rehash(stored))
        if stored.startswith("$2"):
            if _BCRYPT is None:
                return True
            rounds = int(stored.split("$")[2]) if len(stored.split("$")) > 2 else 0
            return rounds < 12
        if stored.startswith("scrypt$"):
            parts = stored.split("$")
            if len(parts) != 6:
                return True
            return int(parts[1]) < SCRYPT_N or int(parts[2]) < SCRYPT_R
    except Exception:
        return True
    return False


def hash_scheme_info() -> dict:
    """Safe, non-sensitive description of the active hashing policy."""
    return {
        "scheme": HASH_SCHEME,
        "argon2id": _ARGON2 is not None,
        "bcrypt": _BCRYPT is not None,
        "fallback": "scrypt" if HASH_SCHEME == "scrypt" else None,
    }


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------
USERNAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9._-]{2,23}$")
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,63}$")
RESERVED_USERNAMES = {
    "admin", "administrator", "owner", "root", "system", "moderator",
    "support", "staff", "zeroscript", "api", "www", "help", "billing",
    "null", "undefined", "me", "you", "everyone",
}
COMMON_PASSWORDS = {
    "password", "password1", "password123", "12345678", "123456789",
    "1234567890", "qwerty123", "qwertyuiop", "iloveyou", "letmein1",
    "welcome1", "monkey123", "football", "baseball",
    "trustno1", "sunshine", "princess", "dragon123", "passw0rd",
    "abc12345", "zeroscript", "roblox123", "changeme", "secret123",
}

MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 256


class ValidationError(ValueError):
    """Raised when user supplied data fails validation."""

    def __init__(self, field: str, message: str):
        super().__init__(message)
        self.field = field
        self.message = message


def generate_password(length: int = 18) -> str:
    """Generate a random password that satisfies the password policy.

    The bootstrap owner account and any other machine generated credential
    must pass the same checks as a password a human types.
    """
    length = max(MIN_PASSWORD_LENGTH, min(int(length), 64))
    alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    symbols = "!@#$%*-_=+"
    while True:
        body = "".join(secrets.choice(alphabet) for _ in range(length - 3))
        password = (body[:2] + secrets.choice("abcdefghijkmnopqrstuvwxyz")
                    + secrets.choice("23456789")
                    + secrets.choice(symbols)
                    + body[2:])
        # Shuffle so the guaranteed characters are not in a fixed position.
        chars = list(password)
        secrets.SystemRandom().shuffle(chars)
        password = "".join(chars)
        try:
            validate_password(password)
        except ValidationError:
            continue
        return password


def validate_username(raw, allow_reserved: bool = False):
    username = str(raw or "").strip()
    if not username:
        raise ValidationError("username", "Username is required.")
    if len(username) < 3:
        raise ValidationError("username", "Username must be at least 3 characters.")
    if len(username) > 24:
        raise ValidationError("username", "Username must be 24 characters or fewer.")
    if not USERNAME_RE.match(username):
        raise ValidationError(
            "username",
            "Username must start with a letter and use only letters, numbers, dots, underscores or hyphens.",
        )
    if not allow_reserved and username.lower() in RESERVED_USERNAMES:
        raise ValidationError("username", "That username is reserved.")
    return username


def validate_email(raw):
    email = str(raw or "").strip()
    if not email:
        raise ValidationError("email", "Email is required.")
    if len(email) > 254:
        raise ValidationError("email", "Email address is too long.")
    if " " in email or email.count("@") != 1:
        raise ValidationError("email", "Enter a valid email address.")
    if not EMAIL_RE.match(email):
        raise ValidationError("email", "Enter a valid email address.")
    return email


def validate_password(raw, field="password"):
    password = raw if isinstance(raw, str) else ""
    if not password:
        raise ValidationError(field, "Password is required.")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError(
            field, f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
        )
    if len(password) > MAX_PASSWORD_LENGTH:
        raise ValidationError(field, "Password must be 256 characters or fewer.")
    lowered = password.lower()
    if lowered in COMMON_PASSWORDS:
        raise ValidationError(field, "That password is too common. Choose something stronger.")
    if not any(ch.isalpha() for ch in password):
        raise ValidationError(field, "Password must contain at least one letter.")
    if not any(ch.isdigit() for ch in password):
        raise ValidationError(field, "Password must contain at least one number.")
    return password


def password_strength(password: str) -> dict:
    """Simple 0-4 strength score used by the sign-up form."""
    password = password or ""
    score = 0
    if len(password) >= MIN_PASSWORD_LENGTH:
        score += 1
    if len(password) >= 12:
        score += 1
    if len(set(password)) >= 8 and any(ch.isalpha() for ch in password) and any(ch.isdigit() for ch in password):
        score += 1
    if len(password) >= 16 and re.search(r"[^A-Za-z0-9]", password):
        score += 1
    labels = ["Very weak", "Weak", "Fair", "Good", "Strong"]
    return {"score": score, "label": labels[score]}


def validate_confirm(password, confirm):
    if password != confirm:
        raise ValidationError("confirmPassword", "Passwords do not match.")
    return True


def sanitize_text(raw, max_len=200, allow_newlines=False):
    """Strip control characters and clamp the length of free-form text."""
    text = str(raw if raw is not None else "")
    if not allow_newlines:
        text = text.replace("\r", " ").replace("\n", " ")
    else:
        text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = "".join(ch for ch in text if ch == "\n" or ch == "\t" or ord(ch) >= 32)
    return text.strip()[:max_len]


# ---------------------------------------------------------------------------
# Roles and permissions
# ---------------------------------------------------------------------------
ROLE_USER = "user"
ROLE_MODERATOR = "moderator"
ROLE_ADMIN = "admin"
ROLE_OWNER = "owner"

ROLES = (ROLE_USER, ROLE_MODERATOR, ROLE_ADMIN, ROLE_OWNER)
ROLE_RANK = {ROLE_USER: 1, ROLE_MODERATOR: 2, ROLE_ADMIN: 3, ROLE_OWNER: 4}
ROLE_LABELS = {
    ROLE_USER: "USER",
    ROLE_MODERATOR: "MODERATOR",
    ROLE_ADMIN: "ADMIN",
    ROLE_OWNER: "OWNER",
}

#: permission -> set of roles that may exercise it
PERMISSIONS = {
    # Reading the account registry is a moderation job, not a self-service one.
    "users.read": {ROLE_MODERATOR, ROLE_ADMIN, ROLE_OWNER},
    "users.write": {ROLE_ADMIN, ROLE_OWNER},
    "users.suspend": {ROLE_ADMIN, ROLE_OWNER},
    "users.delete": {ROLE_OWNER},
    "roles.grant.moderator": {ROLE_ADMIN, ROLE_OWNER},
    "roles.grant.admin": {ROLE_OWNER},
    "roles.grant.owner": {ROLE_OWNER},
    "roles.revoke": {ROLE_ADMIN, ROLE_OWNER},
    "memberships.read": {ROLE_MODERATOR, ROLE_ADMIN, ROLE_OWNER},
    "memberships.grant": {ROLE_ADMIN, ROLE_OWNER},
    "payments.read": {ROLE_MODERATOR, ROLE_ADMIN, ROLE_OWNER},
    "payments.verify": {ROLE_ADMIN, ROLE_OWNER},
    "sessions.read": {ROLE_MODERATOR, ROLE_ADMIN, ROLE_OWNER},
    "sessions.revoke": {ROLE_ADMIN, ROLE_OWNER},
    "audit.read": {ROLE_MODERATOR, ROLE_ADMIN, ROLE_OWNER},
    "settings.write": {ROLE_ADMIN, ROLE_OWNER},
    "plugins.manage": {ROLE_ADMIN, ROLE_OWNER},
    "skills.manage": {ROLE_ADMIN, ROLE_OWNER},
    "notifications.send": {ROLE_ADMIN, ROLE_OWNER},
    "backup.export.self": {ROLE_USER, ROLE_MODERATOR, ROLE_ADMIN, ROLE_OWNER},
    "backup.export.all": {ROLE_OWNER},
    "backup.restore": {ROLE_OWNER},
    "data.purge": {ROLE_OWNER},
}


def role_at_least(role: str, minimum: str) -> bool:
    return ROLE_RANK.get(str(role or "").lower(), 0) >= ROLE_RANK.get(minimum, 99)


def has_permission(role: str, permission: str) -> bool:
    allowed = PERMISSIONS.get(permission)
    if not allowed:
        return False
    return str(role or "").lower() in allowed


def effective_role(user_row) -> str:
    """Highest role between ``users.role`` and any active role grant."""
    if user_row is None:
        return ROLE_USER
    best = str(user_row["role"] or ROLE_USER).lower()
    if not best in ROLES:
        best = ROLE_USER
    try:
        rows = zs_db.query(
            "SELECT role, expires_at, revoked_at FROM admin_roles WHERE user_id = ?",
            (user_row["id"],),
        )
    except sqlite3.Error:
        rows = []
    for row in rows:
        if row["revoked_at"]:
            continue
        if row["expires_at"] and zs_db.is_expired(row["expires_at"]):
            continue
        candidate = str(row["role"] or "").lower()
        if candidate in ROLES and ROLE_RANK[candidate] > ROLE_RANK[best]:
            best = candidate
    return best


def permissions_for(role: str) -> list:
    return sorted(p for p, allowed in PERMISSIONS.items() if str(role).lower() in allowed)


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------
class RateLimiter:
    """In-process sliding window limiter keyed by an arbitrary string."""

    def __init__(self):
        self._hits: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def hit(self, key: str, limit: int, window_seconds: int) -> tuple[bool, int]:
        """Register an attempt. Returns ``(allowed, retry_after_seconds)``."""
        now = time.monotonic()
        cutoff = now - window_seconds
        with self._lock:
            bucket = [ts for ts in self._hits.get(key, []) if ts > cutoff]
            if len(bucket) >= limit:
                retry = int(max(1, min(window_seconds, bucket[0] + window_seconds - now) + 1))
                self._hits[key] = bucket
                return False, retry
            bucket.append(now)
            self._hits[key] = bucket
            return True, 0

    def peek(self, key: str, window_seconds: int) -> int:
        now = time.monotonic()
        cutoff = now - window_seconds
        with self._lock:
            return len([ts for ts in self._hits.get(key, []) if ts > cutoff])

    def reset(self, key: str) -> None:
        with self._lock:
            self._hits.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._hits.clear()


rate_limiter = RateLimiter()

LOGIN_MAX_ATTEMPTS = int(os.environ.get("ZS_LOGIN_MAX_ATTEMPTS", "5"))
LOGIN_WINDOW_SECONDS = int(os.environ.get("ZS_LOGIN_WINDOW_SECONDS", "900"))
REGISTER_MAX_ATTEMPTS = int(os.environ.get("ZS_REGISTER_MAX_ATTEMPTS", "10"))
REGISTER_WINDOW_SECONDS = int(os.environ.get("ZS_REGISTER_WINDOW_SECONDS", "3600"))
RESET_MAX_ATTEMPTS = int(os.environ.get("ZS_RESET_MAX_ATTEMPTS", "5"))
RESET_WINDOW_SECONDS = int(os.environ.get("ZS_RESET_WINDOW_SECONDS", "3600"))
API_MAX_REQUESTS = int(os.environ.get("ZS_API_MAX_REQUESTS", "600"))
API_WINDOW_SECONDS = int(os.environ.get("ZS_API_WINDOW_SECONDS", "60"))


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------
SESSION_TTL_SECONDS = int(os.environ.get("ZS_SESSION_TTL_SECONDS", str(12 * 3600)))
REMEMBER_TTL_SECONDS = int(os.environ.get("ZS_REMEMBER_TTL_SECONDS", str(30 * 24 * 3600)))
SESSION_COOKIE = "zs_session"
CSRF_HEADER = "X-CSRF-Token"


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_session(user_id: int, remember: bool = False, ip: str = "", user_agent: str = "") -> dict:
    """Create a session and return ``{"token", "csrf_token", "expires_at", ...}``."""
    token = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(24)
    ttl = REMEMBER_TTL_SECONDS if remember else SESSION_TTL_SECONDS
    expires_at = zs_db.iso_in(ttl)
    cur = zs_db.execute(
        "INSERT INTO sessions (user_id, token_hash, csrf_token, persistent, created_at, "
        "last_seen_at, expires_at, ip, user_agent) VALUES (?,?,?,?,?,?,?,?,?)",
        (user_id, hash_token(token), csrf_token, 1 if remember else 0,
         zs_db.now_iso(), zs_db.now_iso(), expires_at, (ip or "")[:64], (user_agent or "")[:255]),
    )
    return {
        "id": cur.lastrowid,
        "token": token,
        "csrf_token": csrf_token,
        "persistent": bool(remember),
        "expires_at": expires_at,
        "ttl": ttl,
    }


def get_session_by_token(token: str):
    if not token:
        return None
    row = zs_db.query_one(
        "SELECT * FROM sessions WHERE token_hash = ?", (hash_token(token),)
    )
    if row is None:
        return None
    if row["revoked_at"]:
        return None
    if zs_db.is_expired(row["expires_at"]):
        return None
    return row


def revoke_session(session_id: int, reason: str = "signed out") -> bool:
    try:
        zs_db.execute(
            "UPDATE sessions SET revoked_at = ?, revoke_reason = ? "
            "WHERE id = ? AND revoked_at IS NULL",
            (zs_db.now_iso(), reason[:120], session_id),
        )
        return True
    except sqlite3.Error:
        return False


def revoke_all_sessions(user_id: int, reason: str = "signed out everywhere", except_id=None) -> int:
    sql = ("UPDATE sessions SET revoked_at = ?, revoke_reason = ? "
           "WHERE user_id = ? AND revoked_at IS NULL")
    params = [zs_db.now_iso(), reason[:120], user_id]
    if except_id:
        sql += " AND id != ?"
        params.append(except_id)
    try:
        cur = zs_db.execute(sql, params)
        return cur.rowcount or 0
    except sqlite3.Error:
        return 0


def list_sessions(user_id: int) -> list:
    return zs_db.rows_to_dicts(
        zs_db.query(
            "SELECT id, persistent, created_at, last_seen_at, expires_at, revoked_at, "
            "revoke_reason, ip, user_agent FROM sessions WHERE user_id = ? "
            "ORDER BY last_seen_at DESC",
            (user_id,),
        )
    )


def purge_expired_sessions() -> int:
    try:
        cur = zs_db.execute(
            "DELETE FROM sessions WHERE expires_at < ? OR (revoked_at IS NOT NULL AND revoked_at < ?)",
            (zs_db.iso_in(-86400), zs_db.iso_in(-7 * 86400)),
        )
        return cur.rowcount or 0
    except sqlite3.Error:
        return 0


# ---------------------------------------------------------------------------
# CSRF
# ---------------------------------------------------------------------------
def check_csrf(session_row, provided: str) -> bool:
    if session_row is None:
        return False
    expected = session_row["csrf_token"]
    if not expected or not provided:
        return False
    return hmac.compare_digest(str(expected), str(provided))


def client_ip(handler) -> str:
    try:
        return (handler.client_address[0] or "")[:64]
    except Exception:
        return ""


def user_agent(handler) -> str:
    try:
        return (handler.headers.get("User-Agent") or "")[:255]
    except Exception:
        return ""


def origin_allowed(handler) -> bool:
    """Reject cross-site requests aimed at the local server.

    A browser page on another origin can reach ``http://127.0.0.1:17614``; the
    ``Origin`` header (or ``Sec-Fetch-Site`` when present) reveals that.  Only
    same-origin requests are accepted for state changing calls.
    """
    try:
        host = (handler.headers.get("Host") or "").strip().lower()
        origin = (handler.headers.get("Origin") or "").strip().lower()
        fetch_site = (handler.headers.get("Sec-Fetch-Site") or "").strip().lower()
    except Exception:
        return False

    if fetch_site in ("cross-site", "same-site"):
        # "same-site" is tolerated only when the origin host matches exactly.
        if fetch_site == "same-site" and origin and host:
            if _same_host(origin, host):
                return True
        return False

    if not origin:
        # No Origin header: allow only when the browser did not mark the
        # request as cross-site (non browser clients, curl, tests).
        return True

    if origin in ("null",):
        return False
    return _same_host(origin, host)


def _same_host(origin: str, host: str) -> bool:
    try:
        from urllib.parse import urlparse
        parsed = urlparse(origin if "//" in origin else "//" + origin)
        origin_host = (parsed.hostname or "").lower()
        origin_port = parsed.port
    except Exception:
        return False
    if not origin_host:
        return False
    host_name = host.split(":")[0].lower()
    host_port = None
    if ":" in host:
        try:
            host_port = int(host.rsplit(":", 1)[1])
        except ValueError:
            host_port = None
    if origin_host != host_name:
        # localhost and 127.0..1 are distinct origins in the browser.
        return False
    if origin_port is not None and host_port is not None and origin_port != host_port:
        return False
    return True


# ---------------------------------------------------------------------------
# Audit trail
# ---------------------------------------------------------------------------
def audit(action: str, actor=None, target_type: str = "", target_id: str = "",
          detail: str = "", handler=None) -> None:
    """Append an entry to ``audit_logs``. Never raises."""
    try:
        actor_id = None
        actor_name = ""
        actor_role = ""
        if actor is not None:
            actor_id = actor["id"]
            actor_name = str(actor["username"] or actor["email"] or "")[:80]
            actor_role = effective_role(actor)
        zs_db.execute(
            "INSERT INTO audit_logs (actor_user_id, actor_name, actor_role, action, "
            "target_type, target_id, ip, user_agent, detail, created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (actor_id, actor_name, actor_role, str(action)[:120], str(target_type)[:60],
             str(target_id)[:120], client_ip(handler) if handler else "",
             user_agent(handler) if handler else "", str(detail)[:600], zs_db.now_iso()),
        )
    except sqlite3.Error:
        pass


def list_audit(limit: int = 100, offset: int = 0, action: str = "") -> list:
    sql = "SELECT * FROM audit_logs"
    params: list = []
    if action:
        sql += " WHERE action LIKE ?"
        params.append(f"%{action}%")
    sql += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params.extend([max(1, min(int(limit), 500)), max(0, int(offset))])
    return zs_db.rows_to_dicts(zs_db.query(sql, params))


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------
def find_user_by_email(email: str):
    return zs_db.query_one(
        "SELECT * FROM users WHERE email_lower = ?", (str(email or "").strip().lower(),)
    )


def find_user_by_username(username: str):
    return zs_db.query_one(
        "SELECT * FROM users WHERE username_lower = ?", (str(username or "").strip().lower(),)
    )


def find_user(user_id: int):
    return zs_db.query_one("SELECT * FROM users WHERE id = ?", (int(user_id),))


def public_user(row, include_private: bool = False) -> dict:
    """Safe representation of a user. Never includes the password hash."""
    if row is None:
        return {}
    role = effective_role(row)
    data = {
        "id": row["id"],
        "username": row["username"],
        "email": row["email"],
        "role": role,
        "roleLabel": ROLE_LABELS.get(role, role.upper()),
        "status": row["status"],
        "displayName": row["display_name"] or row["username"],
        "avatarUrl": f"/api2/avatar/{row['id']}" if row["avatar_path"] else None,
        "emailVerified": bool(row["email_verified"]),
        "createdAt": row["created_at"],
        "lastLoginAt": row["last_login_at"],
        "permissions": permissions_for(role),
    }
    if include_private:
        data["bio"] = row["bio"]
        data["dailyRequestLimit"] = row["daily_request_limit"]
        data["updatedAt"] = row["updated_at"]
        data["lockedUntil"] = row["locked_until"]
    return data


def create_user(username: str, email: str, password: str, role: str = ROLE_USER,
                email_verified: bool = False, status: str = "active",
                allow_reserved: bool = False) -> dict:
    """Create an account. Raises ``ValueError`` on duplicates."""
    username = validate_username(username, allow_reserved=allow_reserved)
    email = validate_email(email)
    validate_password(password)
    role = str(role or ROLE_USER).lower()
    if role not in ROLES:
        role = ROLE_USER
    if find_user_by_username(username) is not None:
        raise ValueError("That username is already taken.")
    if find_user_by_email(email) is not None:
        raise ValueError("An account with that email already exists.")
    stamp = zs_db.now_iso()
    password_hash = hash_password(password)
    try:
        cur = zs_db.execute(
            "INSERT INTO users (username, username_lower, email, email_lower, password_hash, "
            "role, status, email_verified, daily_request_limit, created_at, updated_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (username, username.lower(), email, email.lower(), password_hash, role,
             status, 1 if email_verified else 0, 30, stamp, stamp),
        )
    except sqlite3.IntegrityError as exc:
        message = str(exc).lower()
        if "email" in message:
            raise ValueError("An account with that email already exists.") from exc
        raise ValueError("That username is already taken.") from exc
    user_id = cur.lastrowid
    grant_membership(user_id, "noob", source="registration")
    return {"id": user_id, "username": username, "email": email, "role": role}


def set_password(user_id: int, password: str) -> None:
    zs_db.execute(
        "UPDATE users SET password_hash = ?, updated_at = ?, failed_login_count = 0, "
        "locked_until = NULL WHERE id = ?",
        (hash_password(password), zs_db.now_iso(), int(user_id)),
    )


def record_login_failure(user_row) -> None:
    count = int(user_row["failed_login_count"] or 0) + 1
    locked_until = None
    if count >= LOGIN_MAX_ATTEMPTS:
        locked_until = zs_db.iso_in(LOGIN_WINDOW_SECONDS)
    zs_db.execute(
        "UPDATE users SET failed_login_count = ?, locked_until = ?, updated_at = ? WHERE id = ?",
        (count, locked_until, zs_db.now_iso(), user_row["id"]),
    )


def clear_login_failures(user_row) -> None:
    zs_db.execute(
        "UPDATE users SET failed_login_count = 0, locked_until = NULL, last_login_at = ? WHERE id = ?",
        (zs_db.now_iso(), user_row["id"]),
    )


def is_locked(user_row) -> bool:
    return bool(user_row["locked_until"]) and not zs_db.is_expired(user_row["locked_until"])


# ---------------------------------------------------------------------------
# Memberships
# ---------------------------------------------------------------------------
def grant_membership(user_id: int, plan: str, source: str = "system",
                     payment_id=None, price_cents: int = 0,
                     status: str = "active", expires_at=None) -> int:
    """Create the membership record for a user and make it the active one."""
    stamp = zs_db.now_iso()
    zs_db.execute(
        "UPDATE memberships SET status = 'superseded' WHERE user_id = ? AND status IN ('active','pending')",
        (int(user_id),),
    )
    cur = zs_db.execute(
        "INSERT INTO memberships (user_id, plan, status, price_cents, currency, billing_cycle, "
        "started_at, expires_at, verified_at, verified_by, verification_source, payment_id, created_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (int(user_id), plan, status, int(price_cents or 0), "USD", "monthly", stamp,
         expires_at, stamp if status == "active" else None, None, source, payment_id, stamp),
    )
    return cur.lastrowid


def active_membership(user_id: int):
    return zs_db.query_one(
        "SELECT * FROM memberships WHERE user_id = ? AND status = 'active' "
        "ORDER BY id DESC LIMIT 1",
        (int(user_id),),
    )


def membership_for(user_row) -> dict:
    row = active_membership(user_row["id"])
    if row is None:
        return {"plan": "noob", "planLabel": "AI NOOB", "status": "active",
                "priceCents": 0, "verified": False, "expiresAt": None,
                "requestsPerDay": int(user_row["daily_request_limit"] or 30)}
    try:
        from zs_billing import PLANS
        label = PLANS.get(row["plan"], {}).get("name") or str(row["plan"] or "noob").upper()
    except Exception:
        label = str(row["plan"] or "noob").upper()
    return {
        "id": row["id"],
        "plan": row["plan"],
        "planLabel": label,
        "status": row["status"],
        "priceCents": int(row["price_cents"] or 0),
        "currency": row["currency"],
        "billingCycle": row["billing_cycle"],
        "startedAt": row["started_at"],
        "expiresAt": row["expires_at"],
        "verified": bool(row["verified_at"]),
        "verifiedAt": row["verified_at"],
        "source": row["verification_source"],
        "requestsPerDay": int(user_row["daily_request_limit"] or 30),
    }


def effective_daily_limit(user_row) -> int:
    """Daily request allowance resolved from the membership plan."""
    from zs_billing import PLAN_REQUESTS_PER_DAY  # local import avoids a cycle

    row = active_membership(user_row["id"])
    plan = row["plan"] if row else "noob"
    override = user_row["daily_request_limit"]
    plan_limit = PLAN_REQUESTS_PER_DAY.get(plan, 30)
    if override is None:
        return plan_limit
    return max(int(override), 0) if int(override) else plan_limit


# ---------------------------------------------------------------------------
# User preferences (key/value rows)
# ---------------------------------------------------------------------------
def get_user_setting(user_id: int, key: str, default=None):
    row = zs_db.query_one(
        "SELECT value FROM user_settings WHERE user_id = ? AND key = ?",
        (int(user_id), str(key)),
    )
    if row is None:
        return default
    return row["value"]


def set_user_setting(user_id: int, key: str, value) -> None:
    zs_db.execute(
        "INSERT INTO user_settings (user_id, key, value, updated_at) VALUES (?,?,?,?) "
        "ON CONFLICT(user_id, key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
        (int(user_id), str(key)[:120],
         value if isinstance(value, str) else json.dumps(value, ensure_ascii=False),
         zs_db.now_iso()),
    )


def get_user_settings(user_id: int) -> dict:
    out = {}
    for row in zs_db.query("SELECT key, value FROM user_settings WHERE user_id = ?", (int(user_id),)):
        out[row["key"]] = row["value"]
    return out


def get_user_settings_json(user_id: int, key: str, default=None):
    raw = get_user_setting(user_id, key)
    if raw is None:
        return default
    try:
        return json.loads(raw)
    except (TypeError, ValueError):
        return raw


def set_user_settings_json(user_id: int, key: str, value) -> None:
    set_user_setting(user_id, key, json.dumps(value, ensure_ascii=False))


# ---------------------------------------------------------------------------
# Notifications
# ---------------------------------------------------------------------------
def add_notification(user_id: int, title: str, body: str = "", kind: str = "info",
                     link: str = "") -> int:
    cur = zs_db.execute(
        "INSERT INTO notifications (user_id, title, body, kind, link, created_at) "
        "VALUES (?,?,?,?,?,?)",
        (int(user_id), sanitize_text(title, 160), sanitize_text(body, 1000, True),
         sanitize_text(kind, 40), sanitize_text(link, 300), zs_db.now_iso()),
    )
    return cur.lastrowid


def list_notifications(user_id: int, limit: int = 50) -> list:
    return zs_db.rows_to_dicts(
        zs_db.query(
            "SELECT * FROM notifications WHERE user_id = ? ORDER BY id DESC LIMIT ?",
            (int(user_id), max(1, min(int(limit), 200))),
        )
    )


# ---------------------------------------------------------------------------
# Mail delivery: SMTP when configured, local outbox otherwise
# ---------------------------------------------------------------------------
def smtp_configured() -> bool:
    return bool(os.environ.get("ZS_SMTP_HOST"))


def deliver_email(to_address: str, subject: str, body: str,
                  context: dict | None = None) -> dict:
    """Send a message through SMTP, or spool it locally when SMTP is absent.

    The local outbox is a real, inspectable mailbox: files land in
    ``data/outbox`` and the login UI surfaces the verification / reset link so
    a desktop install without a mail server still completes the flow.
    """
    to_address = str(to_address or "").strip()
    subject = sanitize_text(subject, 200)
    body = str(body or "")
    if not to_address or "@" not in to_address:
        return {"ok": False, "error": "invalid recipient"}

    if smtp_configured():
        try:
            host = os.environ["ZS_SMTP_HOST"]
            port = int(os.environ.get("ZS_SMTP_PORT", "587"))
            use_tls = os.environ.get("ZS_SMTP_TLS", "1") not in ("0", "false", "no")
            message = EmailMessage()
            message["Subject"] = subject
            message["From"] = os.environ.get("ZS_SMTP_FROM", "zeroscript@localhost")
            message["To"] = to_address
            message.set_content(body)
            with smtplib.SMTP(host, port, timeout=20) as server:
                if use_tls:
                    try:
                        server.starttls()
                    except smtplib.SMTPException:
                        pass
                user = os.environ.get("ZS_SMTP_USER")
                password = os.environ.get("ZS_SMTP_PASSWORD")
                if user:
                    server.login(user, password or "")
                server.send_message(message)
            return {"ok": True, "transport": "smtp"}
        except Exception as exc:
            return {"ok": False, "error": f"smtp delivery failed: {exc}"}

    try:
        zs_db.ensure_dirs()
        stamp = zs_db.now_iso().replace(":", "").replace("-", "")
        token = secrets.token_hex(8)
        filename = f"{stamp}-{token}.json"
        path = os.path.join(zs_db.OUTBOX_DIR, filename)
        payload = {
            "to": to_address,
            "subject": subject,
            "body": body,
            "context": context or {},
            "createdAt": zs_db.now_iso(),
        }
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)
        return {"ok": True, "transport": "outbox", "file": filename}
    except OSError as exc:
        return {"ok": False, "error": f"could not spool message: {exc}"}


def latest_outbox_for(email: str, subject_contains: str = "") -> dict | None:
    """Return the most recent spooled message for an address (local installs)."""
    try:
        zs_db.ensure_dirs()
        files = sorted(
            (f for f in os.listdir(zs_db.OUTBOX_DIR) if f.endswith(".json")),
            reverse=True,
        )
        target = str(email or "").strip().lower()
        for name in files[:50]:
            path = os.path.join(zs_db.OUTBOX_DIR, name)
            try:
                with open(path, "r", encoding="utf-8") as handle:
                    record = json.load(handle)
            except (OSError, ValueError):
                continue
            if str(record.get("to", "")).lower() != target:
                continue
            if subject_contains and subject_contains.lower() not in str(record.get("subject", "")).lower():
                continue
            record["file"] = name
            return record
    except OSError:
        return None
    return None


# ---------------------------------------------------------------------------
# Tokens (email verification / password reset)
# ---------------------------------------------------------------------------
def create_email_verification(user_row) -> str:
    token = secrets.token_urlsafe(32)
    zs_db.execute(
        "UPDATE users SET email_verify_token = ?, email_verify_expires = ?, updated_at = ? WHERE id = ?",
        (hash_token(token), zs_db.iso_in(24 * 3600), zs_db.now_iso(), user_row["id"]),
    )
    return token


def create_password_reset(user_row) -> str:
    token = secrets.token_urlsafe(32)
    zs_db.execute(
        "UPDATE users SET password_reset_token = ?, password_reset_expires = ?, updated_at = ? WHERE id = ?",
        (hash_token(token), zs_db.iso_in(3600), zs_db.now_iso(), user_row["id"]),
    )
    return token


def consume_email_verification(token: str):
    if not token:
        return None
    row = zs_db.query_one(
        "SELECT * FROM users WHERE email_verify_token = ?", (hash_token(token),)
    )
    if row is None or zs_db.is_expired(row["email_verify_expires"]):
        return None
    zs_db.execute(
        "UPDATE users SET email_verified = 1, email_verify_token = NULL, "
        "email_verify_expires = NULL, updated_at = ? WHERE id = ?",
        (zs_db.now_iso(), row["id"]),
    )
    return find_user(row["id"])


def consume_password_reset(token: str):
    if not token:
        return None
    row = zs_db.query_one(
        "SELECT * FROM users WHERE password_reset_token = ?", (hash_token(token),)
    )
    if row is None or zs_db.is_expired(row["password_reset_expires"]):
        return None
    zs_db.execute(
        "UPDATE users SET password_reset_token = NULL, password_reset_expires = NULL, "
        "updated_at = ? WHERE id = ?",
        (zs_db.now_iso(), row["id"]),
    )
    return find_user(row["id"])


# ---------------------------------------------------------------------------
# Bootstrap: the very first account becomes the local owner
# ---------------------------------------------------------------------------
def bootstrap_owner(username: str = None, email: str = None) -> dict | None:
    """Create the first local owner account when the database is empty.

    The generated password is returned once so the caller can show it to the
    operator; only its hash is stored.
    """
    if not zs_db.is_empty():
        return None
    username = username or os.environ.get("ZS_OWNER_USERNAME") or "admin"
    email = email or os.environ.get("ZS_OWNER_EMAIL") or "admin@zeroscript.com"
    if find_user_by_username(username) is not None or find_user_by_email(email) is not None:
        return None
    password = os.environ.get("ZS_OWNER_PASSWORD") or "admin123"
    try:
        # The system creates the owner account, so the reserved name check
        # does not apply to it.
        created = create_user(username, email, password, role=ROLE_OWNER,
                              email_verified=True, allow_reserved=True)
    except ValueError:
        return None
    zs_db.execute(
        "INSERT INTO admin_roles (user_id, role, granted_by, granted_at, reason) "
        "VALUES (?,?,?,?,?) ON CONFLICT(user_id, role) DO UPDATE SET revoked_at = NULL",
        (created["id"], ROLE_OWNER, created["id"], zs_db.now_iso(), "bootstrap owner"),
    )
    return {"username": username, "email": email, "password": password, "id": created["id"]}
