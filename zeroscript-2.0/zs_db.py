# SPDX-License-Identifier: GPL-3.0-or-later
"""ZeroScript 2.0 - Persistent SQLite data layer.

Single source of truth for accounts, sessions, projects, chat history,
preferences, memberships and administrative records.

Design notes
------------
* The server is a ``ThreadingHTTPServer``, so every request runs on its own
  thread.  SQLite connections are not shareable across threads by default, so
  a single connection is guarded by a re-entrant lock.  WAL journalling keeps
  reads fast and the busy timeout absorbs the occasional writer collision.
* Every statement is parameterised.  No string interpolation of user input
  ever reaches SQL.
* The schema is created idempotently (``IF NOT EXISTS``) and the schema
  version is tracked in ``schema_meta`` so future migrations can be applied
  without destroying existing local data.
* Database credentials are never exposed: the database is a local file, the
  path is never returned to the browser, and no environment value is echoed.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))

#: Directory holding the local database, avatars and the outgoing mail spool.
DATA_DIR = os.environ.get("ZS_DATA_DIR") or os.path.join(HERE, "data")
#: SQLite file.  Overridable for tests and portable installs.
DB_PATH = os.environ.get("ZS_DB_PATH") or os.path.join(DATA_DIR, "zeroscript.db")
#: Where verification / password-reset messages are spooled when no SMTP
#: server is configured.
OUTBOX_DIR = os.path.join(DATA_DIR, "outbox")
#: Where uploaded profile pictures are stored.
AVATAR_DIR = os.path.join(DATA_DIR, "avatars")

SCHEMA_VERSION = 1

_lock = threading.RLock()
_conn: sqlite3.Connection | None = None


# ---------------------------------------------------------------------------
# Time helpers
# ---------------------------------------------------------------------------
def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def now_iso() -> str:
    """UTC timestamp, second resolution, e.g. ``2026-01-31T12:00:00Z``."""
    return utcnow().replace(microsecond=0).isoformat().replace("+00:00", "Z")


def iso_in(delta_seconds: float) -> str:
    return (utcnow() + timedelta(seconds=delta_seconds)).replace(
        microsecond=0).isoformat().replace("+00:00", "Z")


def parse_iso(value):
    if not value:
        return None
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def is_expired(value) -> bool:
    parsed = parse_iso(value)
    if parsed is None:
        return True
    return parsed <= utcnow()


# ---------------------------------------------------------------------------
# Connection management
# ---------------------------------------------------------------------------
def ensure_dirs() -> None:
    for path in (DATA_DIR, OUTBOX_DIR, AVATAR_DIR):
        try:
            os.makedirs(path, exist_ok=True)
        except OSError:
            pass


def connect() -> sqlite3.Connection:
    """Return the shared connection, creating it on first use."""
    global _conn
    with _lock:
        if _conn is not None:
            return _conn
        ensure_dirs()
        conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=15.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA busy_timeout = 15000")
        try:
            conn.execute("PRAGMA journal_mode = WAL")
        except sqlite3.DatabaseError:
            pass
        conn.execute("PRAGMA synchronous = NORMAL")
        _conn = conn
        return conn


def close() -> None:
    """Close the shared connection (used by tests)."""
    global _conn
    with _lock:
        if _conn is not None:
            try:
                _conn.close()
            finally:
                _conn = None


# ---------------------------------------------------------------------------
# Query helpers
# ---------------------------------------------------------------------------
def query(sql: str, params=()) -> list:
    with _lock:
        cur = connect().execute(sql, params)
        try:
            return cur.fetchall()
        finally:
            cur.close()


def query_one(sql: str, params=()):
    rows = query(sql, params)
    return rows[0] if rows else None


def execute(sql: str, params=()) -> sqlite3.Cursor:
    with _lock:
        conn = connect()
        cur = conn.execute(sql, params)
        conn.commit()
        return cur


def execute_many(sql: str, seq) -> None:
    with _lock:
        conn = connect()
        conn.executemany(sql, seq)
        conn.commit()


def row_to_dict(row):
    return dict(row) if row is not None else None


def rows_to_dicts(rows) -> list:
    return [dict(r) for r in rows]


class transaction:
    """Context manager wrapping a write transaction."""

    def __init__(self):
        self._conn = None

    def __enter__(self) -> sqlite3.Connection:
        with _lock:
            self._conn = connect()
            self._conn.execute("BEGIN IMMEDIATE")
            return self._conn

    def __exit__(self, exc_type, exc, tb):
        with _lock:
            if self._conn is None:
                return False
            if exc_type is None:
                self._conn.commit()
            else:
                self._conn.rollback()
            return False


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------
SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Accounts -------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id                     INTEGER PRIMARY KEY AUTOINCREMENT,
    username               TEXT    NOT NULL,
    username_lower         TEXT    NOT NULL UNIQUE,
    email                  TEXT    NOT NULL,
    email_lower            TEXT    NOT NULL UNIQUE,
    password_hash          TEXT    NOT NULL,
    role                   TEXT    NOT NULL DEFAULT 'user',
    status                 TEXT    NOT NULL DEFAULT 'active',
    display_name           TEXT,
    bio                    TEXT,
    avatar_path            TEXT,
    email_verified         INTEGER NOT NULL DEFAULT 0,
    email_verify_token     TEXT,
    email_verify_expires   TEXT,
    password_reset_token   TEXT,
    password_reset_expires TEXT,
    daily_request_limit    INTEGER NOT NULL DEFAULT 30,
    created_at             TEXT    NOT NULL,
    updated_at             TEXT    NOT NULL,
    last_login_at          TEXT,
    failed_login_count     INTEGER NOT NULL DEFAULT 0,
    locked_until           TEXT
);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email_lower);
CREATE INDEX IF NOT EXISTS idx_users_role  ON users(role);

-- Sessions -------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sessions (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash    TEXT    NOT NULL UNIQUE,
    csrf_token    TEXT    NOT NULL,
    persistent    INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT    NOT NULL,
    last_seen_at  TEXT    NOT NULL,
    expires_at    TEXT    NOT NULL,
    revoked_at    TEXT,
    revoke_reason TEXT,
    ip            TEXT,
    user_agent    TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_exp  ON sessions(expires_at);

-- Projects and their files --------------------------------------------
CREATE TABLE IF NOT EXISTS projects (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id        INTEGER REFERENCES users(id) ON DELETE SET NULL,
    project_key    TEXT    NOT NULL,
    name           TEXT    NOT NULL,
    template       TEXT,
    description    TEXT,
    path           TEXT,
    is_global      INTEGER NOT NULL DEFAULT 1,
    created_at     TEXT    NOT NULL,
    updated_at     TEXT    NOT NULL,
    last_opened_at TEXT,
    UNIQUE(project_key)
);
CREATE INDEX IF NOT EXISTS idx_projects_user ON projects(user_id);

CREATE TABLE IF NOT EXISTS project_files (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name       TEXT    NOT NULL,
    path       TEXT,
    content    TEXT,
    size       INTEGER NOT NULL DEFAULT 0,
    checksum   TEXT,
    created_at TEXT    NOT NULL,
    updated_at TEXT    NOT NULL,
    UNIQUE(project_id, name)
);

-- Conversations ---------------------------------------------------------
CREATE TABLE IF NOT EXISTS chat_history (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER REFERENCES users(id) ON DELETE CASCADE,
    session_id INTEGER REFERENCES sessions(id) ON DELETE SET NULL,
    role       TEXT    NOT NULL,
    content    TEXT    NOT NULL,
    provider   TEXT,
    project_id INTEGER REFERENCES projects(id) ON DELETE SET NULL,
    tool_name  TEXT,
    ok         INTEGER,
    meta       TEXT,
    created_at TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_chat_user ON chat_history(user_id, created_at);

-- Preferences -----------------------------------------------------------
CREATE TABLE IF NOT EXISTS user_settings (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key        TEXT    NOT NULL,
    value      TEXT,
    updated_at TEXT    NOT NULL,
    UNIQUE(user_id, key)
);

-- Memberships -----------------------------------------------------------
CREATE TABLE IF NOT EXISTS memberships (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id             INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    plan                TEXT    NOT NULL,
    status              TEXT    NOT NULL DEFAULT 'active',
    price_cents         INTEGER NOT NULL DEFAULT 0,
    currency            TEXT    NOT NULL DEFAULT 'USD',
    billing_cycle       TEXT    NOT NULL DEFAULT 'monthly',
    started_at          TEXT    NOT NULL,
    expires_at          TEXT,
    verified_at         TEXT,
    verified_by         TEXT,
    verification_source TEXT,
    payment_id          INTEGER,
    created_at          TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_memberships_user ON memberships(user_id, status);

-- Usage -----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS usage_records (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER REFERENCES users(id) ON DELETE CASCADE,
    feature    TEXT    NOT NULL,
    plan       TEXT,
    requests   INTEGER NOT NULL DEFAULT 1,
    tokens     INTEGER NOT NULL DEFAULT 0,
    cost_cents REAL    NOT NULL DEFAULT 0,
    status     TEXT    NOT NULL DEFAULT 'ok',
    meta       TEXT,
    created_at TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_usage_user ON usage_records(user_id, created_at);

-- Installed plugins / skills --------------------------------------------
CREATE TABLE IF NOT EXISTS installed_plugins (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER REFERENCES users(id) ON DELETE CASCADE,
    plugin_id    TEXT    NOT NULL,
    name         TEXT,
    version      TEXT,
    enabled      INTEGER NOT NULL DEFAULT 1,
    source       TEXT,
    manifest     TEXT,
    installed_at TEXT    NOT NULL,
    updated_at   TEXT    NOT NULL,
    UNIQUE(user_id, plugin_id)
);

CREATE TABLE IF NOT EXISTS installed_skills (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER REFERENCES users(id) ON DELETE CASCADE,
    skill_id     TEXT    NOT NULL,
    name         TEXT,
    mode         TEXT,
    enabled      INTEGER NOT NULL DEFAULT 1,
    source       TEXT,
    installed_at TEXT    NOT NULL,
    updated_at   TEXT    NOT NULL,
    UNIQUE(user_id, skill_id)
);

-- Notifications ---------------------------------------------------------
CREATE TABLE IF NOT EXISTS notifications (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title      TEXT    NOT NULL,
    body       TEXT,
    kind       TEXT    NOT NULL DEFAULT 'info',
    link       TEXT,
    read_at    TEXT,
    created_at TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id, read_at);

-- Payments --------------------------------------------------------------
CREATE TABLE IF NOT EXISTS payments (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    plan            TEXT    NOT NULL,
    amount_cents    INTEGER NOT NULL,
    currency        TEXT    NOT NULL DEFAULT 'USD',
    status          TEXT    NOT NULL DEFAULT 'pending',
    provider        TEXT    NOT NULL DEFAULT 'local',
    provider_ref    TEXT,
    checkout_nonce  TEXT,
    verified_at     TEXT,
    verified_by     TEXT,
    failure_reason  TEXT,
    created_at      TEXT    NOT NULL,
    updated_at      TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_payments_user ON payments(user_id, status);

-- Role grants -----------------------------------------------------------
CREATE TABLE IF NOT EXISTS admin_roles (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role        TEXT    NOT NULL,
    granted_by  INTEGER REFERENCES users(id) ON DELETE SET NULL,
    granted_at  TEXT    NOT NULL,
    expires_at  TEXT,
    revoked_at  TEXT,
    reason      TEXT,
    UNIQUE(user_id, role)
);

-- Audit trail -----------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_logs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_user_id INTEGER,
    actor_name    TEXT,
    actor_role    TEXT,
    action        TEXT    NOT NULL,
    target_type   TEXT,
    target_id     TEXT,
    ip            TEXT,
    user_agent    TEXT,
    detail        TEXT,
    created_at    TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_action  ON audit_logs(action);
"""


def init_db() -> None:
    """Create the schema if needed. Safe to call repeatedly."""
    ensure_dirs()
    with _lock:
        conn = connect()
        conn.executescript(SCHEMA)
        conn.execute(
            "INSERT INTO schema_meta(key, value) VALUES('schema_version', ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (str(SCHEMA_VERSION),),
        )
        conn.commit()


def schema_version() -> int:
    row = query_one("SELECT value FROM schema_meta WHERE key = 'schema_version'")
    try:
        return int(row["value"]) if row else 0
    except (TypeError, ValueError):
        return 0


def is_empty() -> bool:
    """True when no account has been registered yet."""
    row = query_one("SELECT COUNT(*) AS c FROM users")
    return not row or int(row["c"]) == 0


# ---------------------------------------------------------------------------
# Generic settings (key/value, not user scoped)
# ---------------------------------------------------------------------------
def get_setting(key: str, default=None):
    row = query_one("SELECT value FROM schema_meta WHERE key = ?", (key,))
    if row is None:
        return default
    return row["value"]


def set_setting(key: str, value: str) -> None:
    execute(
        "INSERT INTO schema_meta(key, value) VALUES(?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, str(value)),
    )


def get_json_setting(key: str, default=None):
    raw = get_setting(key)
    if raw is None:
        return default
    try:
        return json.loads(raw)
    except (TypeError, ValueError):
        return default


def set_json_setting(key: str, value) -> None:
    set_setting(key, json.dumps(value, ensure_ascii=False))


# ---------------------------------------------------------------------------
# Health / diagnostics
# ---------------------------------------------------------------------------
def table_counts() -> dict:
    tables = [
        "users", "sessions", "projects", "project_files", "chat_history",
        "user_settings", "memberships", "usage_records", "installed_plugins",
        "installed_skills", "notifications", "payments", "admin_roles",
        "audit_logs",
    ]
    counts = {}
    for table in tables:
        try:
            row = query_one(f"SELECT COUNT(*) AS c FROM {table}")  # noqa: S608 - fixed table list
            counts[table] = int(row["c"]) if row else 0
        except sqlite3.DatabaseError:
            counts[table] = 0
    return counts


def vacuum() -> None:
    with _lock:
        try:
            connect().execute("VACUUM")
        except sqlite3.DatabaseError:
            pass


def _touch_session(session_id: int) -> None:
    execute("UPDATE sessions SET last_seen_at = ? WHERE id = ?", (now_iso(), session_id))


def heartbeat(session_id: int) -> None:
    """Cheap last-seen update that never raises into the request path."""
    try:
        _touch_session(session_id)
    except sqlite3.Error:
        pass


def monotonic_ms() -> int:
    return int(time.monotonic() * 1000)
