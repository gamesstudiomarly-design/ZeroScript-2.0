# SPDX-License-Identifier: GPL-3.0-or-later
"""ZeroScript 2.0 - Authentication, account, data and admin HTTP routes.

Everything the browser can ask for lives behind these handlers.  The rules:

* Route handlers never trust the client for identity, role or membership.
  The role comes from the session, the membership comes from the database.
* Every state changing call needs a valid session, a matching CSRF token and
  a same-origin request, except the small set of entry points (login, register,
  forgot / reset password) which are protected by rate limiting and by the
  origin check instead.
* Responses never contain a password hash, a session token, a CSRF secret, an
  API key or the path of the database file.
"""
from __future__ import annotations

import base64
import binascii
import json
import os
import re
import sqlite3
import time
from urllib.parse import urlparse

import zs_auth
import zs_billing
import zs_data
import zs_db

UI_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "app_ui2")

SESSION_COOKIE = zs_auth.SESSION_COOKIE
CSRF_HEADER = zs_auth.CSRF_HEADER

#: When false the workspace runs without a login (single user kiosk mode).
AUTH_REQUIRED = os.environ.get("ZS_AUTH_REQUIRED", "1").strip().lower() not in (
    "0", "false", "no", "off")

#: Routes that may be called without an existing session.
PUBLIC_POST_ROUTES = {
    "/api2/auth/login",
    "/api2/auth/register",
    "/api2/auth/forgot-password",
    "/api2/auth/reset-password",
    "/api2/auth/verify-email",
    "/api2/membership/webhook",
}

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
}


# ---------------------------------------------------------------------------
# Response helpers
# ---------------------------------------------------------------------------
def send_json(handler, code: int, obj, headers: dict | None = None):
    body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    handler.send_response(code)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control", "no-store")
    for key, value in SECURITY_HEADERS.items():
        handler.send_header(key, value)
    for key, value in (headers or {}).items():
        handler.send_header(key, value)
    handler.end_headers()
    try:
        handler.wfile.write(body)
    except (BrokenPipeError, ConnectionResetError):
        pass


def send_file(handler, path: str, content_type: str = None, cache: str = "no-store"):
    """Serve a static file with security headers."""
    if not os.path.isfile(path):
        send_json(handler, 404, {"ok": False, "error": "not found"})
        return
    try:
        with open(path, "rb") as handle:
            body = handle.read()
    except OSError:
        send_json(handler, 500, {"ok": False, "error": "could not read file"})
        return
    handler.send_response(200)
    handler.send_header("Content-Type", content_type or _guess_type(path))
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control", cache)
    for key, value in SECURITY_HEADERS.items():
        handler.send_header(key, value)
    handler.end_headers()
    try:
        handler.wfile.write(body)
    except (BrokenPipeError, ConnectionResetError):
        pass


def _guess_type(path: str) -> str:
    if path.endswith(".js"):
        return "application/javascript; charset=utf-8"
    if path.endswith(".css"):
        return "text/css; charset=utf-8"
    if path.endswith(".html"):
        return "text/html; charset=utf-8"
    if path.endswith(".svg"):
        return "image/svg+xml"
    if path.endswith(".png"):
        return "image/png"
    if path.endswith(".jpg") or path.endswith(".jpeg"):
        return "image/jpeg"
    if path.endswith(".webp"):
        return "image/webp"
    if path.endswith(".ico"):
        return "image/x-icon"
    return "application/octet-stream"


def send_redirect(handler, location: str, code: int = 302):
    handler.send_response(code)
    handler.send_header("Location", location)
    handler.send_header("Content-Length", "0")
    handler.send_header("Cache-Control", "no-store")
    for key, value in SECURITY_HEADERS.items():
        handler.send_header(key, value)
    handler.end_headers()


def error(handler, code: int, message: str, field: str = ""):
    payload = {"ok": False, "error": message}
    if field:
        payload["field"] = field
    send_json(handler, code, payload)


# ---------------------------------------------------------------------------
# Cookie helpers
# ---------------------------------------------------------------------------
def _is_secure(handler) -> bool:
    if os.environ.get("ZS_SECURE_COOKIES", "").strip() in ("1", "true", "yes"):
        return True
    try:
        proto = (handler.headers.get("X-Forwarded-Proto") or "").lower()
        if proto == "https":
            return True
    except Exception:
        pass
    return False


def set_session_cookie(handler, token: str, persistent: bool) -> str:
    """Build the ``Set-Cookie`` value for the session."""
    parts = [
        f"{SESSION_COOKIE}={token}",
        "Path=/",
        "HttpOnly",
        "SameSite=Strict",
    ]
    if persistent:
        parts.append(f"Max-Age={zs_auth.REMEMBER_TTL_SECONDS}")
    if _is_secure(handler):
        parts.append("Secure")
    return "; ".join(parts)


def clear_session_cookie(handler) -> str:
    parts = [f"{SESSION_COOKIE}=", "Path=/", "HttpOnly", "SameSite=Strict", "Max-Age=0"]
    if _is_secure(handler):
        parts.append("Secure")
    return "; ".join(parts)


def read_cookie(handler, name: str) -> str:
    try:
        raw = handler.headers.get("Cookie") or ""
    except Exception:
        return ""
    for chunk in raw.split(";"):
        if "=" not in chunk:
            continue
        key, value = chunk.split("=", 1)
        if key.strip() == name:
            return value.strip()
    return ""


# ---------------------------------------------------------------------------
# Session helpers
# ---------------------------------------------------------------------------
def current_session(handler):
    token = read_cookie(handler, SESSION_COOKIE)
    if not token:
        if not AUTH_REQUIRED:
            return _kiosk_session()
        return None, None
    session = zs_auth.get_session_by_token(token)
    if session is None:
        if not AUTH_REQUIRED:
            return _kiosk_session()
        return None, None
    user = zs_auth.find_user(session["user_id"])
    if user is None or user["status"] != "active":
        zs_auth.revoke_session(session["id"], "account unavailable")
        return None, None
    zs_db.heartbeat(session["id"])
    # The Studio Bridge runs on its own threads; this is how its tool
    # activity is attributed to the account that is driving the workspace.
    zs_data.set_current_user(user["id"])
    return session, user


_kiosk_session_id = None


def _kiosk_session():
    """Kiosk mode (ZS_AUTH_REQUIRED=0): act as the local owner account."""
    global _kiosk_session_id
    if _kiosk_session_id:
        row = zs_db.query_one("SELECT * FROM sessions WHERE id = ?", (_kiosk_session_id,))
        if row is not None and not row["revoked_at"] and not zs_db.is_expired(row["expires_at"]):
            owner = zs_auth.find_user(row["user_id"])
            if owner is not None:
                return row, owner
    owner = zs_db.query_one(
        "SELECT * FROM users WHERE role = ? ORDER BY id LIMIT 1", (zs_auth.ROLE_OWNER,)
    )
    if owner is None:
        return None, None
    created = zs_auth.create_session(owner["id"], remember=True, ip="local", user_agent="kiosk")
    _kiosk_session_id = created["id"]
    row = zs_db.query_one("SELECT * FROM sessions WHERE id = ?", (created["id"],))
    return row, owner


def require_auth(handler):
    """Return ``(session, user)`` or send a 401 and return ``(None, None)``."""
    session, user = current_session(handler)
    if session is None or user is None:
        error(handler, 401, "Sign in to continue.")
        return None, None
    return session, user


def enforce_csrf(handler, session) -> bool:
    """Validate the CSRF token and the request origin."""
    if not zs_auth.origin_allowed(handler):
        error(handler, 403, "Cross-site request blocked.")
        return False
    provided = handler.headers.get(CSRF_HEADER) or ""
    if not zs_auth.check_csrf(session, provided):
        error(handler, 419, "Your session expired or the request could not be verified. Reload and try again.")
        return False
    return True


def precheck(handler, path: str) -> bool:
    """Decide whether a state changing request may proceed.

    Called by the server before any handler runs.  It verifies the origin,
    the session and the CSRF token, and stashes the resolved session and user
    on the handler so the route handlers do not have to look them up again.
    """
    if not zs_auth.origin_allowed(handler):
        error(handler, 403, "Cross-site request blocked.")
        return False
    if path in PUBLIC_POST_ROUTES:
        return True
    session, user = current_session(handler)
    if session is None or user is None:
        error(handler, 401, "Sign in to continue.")
        return False
    handler._zs_session = session
    handler._zs_user = user
    if not AUTH_REQUIRED:
        # Kiosk mode: the local owner acts automatically, no CSRF handshake.
        return True
    if not zs_auth.check_csrf(session, handler.headers.get(CSRF_HEADER) or ""):
        error(handler, 419, "Your session expired or the request could not be verified. "
                            "Reload the page and try again.")
        return False
    return True


def precheck_get(handler, path: str) -> bool:
    """Gate a read request: a valid session is required, CSRF is not."""
    if not AUTH_REQUIRED:
        return True
    session, user = current_session(handler)
    if session is None or user is None:
        error(handler, 401, "Sign in to continue.")
        return False
    handler._zs_session = session
    handler._zs_user = user
    return True


def require_permission(handler, session, user, permission: str):
    """Enforce a server side role permission. Returns the role on success."""
    role = zs_auth.effective_role(user)
    if not zs_auth.has_permission(role, permission):
        zs_auth.audit("permission.denied", user, "permission", permission,
                      "insufficient role", handler)
        error(handler, 403, "Your role does not allow this action.")
        return None
    return role


def session_payload(session, user) -> dict:
    role = zs_auth.effective_role(user)
    return {
        "ok": True,
        "authenticated": True,
        "csrfToken": session["csrf_token"],
        "expiresAt": session["expires_at"],
        "persistent": bool(session["persistent"]),
        "user": zs_auth.public_user(user, include_private=True),
        "membership": zs_auth.membership_for(user),
        "permissions": zs_auth.permissions_for(role),
        "role": role,
        "roleLabel": zs_auth.ROLE_LABELS.get(role, role.upper()),
    }


# ---------------------------------------------------------------------------
# Account payload
# ---------------------------------------------------------------------------
def account_payload(user) -> dict:
    membership = zs_auth.membership_for(user)
    return {
        "ok": True,
        "user": zs_auth.public_user(user, include_private=True),
        "membership": membership,
        "sessions": zs_auth.list_sessions(user["id"]),
        "notifications": zs_auth.list_notifications(user["id"], 25),
        "usage": {
            "today": zs_billing.usage_today(user["id"]),
            "limit": zs_auth.effective_daily_limit(user),
            "chat": zs_data.chat_stats(user["id"]),
        },
        "workspace": zs_data.load_workspace(user["id"]),
        "plans": zs_billing.public_plans(),
        "hashScheme": zs_auth.hash_scheme_info(),
    }


# ---------------------------------------------------------------------------
# Public routes: GET
# ---------------------------------------------------------------------------
def handle_get(handler, path: str) -> bool:
    if path == "/api2/auth/session":
        session, user = current_session(handler)
        if session is None or user is None:
            send_json(handler, 200, {"ok": True, "authenticated": False})
            return True
        send_json(handler, 200, session_payload(session, user))
        return True

    if path == "/api2/auth/plans":
        send_json(handler, 200, {
            "ok": True,
            "plans": zs_billing.public_plans(),
            "freePlan": zs_billing.DEFAULT_PLAN,
        })
        return True

    if path == "/api2/account/profile":
        session, user = require_auth(handler)
        if not user:
            return True
        send_json(handler, 200, account_payload(user))
        return True

    if path == "/api2/account/sessions":
        session, user = require_auth(handler)
        if not user:
            return True
        send_json(handler, 200, {"ok": True, "sessions": zs_auth.list_sessions(user["id"])})
        return True

    if path == "/api2/account/outbox":
        # Local install helper: shows the most recent spooled message so the
        # verification / reset link can be followed without a mail server.
        session, user = require_auth(handler)
        if not user:
            return True
        email = handler.path.split("?", 1)[-1]
        address = user["email"]
        for part in email.split("&"):
            if part.startswith("email="):
                from urllib.parse import unquote
                address = unquote(part[6:])
                break
        record = zs_auth.latest_outbox_for(address)
        send_json(handler, 200, {"ok": True, "message": record})
        return True

    if path.startswith("/api2/avatar/"):
        return _serve_avatar(handler, path)

    if path == "/api2/data/workspace":
        session, user = require_auth(handler)
        if not user:
            return True
        send_json(handler, 200, {
            "ok": True,
            "workspace": zs_data.load_workspace(user["id"]),
            "preferences": zs_data.load_preferences(user["id"]),
        })
        return True

    if path == "/api2/data/backup":
        session, user = require_auth(handler)
        if not user:
            return True
        scope = "self"
        if "scope=all" in (handler.path or ""):
            scope = "all"
        try:
            backup = zs_data.export_backup(user, scope=scope)
        except PermissionError as exc:
            error(handler, 403, str(exc))
            return True
        send_json(handler, 200, {"ok": True, "backup": backup})
        return True

    if path == "/api2/chat/history":
        session, user = require_auth(handler)
        if not user:
            return True
        limit = 100
        if "limit=" in (handler.path or ""):
            try:
                limit = int(handler.path.split("limit=")[1].split("&")[0])
            except (TypeError, ValueError):
                limit = 100
        send_json(handler, 200, {
            "ok": True,
            "messages": zs_data.recent_chat(user["id"], limit),
            "stats": zs_data.chat_stats(user["id"]),
        })
        return True

    # ---- Administrative ------------------------------------------------
    if path == "/api2/admin/accounts":
        session, user = require_auth(handler)
        if not user:
            return True
        if not require_permission(handler, session, user, "users.read"):
            return True
        return _admin_accounts(handler, user)

    if path == "/api2/admin/audit":
        session, user = require_auth(handler)
        if not user:
            return True
        if not require_permission(handler, session, user, "audit.read"):
            return True
        limit = 100
        offset = 0
        query = handler.path.split("?", 1)[-1]
        for part in query.split("&"):
            if part.startswith("limit="):
                limit = int(part[6:]) if part[6:].isdigit() else 100
            if part.startswith("offset="):
                offset = int(part[7:]) if part[7:].isdigit() else 0
        send_json(handler, 200, {"ok": True, "logs": zs_auth.list_audit(limit, offset)})
        return True

    if path == "/api2/admin/payments":
        session, user = require_auth(handler)
        if not user:
            return True
        if not require_permission(handler, session, user, "payments.read"):
            return True
        rows = zs_db.rows_to_dicts(
            zs_db.query("SELECT * FROM payments ORDER BY id DESC LIMIT 200"))
        send_json(handler, 200, {"ok": True, "payments": rows})
        return True

    if path == "/api2/admin/sessions":
        session, user = require_auth(handler)
        if not user:
            return True
        if not require_permission(handler, session, user, "sessions.read"):
            return True
        rows = zs_db.rows_to_dicts(
            zs_db.query(
                "SELECT s.id, s.user_id, s.persistent, s.created_at, s.last_seen_at, "
                "s.expires_at, s.revoked_at, s.ip, s.user_agent, u.username, u.email "
                "FROM sessions s LEFT JOIN users u ON u.id = s.user_id "
                "ORDER BY s.last_seen_at DESC LIMIT 300"))
        send_json(handler, 200, {"ok": True, "sessions": rows})
        return True

    if path == "/api2/admin/stats":
        session, user = require_auth(handler)
        if not user:
            return True
        if not require_permission(handler, session, user, "users.read"):
            return True
        counts = zs_db.table_counts()
        send_json(handler, 200, {
            "ok": True,
            "counts": counts,
            "roles": list(zs_auth.ROLES),
            "plans": zs_billing.public_plans(),
            "hashScheme": zs_auth.hash_scheme_info(),
        })
        return True

    # ---- Static pages --------------------------------------------------
    if path in ("/2/login", "/2/login.html"):
        send_file(handler, os.path.join(UI_DIR, "login.html"))
        return True
    if path == "/2/login.css":
        send_file(handler, os.path.join(UI_DIR, "login.css"))
        return True
    if path == "/2/login.js":
        send_file(handler, os.path.join(UI_DIR, "login.js"))
        return True
    if path in ("/2/account", "/2/account.html"):
        session, user = current_session(handler)
        if session is None or user is None:
            send_redirect(handler, "/2/login?next=/2/account")
            return True
        send_file(handler, os.path.join(UI_DIR, "account.html"))
        return True
    if path == "/2/account.css":
        send_file(handler, os.path.join(UI_DIR, "account.css"))
        return True
    if path == "/2/account.js":
        send_file(handler, os.path.join(UI_DIR, "account.js"))
        return True

    return False


# ---------------------------------------------------------------------------
# Avatar serving
# ---------------------------------------------------------------------------
def _serve_avatar(handler, path: str) -> bool:
    tail = path[len("/api2/avatar/"):].split("?")[0]
    if not tail.isdigit():
        error(handler, 400, "Invalid avatar request.")
        return True
    user_id = int(tail)
    row = zs_db.query_one("SELECT avatar_path FROM users WHERE id = ?", (user_id,))
    if row is None or not row["avatar_path"]:
        send_json(handler, 404, {"ok": False, "error": "no avatar"})
        return True
    file_path = os.path.join(zs_db.AVATAR_DIR, os.path.basename(row["avatar_path"]))
    send_file(handler, file_path, cache="public, max-age=300")
    return True


# ---------------------------------------------------------------------------
# Admin account listing
# ---------------------------------------------------------------------------
def _admin_accounts(handler, actor) -> bool:
    rows = zs_db.query("SELECT * FROM users ORDER BY id")
    users = []
    for row in rows:
        data = zs_auth.public_user(row, include_private=True)
        membership = zs_auth.membership_for(row)
        data["membership"] = membership
        data["sessions"] = len([
            s for s in zs_auth.list_sessions(row["id"])
            if not s["revoked_at"]
        ])
        data["grants"] = zs_db.rows_to_dicts(
            zs_db.query("SELECT role, granted_at, revoked_at FROM admin_roles WHERE user_id = ?",
                        (row["id"],))
        )
        users.append(data)
    counts = zs_db.table_counts()
    send_json(handler, 200, {
        "ok": True,
        "users": users,
        "counts": counts,
        "roles": list(zs_auth.ROLES),
        "plans": zs_billing.public_plans(),
        "admin": {
            "emailTransport": "smtp" if zs_auth.smtp_configured() else "outbox",
            "hashScheme": zs_auth.hash_scheme_info(),
            "authRequired": zs_db.get_setting("auth_required", "1") == "1",
        },
    })
    return True


# ---------------------------------------------------------------------------
# POST routes
# ---------------------------------------------------------------------------
def handle_post(handler, path: str, body: dict) -> bool:
    session = getattr(handler, "_zs_session", None)
    user = getattr(handler, "_zs_user", None)
    if path in PUBLIC_POST_ROUTES:
        session, user = None, None
        if not zs_auth.origin_allowed(handler):
            error(handler, 403, "Cross-site request blocked.")
            return True
    elif session is None:
        session, user = require_auth(handler)
        if not user:
            return True
        if not enforce_csrf(handler, session):
            return True

    # ---- Registration --------------------------------------------------
    if path == "/api2/auth/register":
        return _register(handler, body)

    # ---- Login ---------------------------------------------------------
    if path == "/api2/auth/login":
        return _login(handler, body)

    # ---- Logout --------------------------------------------------------
    if path == "/api2/auth/logout":
        session, user = require_auth(handler)
        if not user:
            return True
        if not enforce_csrf(handler, session):
            return True
        zs_auth.revoke_session(session["id"], "signed out")
        zs_auth.audit("auth.logout", user, "session", str(session["id"]), "", handler)
        send_json(handler, 200, {"ok": True}, {"Set-Cookie": clear_session_cookie(handler)})
        return True

    if path == "/api2/auth/logout-all":
        session, user = require_auth(handler)
        if not user:
            return True
        if not enforce_csrf(handler, session):
            return True
        revoked = zs_auth.revoke_all_sessions(user["id"], "signed out everywhere")
        zs_auth.audit("auth.logout_all", user, "user", str(user["id"]),
                      f"{revoked} sessions revoked", handler)
        send_json(handler, 200, {"ok": True, "revoked": revoked},
                  {"Set-Cookie": clear_session_cookie(handler)})
        return True

    # ---- Forgot / reset ------------------------------------------------
    if path == "/api2/auth/forgot-password":
        return _forgot_password(handler, body)

    if path == "/api2/auth/reset-password":
        return _reset_password(handler, body)

    if path == "/api2/auth/verify-email":
        return _verify_email(handler, body)

    # ---- Membership ----------------------------------------------------
    if path == "/api2/membership/checkout":
        return _membership_checkout(handler, session, user, body)

    if path == "/api2/membership/confirm":
        return _membership_confirm(handler, session, user, body)

    if path == "/api2/membership/webhook":
        return _membership_webhook(handler, body)

    # ---- Account -------------------------------------------------------
    if path == "/api2/account/profile":
        return _update_profile(handler, user, body)

    if path == "/api2/account/password":
        return _change_password(handler, session, user, body)

    if path == "/api2/account/avatar":
        return _upload_avatar(handler, user, body)

    if path == "/api2/account/delete":
        return _delete_account(handler, session, user, body)

    if path == "/api2/account/notifications/read":
        ids = body.get("ids") if isinstance(body.get("ids"), list) else []
        for note_id in ids[:100]:
            zs_db.execute(
                "UPDATE notifications SET read_at = ? WHERE id = ? AND user_id = ?",
                (zs_db.now_iso(), int(note_id), int(user["id"])),
            )
        send_json(handler, 200, {"ok": True,
                                 "notifications": zs_auth.list_notifications(user["id"], 25)})
        return True

    # ---- Data ----------------------------------------------------------
    if path == "/api2/data/workspace":
        zs_data.save_workspace(user["id"], body if isinstance(body, dict) else {})
        send_json(handler, 200, {"ok": True, "workspace": zs_data.load_workspace(user["id"])})
        return True

    if path == "/api2/data/preferences":
        zs_data.save_preferences(user["id"], body if isinstance(body, dict) else {})
        send_json(handler, 200, {"ok": True, "preferences": zs_data.load_preferences(user["id"])})
        return True

    if path == "/api2/data/save":
        result = zs_data.manual_save(user)
        send_json(handler, 200, {"ok": True, **result})
        return True

    if path == "/api2/data/restore":
        try:
            result = zs_data.restore_backup(user, body.get("backup") or {})
        except PermissionError as exc:
            error(handler, 403, str(exc))
            return True
        except (ValueError, TypeError) as exc:
            error(handler, 400, str(exc))
            return True
        send_json(handler, 200, result)
        return True

    # ---- Chat ----------------------------------------------------------
    if path == "/api2/chat/message":
        return _save_chat_message(handler, session, user, body)

    if path == "/api2/chat/clear":
        removed = zs_data.clear_chat(user["id"])
        send_json(handler, 200, {"ok": True, "removed": removed})
        return True

    # ---- Admin ---------------------------------------------------------
    if path == "/api2/admin/users/update":
        return _admin_user_update(handler, user, body)

    if path == "/api2/admin/users/suspend":
        return _admin_user_suspend(handler, user, body)

    if path == "/api2/admin/users/delete":
        return _admin_user_delete(handler, user, body)

    if path == "/api2/admin/roles/grant":
        return _admin_role_grant(handler, user, body)

    if path == "/api2/admin/roles/revoke":
        return _admin_role_revoke(handler, user, body)

    if path == "/api2/admin/sessions/revoke":
        return _admin_session_revoke(handler, user, body)

    if path == "/api2/admin/payments/verify":
        return _admin_payment_verify(handler, user, body)

    if path == "/api2/admin/membership/grant":
        return _admin_membership_grant(handler, user, body)

    if path == "/api2/admin/backup":
        return _admin_backup(handler, user)

    return False


# ---------------------------------------------------------------------------
# Auth handlers
# ---------------------------------------------------------------------------
def _register(handler, body) -> bool:
    ip = zs_auth.client_ip(handler)
    allowed, retry = zs_auth.rate_limiter.hit(
        f"register:{ip}", zs_auth.REGISTER_MAX_ATTEMPTS, zs_auth.REGISTER_WINDOW_SECONDS)
    if not allowed:
        error(handler, 429, f"Too many accounts created from this device. Try again in {retry}s.")
        return True

    try:
        username = zs_auth.validate_username(body.get("username"))
        email = zs_auth.validate_email(body.get("email"))
        password = zs_auth.validate_password(body.get("password"))
        zs_auth.validate_confirm(password, body.get("confirmPassword"))
    except zs_auth.ValidationError as exc:
        error(handler, 400, exc.message, exc.field)
        return True

    if zs_auth.find_user_by_email(email) is not None:
        error(handler, 409, "An account with that email already exists.", "email")
        return True
    if zs_auth.find_user_by_username(username) is not None:
        error(handler, 409, "That username is already taken.", "username")
        return True

    try:
        created = zs_auth.create_user(username, email, password, role=zs_auth.ROLE_USER)
    except ValueError as exc:
        error(handler, 409, str(exc))
        return True

    user = zs_auth.find_user(created["id"])
    token = zs_auth.create_email_verification(user)
    link = _verification_link(handler, token)
    delivery = zs_auth.deliver_email(
        email,
        "Verify your ZeroScript account",
        f"Hi {username},\n\nConfirm your ZeroScript account by opening this link:\n{link}\n\n"
        f"If you did not create this account you can ignore this message.",
        {"userId": user["id"], "kind": "email-verification"},
    )
    zs_auth.add_notification(
        user["id"], "Welcome to ZeroScript",
        "Your account is ready. Confirm your email address to finish setting it up.",
        kind="success", link="/2/account")
    zs_auth.audit("auth.register", user, "user", str(user["id"]), f"email delivery: {delivery.get('transport')}", handler)

    session = zs_auth.create_session(user["id"], remember=bool(body.get("remember")),
                                     ip=ip, user_agent=zs_auth.user_agent(handler))
    zs_auth.clear_login_failures(user)
    payload = session_payload(_session_row(session["id"]), user)
    payload["verification"] = {"emailSent": delivery.get("ok", False),
                               "transport": delivery.get("transport"),
                               "link": link if delivery.get("transport") == "outbox" else None}
    send_json(handler, 200, payload, {"Set-Cookie": set_session_cookie(handler, session["token"], session["persistent"])})
    return True


def _login(handler, body) -> bool:
    ip = zs_auth.client_ip(handler)
    identifier = str(body.get("email") or "").strip().lower()
    allowed, retry = zs_auth.rate_limiter.hit(
        f"login:{ip}", zs_auth.LOGIN_MAX_ATTEMPTS, zs_auth.LOGIN_WINDOW_SECONDS)
    if not allowed:
        error(handler, 429, f"Too many sign-in attempts. Try again in {retry}s.")
        return True
    if identifier:
        allowed, retry = zs_auth.rate_limiter.hit(
            f"login-acct:{identifier}", zs_auth.LOGIN_MAX_ATTEMPTS, zs_auth.LOGIN_WINDOW_SECONDS)
        if not allowed:
            error(handler, 429, f"Too many sign-in attempts for this account. Try again in {retry}s.")
            return True

    if not identifier or not body.get("password"):
        error(handler, 400, "Enter your email address and password.", "email")
        return True

    user = zs_auth.find_user_by_email(identifier) or zs_auth.find_user_by_username(identifier)
    if user is None:
        zs_auth.rate_limiter.hit(f"login-miss:{ip}", 50, 60)
        error(handler, 401, "That email address and password do not match an account.")
        return True

    if user["status"] != "active":
        error(handler, 403, "This account is not active. Contact the platform owner.")
        return True

    if zs_auth.is_locked(user):
        error(handler, 429, "This account is temporarily locked after too many failed attempts.")
        return True

    if not zs_auth.verify_password(str(body.get("password") or ""), user["password_hash"]):
        zs_auth.record_login_failure(user)
        zs_auth.audit("auth.login_failed", user, "user", str(user["id"]), "", handler)
        error(handler, 401, "That email address and password do not match an account.")
        return True

    if zs_auth.needs_rehash(user["password_hash"]):
        # Upgrade the stored hash to the strongest scheme in use.
        try:
            zs_auth.set_password(user["id"], str(body.get("password")))
            user = zs_auth.find_user(user["id"])
        except Exception:
            pass

    zs_auth.rate_limiter.reset(f"login:{ip}")
    zs_auth.rate_limiter.reset(f"login-acct:{identifier}")
    zs_auth.clear_login_failures(user)

    session = zs_auth.create_session(user["id"], remember=bool(body.get("remember")),
                                     ip=ip, user_agent=zs_auth.user_agent(handler))
    zs_auth.audit("auth.login", user, "session", str(session["id"]),
                  "remember" if body.get("remember") else "session", handler)
    payload = session_payload(_session_row(session["id"]), user)
    send_json(handler, 200, payload, {"Set-Cookie": set_session_cookie(handler, session["token"], session["persistent"])})
    return True


def _session_row(session_id: int):
    return zs_db.query_one("SELECT * FROM sessions WHERE id = ?", (int(session_id),))


def _forgot_password(handler, body) -> bool:
    email = str(body.get("email") or "").strip()
    ip = zs_auth.client_ip(handler)
    allowed, retry = zs_auth.rate_limiter.hit(
        f"reset:{email.lower()}", zs_auth.RESET_MAX_ATTEMPTS, zs_auth.RESET_WINDOW_SECONDS)
    if not allowed:
        error(handler, 429, f"Too many reset requests for this address. Try again in {retry}s.")
        return True

    generic = {"ok": True,
               "message": "If that address has a ZeroScript account, a reset link is on its way."}
    try:
        address = zs_auth.validate_email(email)
    except zs_auth.ValidationError:
        # Do not reveal whether the address exists.
        send_json(handler, 200, generic)
        return True

    user = zs_auth.find_user_by_email(address)
    if user is None:
        send_json(handler, 200, generic)
        return True

    token = zs_auth.create_password_reset(user)
    link = _reset_link(handler, token)
    delivery = zs_auth.deliver_email(
        address,
        "Reset your ZeroScript password",
        f"Hi {user['username']},\n\nReset your password with this link:\n{link}\n\n"
        f"The link expires in one hour. If you did not ask for it, nothing changed.",
        {"userId": user["id"], "kind": "password-reset"},
    )
    zs_auth.audit("auth.password_reset_requested", user, "user", str(user["id"]), "", handler)
    payload = dict(generic)
    payload["delivery"] = {"transport": delivery.get("transport"),
                           "link": link if delivery.get("transport") == "outbox" else None}
    send_json(handler, 200, payload)
    return True


def _reset_password(handler, body) -> bool:
    token = str(body.get("token") or "").strip()
    if not token:
        error(handler, 400, "The reset link is missing or invalid.", "token")
        return True
    try:
        password = zs_auth.validate_password(body.get("password"))
        zs_auth.validate_confirm(password, body.get("confirmPassword"))
    except zs_auth.ValidationError as exc:
        error(handler, 400, exc.message, exc.field)
        return True

    user = zs_auth.consume_password_reset(token)
    if user is None:
        error(handler, 400, "That reset link is invalid or has expired.", "token")
        return True

    zs_auth.set_password(user["id"], password)
    revoked = zs_auth.revoke_all_sessions(user["id"], "password changed")
    zs_auth.add_notification(user["id"], "Password changed",
                             "Your password was reset and every other device was signed out.",
                             kind="info")
    zs_auth.audit("auth.password_reset", user, "user", str(user["id"]),
                  f"{revoked} sessions revoked", handler)
    send_json(handler, 200, {"ok": True, "revoked": revoked})
    return True


def _verify_email(handler, body) -> bool:
    token = str(body.get("token") or "").strip()
    if not token:
        error(handler, 400, "The verification link is missing or invalid.", "token")
        return True
    user = zs_auth.consume_email_verification(token)
    if user is None:
        error(handler, 400, "That verification link is invalid or has expired.", "token")
        return True
    zs_auth.add_notification(user["id"], "Email verified",
                             "Your email address is confirmed. Thanks!", kind="success")
    zs_auth.audit("auth.email_verified", user, "user", str(user["id"]), "", handler)
    send_json(handler, 200, {"ok": True, "email": user["email"], "emailVerified": True})
    return True


# ---------------------------------------------------------------------------
# Membership handlers
# ---------------------------------------------------------------------------
def _membership_checkout(handler, session, user, body) -> bool:
    plan_id = str(body.get("plan") or "").strip().lower()
    plan = zs_billing.get_plan(plan_id)
    if plan is None:
        error(handler, 400, "Unknown membership plan.", "plan")
        return True
    if not plan["paid"]:
        error(handler, 400, "The free plan is assigned automatically.", "plan")
        return True
    current = zs_auth.active_membership(user["id"])
    if current is not None and current["plan"] == plan["id"] and current["status"] == "active":
        error(handler, 409, "You are already on this plan.")
        return True
    try:
        checkout = zs_billing.create_checkout(user, plan["id"])
    except ValueError as exc:
        error(handler, 400, str(exc))
        return True
    zs_auth.audit("membership.checkout_started", user, "payment", str(checkout["paymentId"]),
                  plan["id"], handler)
    send_json(handler, 200, {"ok": True, "checkout": checkout})
    return True


def _membership_confirm(handler, session, user, body) -> bool:
    token = str(body.get("checkoutToken") or "").strip()
    if not token:
        error(handler, 400, "Checkout token missing.", "checkoutToken")
        return True
    result = zs_billing.confirm_checkout(user, token,
                                          str(body.get("reference") or ""))
    if not result.get("ok"):
        error(handler, 400, result.get("error", "Checkout could not be verified."))
        return True
    zs_auth.add_notification(user["id"], f"Membership upgraded to {result['planName']}",
                             "Your paid plan is active on this device.", kind="success")
    zs_auth.audit("membership.activated", user, "membership", str(result.get("membershipId")),
                  result["plan"], handler)
    fresh = zs_auth.find_user(user["id"])
    send_json(handler, 200, {"ok": True, "membership": zs_auth.membership_for(fresh),
                             "user": zs_auth.public_user(fresh, include_private=True)})
    return True


def _membership_webhook(handler, body) -> bool:
    signature = handler.headers.get("X-ZS-Signature") or handler.headers.get("X-Signature") or ""
    result = zs_billing.verify_provider_callback(body if isinstance(body, dict) else {}, signature)
    if not result.get("ok"):
        error(handler, 400, result.get("error", "Callback rejected."))
        return True
    send_json(handler, 200, result)
    return True


# ---------------------------------------------------------------------------
# Account handlers
# ---------------------------------------------------------------------------
def _update_profile(handler, user, body) -> bool:
    updates = {}
    try:
        if "username" in body:
            username = zs_auth.validate_username(body.get("username"))
            existing = zs_auth.find_user_by_username(username)
            if existing is not None and existing["id"] != user["id"]:
                error(handler, 409, "That username is already taken.", "username")
                return True
            updates["username"] = username
        if "email" in body:
            email = zs_auth.validate_email(body.get("email"))
            existing = zs_auth.find_user_by_email(email)
            if existing is not None and existing["id"] != user["id"]:
                error(handler, 409, "An account with that email already exists.", "email")
                return True
            updates["email"] = email
        if "displayName" in body:
            updates["display_name"] = zs_auth.sanitize_text(body.get("displayName"), 60)
        if "bio" in body:
            updates["bio"] = zs_auth.sanitize_text(body.get("bio"), 400, allow_newlines=True)
    except zs_auth.ValidationError as exc:
        error(handler, 400, exc.message, exc.field)
        return True

    if updates:
        sets = ", ".join(f"{key} = ?" for key in updates)
        zs_db.execute(f"UPDATE users SET {sets}, updated_at = ? WHERE id = ?",  # noqa: S608 - fixed keys
                      list(updates.values()) + [zs_db.now_iso(), int(user["id"])])
    if "email" in updates and updates["email"].lower() != user["email_lower"]:
        zs_db.execute(
            "UPDATE users SET email_verified = 0, email_verify_token = NULL, "
            "email_verify_expires = NULL WHERE id = ?", (int(user["id"]),))
        fresh = zs_auth.find_user(user["id"])
        token = zs_auth.create_email_verification(fresh)
        link = _verification_link(handler, token)
        zs_auth.deliver_email(
            updates["email"], "Verify your new ZeroScript email address",
            f"Confirm your new address with this link:\n{link}", {"kind": "email-verification"})
        zs_auth.audit("account.email_changed", user, "user", str(user["id"]),
                      updates["email"], handler)

    fresh = zs_auth.find_user(user["id"])
    zs_auth.audit("account.profile_updated", user, "user", str(user["id"]),
                  ", ".join(sorted(updates.keys())) or "none", handler)
    send_json(handler, 200, {"ok": True, "user": zs_auth.public_user(fresh, include_private=True),
                             "membership": zs_auth.membership_for(fresh)})
    return True


def _change_password(handler, session, user, body) -> bool:
    current = str(body.get("currentPassword") or "")
    try:
        password = zs_auth.validate_password(body.get("password"))
        zs_auth.validate_confirm(password, body.get("confirmPassword"))
    except zs_auth.ValidationError as exc:
        error(handler, 400, exc.message, exc.field)
        return True

    if not zs_auth.verify_password(current, user["password_hash"]):
        zs_auth.audit("account.password_change_failed", user, "user", str(user["id"]), "", handler)
        error(handler, 401, "Your current password is not correct.", "currentPassword")
        return True

    zs_auth.set_password(user["id"], password)
    revoked = zs_auth.revoke_all_sessions(user["id"], "password changed", except_id=session["id"])
    zs_auth.add_notification(user["id"], "Password changed",
                             "Your password was updated. Other devices were signed out.",
                             kind="info")
    zs_auth.audit("account.password_changed", user, "user", str(user["id"]),
                  f"{revoked} sessions revoked", handler)
    send_json(handler, 200, {"ok": True, "revoked": revoked})
    return True


def _upload_avatar(handler, user, body) -> bool:
    payload = body.get("dataUrl") or body.get("image") or ""
    if not isinstance(payload, str) or not payload.strip():
        error(handler, 400, "No image was provided.", "avatar")
        return True
    raw = payload.strip()
    if raw.startswith("data:"):
        _, _, raw = raw.partition(",")
    try:
        binary = base64.b64decode(raw, validate=False)
    except (binascii.Error, ValueError):
        error(handler, 400, "The image could not be decoded.", "avatar")
        return True
    if len(binary) < 32:
        error(handler, 400, "That image file looks empty.", "avatar")
        return True
    if len(binary) > 4 * 1024 * 1024:
        error(handler, 413, "Images must be smaller than 4 MB.", "avatar")
        return True

    extension, content_type = _detect_image(binary)
    if extension is None:
        error(handler, 400, "Only PNG, JPEG, GIF or WebP images are supported.", "avatar")
        return True

    zs_db.ensure_dirs()
    filename = f"avatar-{int(user['id'])}.{extension}"
    path = os.path.join(zs_db.AVATAR_DIR, filename)
    try:
        binary = _normalise_avatar(binary)
        with open(path, "wb") as handle:
            handle.write(binary)
    except OSError as exc:
        error(handler, 500, f"The image could not be saved: {exc}")
        return True

    zs_db.execute("UPDATE users SET avatar_path = ?, updated_at = ? WHERE id = ?",
                  (filename, zs_db.now_iso(), int(user["id"])))
    zs_auth.audit("account.avatar_updated", user, "user", str(user["id"]), content_type, handler)
    fresh = zs_auth.find_user(user["id"])
    send_json(handler, 200, {"ok": True, "user": zs_auth.public_user(fresh, include_private=True),
                             "avatarUrl": f"/api2/avatar/{user['id']}?v={int(time.time())}"})
    return True


def _detect_image(binary: bytes):
    if binary.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png", "image/png"
    if binary.startswith(b"\xff\xd8\xff"):
        return "jpg", "image/jpeg"
    if binary.startswith(b"GIF87a") or binary.startswith(b"GIF89a"):
        return "gif", "image/gif"
    if len(binary) > 12 and binary[:4] == b"RIFF" and binary[8:12] == b"WEBP":
        return "webp", "image/webp"
    return None, None


def _normalise_avatar(binary: bytes) -> bytes:
    """Resize to a 256px square when Pillow is available; keep the original otherwise."""
    try:
        import io
        from PIL import Image

        with Image.open(io.BytesIO(binary)) as image:
            image = image.convert("RGBA")
            image.thumbnail((256, 256))
            buffer = io.BytesIO()
            image.save(buffer, format="PNG")
            return buffer.getvalue()
    except Exception:
        return binary


def _delete_account(handler, session, user, body) -> bool:
    confirm = str(body.get("confirm") or "").strip().upper()
    if confirm != "DELETE":
        error(handler, 400, "Type DELETE to confirm removing this account.", "confirm")
        return True
    if not zs_auth.verify_password(str(body.get("password") or ""), user["password_hash"]):
        error(handler, 401, "Your password is not correct.", "password")
        return True

    user_id = int(user["id"])
    avatar = user["avatar_path"]
    zs_db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    zs_auth.audit("account.deleted", user, "user", str(user_id),
                  "account and personal data removed", handler)
    if avatar:
        try:
            os.remove(os.path.join(zs_db.AVATAR_DIR, os.path.basename(avatar)))
        except OSError:
            pass
    send_json(handler, 200, {"ok": True, "deleted": True},
              {"Set-Cookie": clear_session_cookie(handler)})
    return True


# ---------------------------------------------------------------------------
# Chat handler
# ---------------------------------------------------------------------------
def _save_chat_message(handler, session, user, body) -> bool:
    content = body.get("content")
    if not isinstance(content, str) or not content.strip():
        error(handler, 400, "A message is required.", "content")
        return True
    role = str(body.get("role") or "user").strip().lower()
    if role not in ("user", "assistant", "tool", "system"):
        role = "user"
    provider = zs_auth.sanitize_text(body.get("provider"), 60)

    limit = zs_billing.check_usage_limit(user, "ai")
    if not limit.get("allowed"):
        zs_billing.record_usage(user["id"], "ai", status="blocked")
        error(handler, 402, limit.get("error", "Usage limit reached."))
        return True

    project_id = None
    project_key = str(body.get("projectId") or "").strip()
    if project_key:
        row = zs_db.query_one("SELECT id FROM projects WHERE project_key = ?", (project_key,))
        project_id = int(row["id"]) if row else None

    message_id = zs_data.record_chat(
        user["id"], role, content[:20000], provider, project_id=project_id,
        tool_name=zs_auth.sanitize_text(body.get("toolName"), 120),
        ok=bool(body.get("ok", True)),
        meta=body.get("meta") if isinstance(body.get("meta"), dict) else None,
        session_id=session["id"],
    )
    zs_billing.record_usage(user["id"], "ai", tokens=int(body.get("tokens") or 0))
    send_json(handler, 200, {"ok": True, "id": message_id,
                             "stats": zs_data.chat_stats(user["id"]),
                             "usage": zs_billing.usage_today(user["id"])})
    return True


# ---------------------------------------------------------------------------
# Admin handlers
# ---------------------------------------------------------------------------
def _admin_user_update(handler, actor, body) -> bool:
    role = zs_auth.effective_role(actor)
    if not zs_auth.has_permission(role, "users.write"):
        error(handler, 403, "Your role does not allow this action.")
        return True
    user_id = int(body.get("userId") or 0)
    target = zs_auth.find_user(user_id)
    if target is None:
        error(handler, 404, "Account not found.")
        return True
    updates = {}
    if "displayName" in body:
        updates["display_name"] = zs_auth.sanitize_text(body.get("displayName"), 60)
    if "email" in body:
        try:
            email = zs_auth.validate_email(body.get("email"))
        except zs_auth.ValidationError as exc:
            error(handler, 400, exc.message, exc.field)
            return True
        existing = zs_auth.find_user_by_email(email)
        if existing is not None and existing["id"] != target["id"]:
            error(handler, 409, "That email already belongs to another account.", "email")
            return True
        updates["email"] = email
        updates["email_lower"] = email.lower()
    if "dailyRequestLimit" in body:
        try:
            limit = int(body.get("dailyRequestLimit"))
        except (TypeError, ValueError):
            limit = 0
        updates["daily_request_limit"] = max(0, min(limit, 100000))
    if updates:
        sets = ", ".join(f"{key} = ?" for key in updates)
        zs_db.execute(f"UPDATE users SET {sets}, updated_at = ? WHERE id = ?",  # noqa: S608 - fixed keys
                      list(updates.values()) + [zs_db.now_iso(), user_id])
    zs_auth.audit("admin.user_updated", actor, "user", str(user_id),
                  ", ".join(sorted(updates.keys())) or "none", handler)
    fresh = zs_auth.find_user(user_id)
    send_json(handler, 200, {"ok": True, "user": zs_auth.public_user(fresh, include_private=True)})
    return True


def _admin_user_suspend(handler, actor, body) -> bool:
    role = zs_auth.effective_role(actor)
    if not zs_auth.has_permission(role, "users.suspend"):
        error(handler, 403, "Your role does not allow this action.")
        return True
    user_id = int(body.get("userId") or 0)
    target = zs_auth.find_user(user_id)
    if target is None:
        error(handler, 404, "Account not found.")
        return True
    if target["id"] == actor["id"]:
        error(handler, 400, "You cannot suspend your own account.")
        return True
    status = str(body.get("status") or "suspended").lower()
    if status not in ("active", "suspended", "banned"):
        error(handler, 400, "Unknown account status.")
        return True
    zs_db.execute("UPDATE users SET status = ?, updated_at = ? WHERE id = ?",
                  (status, zs_db.now_iso(), user_id))
    if status != "active":
        zs_auth.revoke_all_sessions(user_id, f"account {status}")
    zs_auth.audit("admin.user_status", actor, "user", str(user_id), status, handler)
    send_json(handler, 200, {"ok": True, "status": status})
    return True


def _admin_user_delete(handler, actor, body) -> bool:
    role = zs_auth.effective_role(actor)
    if not zs_auth.has_permission(role, "users.delete"):
        error(handler, 403, "Only the owner can delete accounts.")
        return True
    user_id = int(body.get("userId") or 0)
    target = zs_auth.find_user(user_id)
    if target is None:
        error(handler, 404, "Account not found.")
        return True
    if target["id"] == actor["id"]:
        error(handler, 400, "You cannot delete your own account here.")
        return True
    zs_db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    zs_auth.audit("admin.user_deleted", actor, "user", str(user_id), target["username"], handler)
    send_json(handler, 200, {"ok": True})
    return True


def _admin_role_grant(handler, actor, body) -> bool:
    role = zs_auth.effective_role(actor)
    target_role = str(body.get("role") or "").lower()
    if target_role not in zs_auth.ROLES:
        error(handler, 400, "Unknown role.")
        return True
    permission = {
        zs_auth.ROLE_MODERATOR: "roles.grant.moderator",
        zs_auth.ROLE_ADMIN: "roles.grant.admin",
        zs_auth.ROLE_OWNER: "roles.grant.owner",
        zs_auth.ROLE_USER: "roles.revoke",
    }[target_role]
    if not zs_auth.has_permission(role, permission):
        error(handler, 403, "Your role cannot grant that permission.")
        return True
    user_id = int(body.get("userId") or 0)
    target = zs_auth.find_user(user_id)
    if target is None:
        error(handler, 404, "Account not found.")
        return True
    zs_db.execute(
        "INSERT INTO admin_roles (user_id, role, granted_by, granted_at, reason) "
        "VALUES (?,?,?,?,?) ON CONFLICT(user_id, role) DO UPDATE SET "
        "revoked_at = NULL, granted_by = excluded.granted_by, granted_at = excluded.granted_at",
        (user_id, target_role, int(actor["id"]), zs_db.now_iso(),
         zs_auth.sanitize_text(body.get("reason"), 200)),
    )
    zs_auth.audit("admin.role_granted", actor, "user", str(user_id), target_role, handler)
    send_json(handler, 200, {"ok": True, "role": target_role,
                             "user": zs_auth.public_user(zs_auth.find_user(user_id))})
    return True


def _admin_role_revoke(handler, actor, body) -> bool:
    role = zs_auth.effective_role(actor)
    if not zs_auth.has_permission(role, "roles.revoke"):
        error(handler, 403, "Your role does not allow this action.")
        return True
    user_id = int(body.get("userId") or 0)
    target_role = str(body.get("role") or "").lower()
    zs_db.execute(
        "UPDATE admin_roles SET revoked_at = ?, reason = ? WHERE user_id = ? AND role = ?",
        (zs_db.now_iso(), "revoked by administrator", user_id, target_role),
    )
    zs_auth.audit("admin.role_revoked", actor, "user", str(user_id), target_role, handler)
    send_json(handler, 200, {"ok": True})
    return True


def _admin_session_revoke(handler, actor, body) -> bool:
    role = zs_auth.effective_role(actor)
    if not zs_auth.has_permission(role, "sessions.revoke"):
        error(handler, 403, "Your role does not allow this action.")
        return True
    session_id = int(body.get("sessionId") or 0)
    row = zs_db.query_one("SELECT * FROM sessions WHERE id = ?", (session_id,))
    if row is None:
        error(handler, 404, "Session not found.")
        return True
    zs_auth.revoke_session(session_id, "revoked by administrator")
    zs_auth.audit("admin.session_revoked", actor, "session", str(session_id), "", handler)
    send_json(handler, 200, {"ok": True})
    return True


def _admin_payment_verify(handler, actor, body) -> bool:
    role = zs_auth.effective_role(actor)
    if not zs_auth.has_permission(role, "payments.verify"):
        error(handler, 403, "Your role does not allow this action.")
        return True
    result = zs_billing.admin_verify_payment(actor, int(body.get("paymentId") or 0))
    if not result.get("ok"):
        error(handler, 400, result.get("error", "Could not verify the payment."))
        return True
    send_json(handler, 200, result)
    return True


def _admin_membership_grant(handler, actor, body) -> bool:
    role = zs_auth.effective_role(actor)
    if not zs_auth.has_permission(role, "memberships.grant"):
        error(handler, 403, "Your role does not allow this action.")
        return True
    user_id = int(body.get("userId") or 0)
    plan = str(body.get("plan") or "").lower()
    target = zs_auth.find_user(user_id)
    if target is None:
        error(handler, 404, "Account not found.")
        return True
    try:
        result = zs_billing.admin_grant_membership(actor, target, plan)
    except ValueError as exc:
        error(handler, 400, str(exc))
        return True
    send_json(handler, 200, result)
    return True


def _admin_backup(handler, actor) -> bool:
    role = zs_auth.effective_role(actor)
    if not zs_auth.has_permission(role, "backup.export.all"):
        error(handler, 403, "Only the owner can export a full installation backup.")
        return True
    backup = zs_data.export_backup(actor, scope="all")
    path = zs_data.write_backup_file(actor, backup)
    zs_auth.audit("admin.backup_exported", actor, "backup", os.path.basename(path), "", handler)
    send_json(handler, 200, {"ok": True, "backup": backup, "filename": os.path.basename(path)})
    return True


# ---------------------------------------------------------------------------
# Link helpers
# ---------------------------------------------------------------------------
def _base_url(handler) -> str:
    try:
        host = handler.headers.get("Host") or "127.0.0.1:17614"
        return f"http://{host}"
    except Exception:
        return "http://127.0.0.1:17614"


def _verification_link(handler, token: str) -> str:
    return f"{_base_url(handler)}/2/login?verify={token}"


def _reset_link(handler, token: str) -> str:
    return f"{_base_url(handler)}/2/login?reset={token}"
