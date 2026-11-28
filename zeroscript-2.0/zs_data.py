# SPDX-License-Identifier: GPL-3.0-or-later
"""ZeroScript 2.0 - Persistent data bridge.

Everything the application used to keep in loose JSON files or in memory is
mirrored into SQLite here:

* projects and their files            -> ``projects`` / ``project_files``
* AI conversations and tool activity  -> ``chat_history``
* installed plugins and skills        -> ``installed_plugins`` / ``installed_skills``
* user preferences and workspace      -> ``user_settings``
* membership state                    -> ``memberships`` (see :mod:`zs_billing`)

The on-disk formats stay exactly as they were, so nothing that already works
breaks: the database is a durable mirror plus the source of truth for
accounts, sessions and preferences.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import time

import zs_auth
import zs_billing
import zs_db

# ---------------------------------------------------------------------------
# Projects
# ---------------------------------------------------------------------------
def upsert_project(project_key: str, name: str, template: str = "", path: str = "",
                   user_id: int | None = None, description: str = "") -> int:
    """Mirror a project into the database. Returns the project row id."""
    key = str(project_key or "").strip()[:120]
    if not key:
        raise ValueError("project key required")
    stamp = zs_db.now_iso()
    row = zs_db.query_one("SELECT id FROM projects WHERE project_key = ?", (key,))
    if row is None:
        cur = zs_db.execute(
            "INSERT INTO projects (user_id, project_key, name, template, description, path, "
            "is_global, created_at, updated_at, last_opened_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (user_id, key, str(name or key)[:160], str(template or "")[:40],
             str(description or "")[:400], str(path or "")[:400], 1, stamp, stamp, stamp),
        )
        return cur.lastrowid
    zs_db.execute(
        "UPDATE projects SET name = ?, template = ?, description = ?, path = ?, updated_at = ? "
        "WHERE id = ?",
        (str(name or key)[:160], str(template or "")[:40], str(description or "")[:400],
         str(path or "")[:400], stamp, row["id"]),
    )
    return int(row["id"])


def touch_project(project_key: str) -> None:
    zs_db.execute(
        "UPDATE projects SET last_opened_at = ?, updated_at = ? WHERE project_key = ?",
        (zs_db.now_iso(), zs_db.now_iso(), str(project_key)),
    )


def delete_project(project_key: str) -> None:
    zs_db.execute("DELETE FROM projects WHERE project_key = ?", (str(project_key),))


def upsert_project_file(project_key: str, name: str, content: str) -> None:
    project = zs_db.query_one("SELECT id FROM projects WHERE project_key = ?", (str(project_key),))
    if project is None:
        project_id = upsert_project(project_key, project_key)
    else:
        project_id = int(project["id"])
    text = content if isinstance(content, str) else ""
    stamp = zs_db.now_iso()
    checksum = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()
    existing = zs_db.query_one(
        "SELECT id FROM project_files WHERE project_id = ? AND name = ?",
        (project_id, str(name)),
    )
    if existing is None:
        zs_db.execute(
            "INSERT INTO project_files (project_id, name, path, content, size, checksum, "
            "created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)",
            (project_id, str(name)[:200], str(name)[:400], text, len(text.encode("utf-8")),
             checksum, stamp, stamp),
        )
    else:
        zs_db.execute(
            "UPDATE project_files SET content = ?, size = ?, checksum = ?, updated_at = ? "
            "WHERE id = ?",
            (text, len(text.encode("utf-8")), checksum, stamp, existing["id"]),
        )


def delete_project_file(project_key: str, name: str) -> None:
    project = zs_db.query_one("SELECT id FROM projects WHERE project_key = ?", (str(project_key),))
    if project is None:
        return
    zs_db.execute(
        "DELETE FROM project_files WHERE project_id = ? AND name = ?",
        (int(project["id"]), str(name)),
    )


def list_projects() -> list:
    return zs_db.rows_to_dicts(
        zs_db.query("SELECT * FROM projects ORDER BY updated_at DESC")
    )


def list_project_files(project_key: str) -> list:
    project = zs_db.query_one("SELECT id FROM projects WHERE project_key = ?", (str(project_key),))
    if project is None:
        return []
    return zs_db.rows_to_dicts(
        zs_db.query(
            "SELECT id, name, path, size, checksum, created_at, updated_at "
            "FROM project_files WHERE project_id = ? ORDER BY name",
            (int(project["id"]),),
        )
    )


def sync_all_projects() -> dict:
    """Mirror every on-disk project (and its files) into the database."""
    try:
        import zs_projects
    except Exception:
        return {"projects": 0, "files": 0, "error": "project module unavailable"}
    projects = 0
    files = 0
    try:
        entries = zs_projects.list_projects()
    except Exception:
        entries = []
    known = set()
    for project in entries:
        key = str(project.get("id") or "")
        if not key:
            continue
        known.add(key)
        upsert_project(key, project.get("name") or key, project.get("template") or "",
                       zs_projects._proj_dir(key))
        projects += 1
        try:
            for file_name in zs_projects.list_files(key):
                content = zs_projects.read_file(key, file_name)
                upsert_project_file(key, file_name, content or "")
                files += 1
        except Exception:
            continue
    # Drop rows for projects that no longer exist on disk.
    for row in zs_db.query("SELECT project_key FROM projects"):
        if row["project_key"] not in known:
            delete_project(row["project_key"])
    return {"projects": projects, "files": files}


# ---------------------------------------------------------------------------
# Chat history / AI conversations
# ---------------------------------------------------------------------------
def record_chat(user_id, role: str, content: str, provider: str = "", project_id=None,
                tool_name: str = "", ok: bool = True, meta: dict | None = None,
                session_id=None) -> int:
    """Persist one conversation turn."""
    try:
        text = content if isinstance(content, str) else str(content)
        cur = zs_db.execute(
            "INSERT INTO chat_history (user_id, session_id, role, content, provider, "
            "project_id, tool_name, ok, meta, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (int(user_id) if user_id else None,
             int(session_id) if session_id else None,
             str(role or "user")[:20], text[:20000], str(provider or "")[:60],
             int(project_id) if project_id else None, str(tool_name or "")[:120],
             1 if ok else 0,
             json.dumps(meta or {}, ensure_ascii=False)[:2000], zs_db.now_iso()),
        )
        return cur.lastrowid
    except sqlite3.Error:
        return 0


def recent_chat(user_id: int, limit: int = 100, project_id=None) -> list:
    sql = "SELECT * FROM chat_history WHERE user_id = ?"
    params: list = [int(user_id)]
    if project_id:
        sql += " AND project_id = ?"
        params.append(int(project_id))
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(max(1, min(int(limit), 500)))
    rows = zs_db.rows_to_dicts(zs_db.query(sql, params))
    rows.reverse()
    return rows


def chat_stats(user_id: int) -> dict:
    row = zs_db.query_one(
        "SELECT COUNT(*) AS c, MIN(created_at) AS first_at FROM chat_history WHERE user_id = ?",
        (int(user_id),),
    )
    return {"messages": int(row["c"]) if row else 0,
            "firstAt": row["first_at"] if row else None}


def clear_chat(user_id: int) -> int:
    cur = zs_db.execute("DELETE FROM chat_history WHERE user_id = ?", (int(user_id),))
    return cur.rowcount or 0


# ---------------------------------------------------------------------------
# Installed plugins and skills
# ---------------------------------------------------------------------------
def upsert_plugin(user_id, plugin_id: str, name: str = "", version: str = "",
                  enabled: bool = True, source: str = "local", manifest=None) -> None:
    stamp = zs_db.now_iso()
    payload = json.dumps(manifest or {}, ensure_ascii=False)[:8000]
    zs_db.execute(
        "INSERT INTO installed_plugins (user_id, plugin_id, name, version, enabled, source, "
        "manifest, installed_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?) "
        "ON CONFLICT(user_id, plugin_id) DO UPDATE SET name = excluded.name, "
        "version = excluded.version, enabled = excluded.enabled, manifest = excluded.manifest, "
        "updated_at = excluded.updated_at",
        (int(user_id), str(plugin_id)[:120], str(name or "")[:160], str(version or "")[:40],
         1 if enabled else 0, str(source or "local")[:40], payload, stamp, stamp),
    )


def remove_plugin(user_id, plugin_id: str) -> None:
    zs_db.execute(
        "DELETE FROM installed_plugins WHERE user_id = ? AND plugin_id = ?",
        (int(user_id), str(plugin_id)),
    )


def upsert_skill(user_id, skill_id: str, name: str = "", mode: str = "auto",
                 enabled: bool = True, source: str = "local") -> None:
    stamp = zs_db.now_iso()
    zs_db.execute(
        "INSERT INTO installed_skills (user_id, skill_id, name, mode, enabled, source, "
        "installed_at, updated_at) VALUES (?,?,?,?,?,?,?,?) "
        "ON CONFLICT(user_id, skill_id) DO UPDATE SET name = excluded.name, mode = excluded.mode, "
        "enabled = excluded.enabled, updated_at = excluded.updated_at",
        (int(user_id), str(skill_id)[:120], str(name or "")[:160], str(mode or "auto")[:40],
         1 if enabled else 0, str(source or "local")[:40], stamp, stamp),
    )


def remove_skill(user_id, skill_id: str) -> None:
    zs_db.execute(
        "DELETE FROM installed_skills WHERE user_id = ? AND skill_id = ?",
        (int(user_id), str(skill_id)),
    )


def sync_skills(user_id) -> dict:
    """Mirror the skill library into ``installed_skills``."""
    try:
        import skills_manager
        skills = skills_manager.list_skills(include_content=False)
    except Exception:
        return {"skills": 0, "error": "skills manager unavailable"}
    count = 0
    known = set()
    for skill in skills:
        skill_id = str(skill.get("id") or "")
        if not skill_id:
            continue
        known.add(skill_id)
        upsert_skill(user_id, skill_id, skill.get("name") or skill_id,
                     skill.get("mode") or "auto", skill.get("enabled", True), "library")
        count += 1
    for row in zs_db.query("SELECT skill_id FROM installed_skills WHERE user_id = ?", (int(user_id),)):
        if row["skill_id"] not in known:
            remove_skill(user_id, row["skill_id"])
    return {"skills": count}


def sync_plugins(user_id) -> dict:
    """Mirror discovered plugins into ``installed_plugins``."""
    try:
        import zs_plugins
        plugins = zs_plugins.discover()
        loaded = {item["id"] for item in zs_plugins.list_loaded()}
    except Exception:
        return {"plugins": 0, "error": "plugin sdk unavailable"}
    count = 0
    known = set()
    for plugin in plugins:
        plugin_id = str(plugin.get("id") or "")
        if not plugin_id:
            continue
        known.add(plugin_id)
        upsert_plugin(user_id, plugin_id, plugin.get("name") or plugin_id,
                      plugin.get("version") or "", plugin_id in loaded, "library", plugin)
        count += 1
    for row in zs_db.query("SELECT plugin_id FROM installed_plugins WHERE user_id = ?", (int(user_id),)):
        if row["plugin_id"] not in known:
            remove_plugin(user_id, row["plugin_id"])
    return {"plugins": count}


# ---------------------------------------------------------------------------
# The skills, plugins and preferences live on disk and are shared by the
# local install.  When they change the mirror is updated for every account so
# the per-user tables stay truthful.
# ---------------------------------------------------------------------------
def sync_skill_for_all(skill_id: str, name: str = "", mode: str = "auto",
                        enabled: bool = True, source: str = "library") -> None:
    for row in zs_db.query("SELECT id FROM users"):
        upsert_skill(row["id"], skill_id, name or skill_id, mode, enabled, source)


def remove_skill_for_all(skill_id: str) -> None:
    for row in zs_db.query("SELECT id FROM users"):
        remove_skill(row["id"], skill_id)


def sync_plugin_for_all(plugin_id: str, name: str = "", version: str = "",
                        enabled: bool = True, source: str = "library",
                        manifest=None) -> None:
    for row in zs_db.query("SELECT id FROM users"):
        upsert_plugin(row["id"], plugin_id, name or plugin_id, version, enabled, source, manifest)


def remove_plugin_for_all(plugin_id: str) -> None:
    for row in zs_db.query("SELECT id FROM users"):
        remove_plugin(row["id"], plugin_id)


def save_preferences_for_all(settings: dict) -> None:
    for row in zs_db.query("SELECT id FROM users"):
        save_preferences(row["id"], settings)


# ---------------------------------------------------------------------------
# The account that is currently driving the workspace.  The Studio Bridge
# runs on its own threads and has no session, so the last authenticated
# request decides who its tool activity belongs to.
# ---------------------------------------------------------------------------
_current_user_id = None


def set_current_user(user_id) -> None:
    global _current_user_id
    try:
        _current_user_id = int(user_id) if user_id is not None else None
    except (TypeError, ValueError):
        _current_user_id = None


def current_user_id():
    return _current_user_id


# ---------------------------------------------------------------------------
# Preferences and workspace restore
# ---------------------------------------------------------------------------
def save_preferences(user_id: int, settings: dict) -> None:
    """Store the UI preferences from ``skills_manager`` for this account."""
    if not isinstance(settings, dict):
        return
    allowed = {
        "userName", "accentTheme", "liquidGlass", "liquidBackdrop", "glassStyle",
        "ambientMotion", "favoriteProviders", "globalPrompt", "minimizeToTray",
        "autoOpenWindow", "appPort",
    }
    for key in allowed:
        if key in settings:
            zs_auth.set_user_setting(user_id, f"pref.{key}", settings[key])


def load_preferences(user_id: int) -> dict:
    out = {}
    for key, value in zs_auth.get_user_settings(user_id).items():
        if not key.startswith("pref."):
            continue
        raw = key[5:]
        try:
            out[raw] = json.loads(value)
        except (TypeError, ValueError):
            out[raw] = value
    return out


def save_workspace(user_id: int, workspace: dict) -> None:
    """Remember the open view, project and files so the app can be restored."""
    if not isinstance(workspace, dict):
        return
    payload = {
        "view": str(workspace.get("view") or "home")[:40],
        "subtab": str(workspace.get("subtab") or "")[:40],
        "projectId": str(workspace.get("projectId") or "")[:120],
        "openFiles": [str(f)[:200] for f in (workspace.get("openFiles") or [])][:50],
        "activeProvider": str(workspace.get("activeProvider") or "")[:60],
        "savedAt": zs_db.now_iso(),
    }
    zs_auth.set_user_settings_json(user_id, "workspace", payload)


def load_workspace(user_id: int) -> dict:
    data = zs_auth.get_user_settings_json(user_id, "workspace", None)
    if not isinstance(data, dict):
        return {}
    return data


# ---------------------------------------------------------------------------
# Manual save
# ---------------------------------------------------------------------------
def manual_save(user_row) -> dict:
    """Flush every mirrored collection to the database on demand."""
    user_id = int(user_row["id"])
    result = {"projects": 0, "files": 0, "skills": 0, "plugins": 0, "savedAt": zs_db.now_iso()}
    project_result = sync_all_projects()
    result["projects"] = project_result.get("projects", 0)
    result["files"] = project_result.get("files", 0)
    skill_result = sync_skills(user_id)
    result["skills"] = skill_result.get("skills", 0)
    plugin_result = sync_plugins(user_id)
    result["plugins"] = plugin_result.get("plugins", 0)
    try:
        import skills_manager
        save_preferences(user_id, skills_manager.load_settings())
        result["preferences"] = True
    except Exception:
        result["preferences"] = False
    zs_auth.audit("data.manual_save", user_row, "user", str(user_id),
                  "Manual save of projects, skills, plugins and preferences")
    return result


# ---------------------------------------------------------------------------
# Backup export / restore
# ---------------------------------------------------------------------------
def export_backup(user_row, scope: str = "self") -> dict:
    """Build a portable JSON backup of the caller's data (or the whole install)."""
    user_id = int(user_row["id"])
    is_admin = zs_auth.has_permission(zs_auth.effective_role(user_row), "backup.export.all")
    include_all = scope == "all" and is_admin
    if scope == "all" and not is_admin:
        raise PermissionError("Only the owner can export a full installation backup.")

    def _rows(sql, params=()):
        return zs_db.rows_to_dicts(zs_db.query(sql, params))

    backup = {
        "format": "zeroscript-backup",
        "version": 1,
        "createdAt": zs_db.now_iso(),
        "scope": "all" if include_all else "self",
        "user": zs_auth.public_user(user_row),
        "projects": _rows("SELECT * FROM projects"),
        "projectFiles": _rows("SELECT * FROM project_files"),
        "installedPlugins": _rows("SELECT * FROM installed_plugins"),
        "installedSkills": _rows("SELECT * FROM installed_skills"),
        "userSettings": _rows("SELECT * FROM user_settings"),
        "memberships": _rows("SELECT * FROM memberships"),
        "chatHistory": _rows("SELECT * FROM chat_history ORDER BY id"),
        "usageRecords": _rows("SELECT * FROM usage_records ORDER BY id"),
        "notifications": _rows("SELECT * FROM notifications"),
        "payments": _rows("SELECT * FROM payments"),
        "sessions": _rows(
            "SELECT id, user_id, persistent, created_at, last_seen_at, expires_at, revoked_at "
            "FROM sessions"),
    }
    if include_all:
        backup["users"] = [
            {k: v for k, v in row.items() if k != "password_hash"}
            for row in _rows("SELECT * FROM users")
        ]
        backup["adminRoles"] = _rows("SELECT * FROM admin_roles")
        backup["auditLogs"] = _rows("SELECT * FROM audit_logs ORDER BY id")
    else:
        # Only the caller's own rows.
        for key in ("chatHistory", "usageRecords", "notifications", "payments", "userSettings",
                    "installedPlugins", "installedSkills", "memberships"):
            backup[key] = [row for row in backup.get(key, []) if row.get("user_id") == user_id]
    # Never export password material or raw session tokens.
    backup.pop("users", None) if not include_all else None
    for key in list(backup.keys()):
        if isinstance(backup[key], list):
            backup[key] = [
                {k: v for k, v in row.items() if k not in ("password_hash", "token_hash", "csrf_token")}
                for row in backup[key]
            ]
    return backup


def restore_backup(actor, backup: dict, mode: str = "merge") -> dict:
    """Restore a backup produced by :func:`export_backup`.

    Only the owner may restore a full installation backup.  Password hashes
    are never written back, so a restore cannot be used to take over an
    account.
    """
    if not isinstance(backup, dict) or backup.get("format") != "zeroscript-backup":
        raise ValueError("Not a ZeroScript backup file.")
    role = zs_auth.effective_role(actor)
    scope = backup.get("scope", "self")
    if scope == "all" and not zs_auth.has_permission(role, "backup.restore"):
        raise PermissionError("Only the owner can restore a full installation backup.")

    restored = {}
    stamp = zs_db.now_iso()

    for row in backup.get("projects") or []:
        upsert_project(row.get("project_key"), row.get("name"), row.get("template"),
                       row.get("path"), row.get("user_id"))
        restored["projects"] = restored.get("projects", 0) + 1

    project_map = {}
    for row in zs_db.query("SELECT id, project_key FROM projects"):
        project_map[row["project_key"]] = int(row["id"])
    for row in backup.get("projectFiles") or []:
        project_id = row.get("project_id")
        key = None
        for candidate, value in project_map.items():
            if value == project_id:
                key = candidate
                break
        if key is None:
            continue
        upsert_project_file(key, row.get("name"), row.get("content") or "")
        restored["projectFiles"] = restored.get("projectFiles", 0) + 1

    for row in backup.get("installedSkills") or []:
        upsert_skill(row.get("user_id"), row.get("skill_id"), row.get("name"),
                     row.get("mode"), bool(row.get("enabled", 1)), row.get("source") or "restore")
        restored["installedSkills"] = restored.get("installedSkills", 0) + 1

    for row in backup.get("installedPlugins") or []:
        upsert_plugin(row.get("user_id"), row.get("plugin_id"), row.get("name"),
                      row.get("version"), bool(row.get("enabled", 1)),
                      row.get("source") or "restore")
        restored["installedPlugins"] = restored.get("installedPlugins", 0) + 1

    for row in backup.get("userSettings") or []:
        if row.get("user_id") is None:
            continue
        zs_auth.set_user_setting(row["user_id"], row.get("key"), row.get("value"))
        restored["userSettings"] = restored.get("userSettings", 0) + 1

    for row in backup.get("chatHistory") or []:
        record_chat(row.get("user_id"), row.get("role") or "user", row.get("content") or "",
                    row.get("provider") or "", project_id=None, tool_name=row.get("tool_name") or "",
                    ok=bool(row.get("ok", 1)))
        restored["chatHistory"] = restored.get("chatHistory", 0) + 1

    if mode == "replace":
        zs_db.execute("DELETE FROM chat_history")
        zs_db.execute("DELETE FROM usage_records")

    zs_auth.audit("data.restore", actor, "backup", "", f"restored: {restored}")
    return {"ok": True, "restored": restored, "restoredAt": stamp}


def write_backup_file(user_row, backup: dict) -> str:
    """Write a backup next to the database and return its path."""
    zs_db.ensure_dirs()
    stamp = zs_db.now_iso().replace(":", "").replace("-", "")
    path = os.path.join(zs_db.DATA_DIR, f"zeroscript-backup-{stamp}.json")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(backup, handle, ensure_ascii=False, indent=2)
    return path


def install_backup_file(path: str) -> dict:
    """Read a backup file from disk (used by the admin panel)."""
    if not os.path.isfile(path):
        raise FileNotFoundError(path)
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def cleanup_old_backups(keep: int = 10) -> int:
    try:
        zs_db.ensure_dirs()
        files = sorted(
            (f for f in os.listdir(zs_db.DATA_DIR) if f.startswith("zeroscript-backup-")),
            reverse=True,
        )
        removed = 0
        for name in files[max(0, int(keep)):]:
            try:
                os.remove(os.path.join(zs_db.DATA_DIR, name))
                removed += 1
            except OSError:
                pass
        return removed
    except OSError:
        return 0
