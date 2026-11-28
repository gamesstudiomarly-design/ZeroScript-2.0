# SPDX-License-Identifier: GPL-3.0-or-later
"""ZeroScript 2.0 - automatic persistence hooks.

The runtime modules (project manager, skills manager, plugin SDK and the
Studio Bridge) keep their original behaviour; this module wraps them so that
every change is mirrored into SQLite as it happens:

* a project is created, edited or deleted        -> ``projects`` / ``project_files``
* a skill is saved, toggled or deleted            -> ``installed_skills``
* a plugin is loaded or unloaded                  -> ``installed_plugins``
* the preferences are saved                       -> ``user_settings``
* an AI assistant performs a Studio MCP tool call -> ``chat_history``

The wrappers are deliberately thin: the original return value and error text
are passed through untouched, and a persistence failure never breaks the
feature it is mirroring.
"""
from __future__ import annotations

import json

import zs_data

_installed = False


def _safe(func, *args, **kwargs):
    try:
        func(*args, **kwargs)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Projects
# ---------------------------------------------------------------------------
def patch_projects() -> None:
    import zs_projects

    original_create = zs_projects.create_project
    original_write = zs_projects.write_file
    original_delete = zs_projects.delete_project

    def create_project(name, template="blank"):
        ok, result = original_create(name, template)
        if ok and isinstance(result, dict):
            project_key = result.get("id")
            try:
                zs_data.upsert_project(project_key, result.get("name") or project_key,
                                       template, zs_projects._proj_dir(project_key))
                for file_name in zs_projects.list_files(project_key):
                    content = zs_projects.read_file(project_key, file_name)
                    zs_data.upsert_project_file(project_key, file_name, content or "")
            except Exception:
                pass
        return ok, result

    def write_file(project_id, file_name, content):
        ok, err = original_write(project_id, file_name, content)
        if ok:
            _safe(zs_data.upsert_project_file, project_id, file_name, content or "")
        return ok, err

    def delete_project(project_id):
        ok, err = original_delete(project_id)
        if ok:
            _safe(zs_data.delete_project, project_id)
        return ok, err

    zs_projects.create_project = create_project
    zs_projects.write_file = write_file
    zs_projects.delete_project = delete_project


# ---------------------------------------------------------------------------
# Skills and preferences
# ---------------------------------------------------------------------------
def patch_skills() -> None:
    import skills_manager

    original_save_skill = skills_manager.save_skill
    original_toggle_skill = skills_manager.toggle_skill
    original_delete_skill = skills_manager.delete_skill
    original_save_settings = skills_manager.save_settings

    def save_skill(data):
        ok, result = original_save_skill(data)
        if ok and isinstance(result, dict):
            _safe(zs_data.sync_skill_for_all, result.get("id"), result.get("name") or "",
                  result.get("mode") or "auto", bool(result.get("enabled", True)))
        return ok, result

    def toggle_skill(skill_id, enabled=None, mode=None):
        ok, result = original_toggle_skill(skill_id, enabled=enabled, mode=mode)
        if ok and isinstance(result, dict):
            _safe(zs_data.sync_skill_for_all, result.get("id") or skill_id,
                  result.get("name") or "", result.get("mode") or "auto",
                  bool(result.get("enabled", True)))
        return ok, result

    def delete_skill(skill_id):
        ok, err = original_delete_skill(skill_id)
        if ok:
            _safe(zs_data.remove_skill_for_all, skill_id)
        return ok, err

    def save_settings(patch):
        config = original_save_settings(patch)
        _safe(zs_data.save_preferences_for_all, config)
        return config

    skills_manager.save_skill = save_skill
    skills_manager.toggle_skill = toggle_skill
    skills_manager.delete_skill = delete_skill
    skills_manager.save_settings = save_settings


# ---------------------------------------------------------------------------
# Plugins
# ---------------------------------------------------------------------------
def patch_plugins() -> None:
    import zs_plugins

    original_load = zs_plugins.load
    original_unload = zs_plugins.unload

    def load(plugin_id):
        ok, result = original_load(plugin_id)
        if ok:
            manifest = result if isinstance(result, dict) else {}
            _safe(zs_data.sync_plugin_for_all, plugin_id, manifest.get("name") or plugin_id,
                  manifest.get("version") or "", True, "library", manifest)
        return ok, result

    def unload(plugin_id):
        ok, err = original_unload(plugin_id)
        if ok:
            _safe(zs_data.remove_plugin_for_all, plugin_id)
        return ok, err

    zs_plugins.load = load
    zs_plugins.unload = unload


# ---------------------------------------------------------------------------
# Studio Bridge - AI conversations
# ---------------------------------------------------------------------------
def patch_bridge() -> None:
    import bridge

    original_record = bridge.record_activity

    def record_activity(name, args, res, elapsed_s, server_override=None):
        try:
            original_record(name, args, res, elapsed_s, server_override)
        finally:
            _save_tool_conversation(name, args, res, elapsed_s, server_override)

    bridge.record_activity = record_activity


def _save_tool_conversation(name, args, res, elapsed_s, server_override) -> None:
    """Store one MCP tool call as a conversation turn."""
    user_id = zs_data.current_user_id()
    if not user_id:
        return
    try:
        try:
            arguments = json.dumps(args or {}, ensure_ascii=False)[:4000]
        except Exception:
            arguments = str(args or {})[:4000]
        ok = bool(res.get("ok")) if isinstance(res, dict) else True
        output = ""
        if isinstance(res, dict):
            output = str(res.get("text") if ok else (res.get("error") or res.get("text") or ""))[:4000]
        content = f"{name}\n{arguments}\n{output}".strip()
        zs_data.record_chat(
            user_id,
            "tool",
            content,
            provider=str(server_override or "studio"),
            tool_name=str(name or "")[:120],
            ok=ok,
            meta={"ms": int(round(float(elapsed_s or 0.0) * 1000))},
        )
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def install() -> None:
    """Attach every persistence hook. Safe to call more than once."""
    global _installed
    if _installed:
        return
    for patcher in (patch_projects, patch_skills, patch_plugins, patch_bridge):
        try:
            patcher()
        except Exception as exc:
            print(f"[zs_persist] {patcher.__name__} could not be attached: {exc}")
    _installed = True
