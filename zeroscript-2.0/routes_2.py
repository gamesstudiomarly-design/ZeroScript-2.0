# SPDX-License-Identifier: GPL-3.0-or-later
"""ZeroScript 2.0 - HTTP routes for all new systems.

Import this in app2.py and call handle_new_routes(handler, path, body)
from AppHandler.do_GET / do_POST. Returns True if the route was handled.
"""
import json

import zs_ai
import zs_assets
import zs_debug
import zs_editor
import zs_misc
import zs_plugins
import zs_projects
import zs_uibuilder


def _json(handler, code, obj):
    handler._send_json(code, obj)


def handle_get(handler, path):
    # Editor
    if path == "/api2/editor/docs":
        return _json(handler, 200, {"ok": True, "docs": zs_editor.list_docs()}), True
    if path == "/api2/editor/autocomplete":
        qs = handler.path.split("?", 1)[-1]
        params = dict(p.split("=", 1) for p in qs.split("&") if "=" in p)
        prefix = params.get("prefix", "")
        code = params.get("code", "")
        return _json(handler, 200, {"ok": True, "items": zs_editor.autocomplete(prefix, code)}), True
    # Debug
    if path == "/api2/debug/output":
        return _json(handler, 200, {"ok": True, "items": zs_debug.get_output()}), True
    if path == "/api2/debug/errors":
        return _json(handler, 200, {"ok": True, "errors": zs_debug.get_errors(),
                                    "warnings": zs_debug.get_warnings(),
                                    "summary": zs_debug.summary()}), True
    # Assets
    if path == "/api2/assets":
        return _json(handler, 200, {"ok": True, "assets": zs_assets.list_assets(),
                                    "summary": zs_assets.summary()}), True
    # Projects
    if path == "/api2/projects":
        return _json(handler, 200, {"ok": True, "projects": zs_projects.list_projects(),
                                    "recent": zs_projects.get_recent()}), True
    # Plugins
    if path == "/api2/plugins":
        return _json(handler, 200, {"ok": True, "available": zs_plugins.discover(),
                                    "loaded": zs_plugins.list_loaded()}), True
    # UI Builder
    if path == "/api2/uibuilder/components":
        return _json(handler, 200, {"ok": True, "components": zs_uibuilder.list_components()}), True
    # Script Library
    if path == "/api2/library":
        return _json(handler, 200, {"ok": True, "items": zs_misc.library_list()}), True
    return None, False


def handle_post(handler, path, body):
    # Editor
    if path == "/api2/editor/save":
        ok, res = zs_editor.save_doc(body)
        return _json(handler, 200 if ok else 400,
                     {"ok": ok, "doc": res if ok else None, "error": None if ok else res}), True
    if path == "/api2/editor/format":
        return _json(handler, 200, {"ok": True, "code": zs_editor.format_code(body.get("code", ""))}), True
    if path == "/api2/editor/diagnostics":
        return _json(handler, 200, {"ok": True, "diagnostics": zs_editor.diagnostics(body.get("code", ""))}), True
    if path == "/api2/editor/highlight":
        return _json(handler, 200, {"ok": True, "tokens": zs_editor.highlight(body.get("code", ""))}), True
    # AI Assistant
    if path == "/api2/ai/prompt":
        action = body.get("action", "generate")
        prompt = zs_ai.build_prompt(action, body.get("input", ""))
        return _json(handler, 200, {"ok": True, "prompt": prompt,
                                    "action": action}), True
    if path == "/api2/ai/local":
        action = body.get("action", "generate")
        text = body.get("input", "")
        if action == "generate":
            result = zs_ai.local_generate(text)
        elif action == "explain":
            result = zs_ai.local_explain(text)
        elif action == "fix":
            result = zs_ai.local_fix(text)
        else:
            result = text
        return _json(handler, 200, {"ok": True, "result": result, "action": action}), True
    # Debug
    if path == "/api2/debug/clear":
        return _json(handler, 200, {"ok": zs_debug.clear()}), True
    if path == "/api2/debug/ingest":
        zs_debug.ingest(body.get("msg", ""), body.get("source", "manual"))
        return _json(handler, 200, {"ok": True}), True
    # Assets
    if path == "/api2/assets/add":
        ok, res = zs_assets.add_asset(body)
        return _json(handler, 200 if ok else 400,
                     {"ok": ok, "asset": res if ok else None, "error": None if ok else res}), True
    if path == "/api2/assets/favorite":
        ok, res = zs_assets.toggle_favorite(body.get("id"))
        return _json(handler, 200 if ok else 404,
                     {"ok": ok, "asset": res if ok else None, "error": None if ok else res}), True
    if path == "/api2/assets/delete":
        ok, err = zs_assets.delete_asset(body.get("id"))
        return _json(handler, 200 if ok else 404,
                     {"ok": ok, "error": None if ok else err}), True
    if path == "/api2/assets/collection":
        ok, res = zs_assets.add_collection(body.get("name"))
        return _json(handler, 200 if ok else 400,
                     {"ok": ok, "collections": res if ok else None, "error": None if ok else res}), True
    if path == "/api2/assets/unused":
        return _json(handler, 200, {"ok": True,
                                    "unused": zs_assets.find_unused(body.get("corpus", ""))}), True
    # Projects
    if path == "/api2/projects/create":
        ok, res = zs_projects.create_project(body.get("name"), body.get("template", "blank"))
        return _json(handler, 200 if ok else 400,
                     {"ok": ok, "project": res if ok else None, "error": None if ok else res}), True
    if path == "/api2/projects/delete":
        ok, err = zs_projects.delete_project(body.get("id"))
        return _json(handler, 200 if ok else 404,
                     {"ok": ok, "error": None if ok else err}), True
    if path == "/api2/projects/backup":
        ok, res = zs_projects.backup(body.get("id"))
        return _json(handler, 200 if ok else 400,
                     {"ok": ok, "backup": res if ok else None, "error": None if ok else res}), True
    if path == "/api2/projects/export":
        ok, res = zs_projects.export_project(body.get("id"))
        return _json(handler, 200 if ok else 404,
                     {"ok": ok, "data": res if ok else None, "error": None if ok else res}), True
    if path == "/api2/projects/import":
        ok, res = zs_projects.import_project(body)
        return _json(handler, 200 if ok else 400,
                     {"ok": ok, "project": res if ok else None, "error": None if ok else res}), True
    if path == "/api2/projects/health":
        return _json(handler, 200, {"ok": True, "health": zs_projects.health_check(body.get("id"))}), True
    if path == "/api2/projects/files":
        pid = body.get("id")
        fname = body.get("file")
        if body.get("action") == "write":
            ok, err = zs_projects.write_file(pid, fname, body.get("content", ""))
            return _json(handler, 200 if ok else 400,
                         {"ok": ok, "error": None if ok else err}), True
        return _json(handler, 200, {"ok": True, "files": zs_projects.list_files(pid),
                                    "content": zs_projects.read_file(pid, fname)}), True
    # Plugins
    if path == "/api2/plugins/load":
        ok, res = zs_plugins.load(body.get("id"))
        return _json(handler, 200 if ok else 400,
                     {"ok": ok, "manifest": res if ok else None, "error": None if ok else res}), True
    if path == "/api2/plugins/unload":
        ok, err = zs_plugins.unload(body.get("id"))
        return _json(handler, 200 if ok else 404,
                     {"ok": ok, "error": None if ok else err}), True
    # UI Builder
    if path == "/api2/uibuilder/build":
        return _json(handler, 200, {"ok": True,
                                    "code": zs_uibuilder.build_luau(body.get("tree") or {})}), True
    # Script Library
    if path == "/api2/library/save":
        ok, res = zs_misc.library_save(body.get("title"), body.get("code"), body.get("tags"))
        return _json(handler, 200 if ok else 400,
                     {"ok": ok, "item": res if ok else None, "error": None if ok else res}), True
    if path == "/api2/library/delete":
        ok = zs_misc.library_delete(body.get("title"))
        return _json(handler, 200 if ok else 404,
                     {"ok": ok}), True
    # Misc
    if path == "/api2/misc/deps":
        return _json(handler, 200, {"ok": True,
                                    "analysis": zs_misc.analyze_dependencies(body.get("files") or {})}), True
    if path == "/api2/misc/security":
        return _json(handler, 200, {"ok": True,
                                    "scan": zs_misc.security_scan(body.get("code", ""))}), True
    if path == "/api2/misc/diff":
        return _json(handler, 200, {"ok": True,
                                    "diff": zs_misc.diff(body.get("old", ""), body.get("new", ""))}), True
    if path == "/api2/misc/history":
        if body.get("action") == "restore":
            code = zs_misc.history_restore(body.get("file"), body.get("version"))
            return _json(handler, 200 if code is not None else 404,
                         {"ok": code is not None, "code": code}), True
        if body.get("action") == "snapshot":
            ok, ver = zs_misc.snapshot(body.get("file"), body.get("code", ""), body.get("note", ""))
            return _json(handler, 200 if ok else 400,
                         {"ok": ok, "version": ver if ok else None}), True
        return _json(handler, 200, {"ok": True,
                                    "history": zs_misc.history_list(body.get("file"))}), True
    return None, False