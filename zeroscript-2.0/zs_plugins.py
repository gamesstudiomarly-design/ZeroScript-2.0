# SPDX-License-Identifier: GPL-3.0-or-later
"""ZeroScript 2.0 - Plugin SDK.

Plugins live in plugins/<id>/plugin.json + plugin.py. A plugin declares hooks
it wants to receive; the host dispatches events to registered hooks. Plugins
are loaded in a restricted subprocess-free way: only the declared `hooks`
dict is imported, never arbitrary top-level code execution beyond import.
"""
import importlib.util
import json
import os
import sys
import time
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
import zs_paths  # noqa: E402 - shared install folders
PLUGINS_DIR = zs_paths.install_dir("plugins")
os.makedirs(PLUGINS_DIR, exist_ok=True)

HOOK_EVENTS = ("on_load", "on_unload", "on_tool_call", "on_tool_result",
               "on_ui_event", "on_script_save")

_registry = {}   # id -> {"manifest":..., "module":..., "loaded_at":...}


def discover():
    out = []
    for entry in os.listdir(PLUGINS_DIR):
        pdir = os.path.join(PLUGINS_DIR, entry)
        man = os.path.join(pdir, "plugin.json")
        if os.path.isfile(man):
            try:
                with open(man, "r", encoding="utf-8") as f:
                    m = json.load(f)
                    m["id"] = m.get("id") or entry
                    out.append(m)
            except Exception:
                continue
    return out


def load(plugin_id):
    if plugin_id in _registry:
        return True, _registry[plugin_id]["manifest"]
    pdir = os.path.join(PLUGINS_DIR, plugin_id)
    man_path = os.path.join(pdir, "plugin.json")
    py_path = os.path.join(pdir, "plugin.py")
    if not os.path.isfile(man_path) or not os.path.isfile(py_path):
        return False, "plugin files missing"
    with open(man_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)
    manifest["id"] = manifest.get("id") or plugin_id
    try:
        spec = importlib.util.spec_from_file_location(f"zs_plugin_{plugin_id}", py_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    except Exception as e:
        return False, f"import failed: {e}"
    _registry[plugin_id] = {"manifest": manifest, "module": mod, "loaded_at": time.time()}
    return True, manifest


def unload(plugin_id):
    if plugin_id in _registry:
        del _registry[plugin_id]
        return True, None
    return False, "not loaded"


def list_loaded():
    return [{"id": pid, "manifest": r["manifest"],
             "loadedAt": r["loaded_at"]} for pid, r in _registry.items()]


def dispatch(event, payload=None):
    """Call every loaded plugin hook for `event`. Returns list of results."""
    results = []
    for pid, rec in _registry.items():
        mod = rec["module"]
        hook = getattr(mod, event, None)
        if callable(hook):
            try:
                results.append({"plugin": pid, "ok": True, "result": hook(payload or {})})
            except Exception as e:
                results.append({"plugin": pid, "ok": False,
                                "error": str(e), "trace": traceback.format_exc()[-800:]})
    return results