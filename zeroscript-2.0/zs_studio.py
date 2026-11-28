# SPDX-License-Identifier: GPL-3.0-or-later
"""ZeroScript 2.0 - Direct Studio Control."""
import os
import time
import zs_projects
import zs_editor
import zs_ai

# Memory for Studio Logs
STUDIO_LOGS = []
MAX_LOGS = 200

def add_studio_log(msg):
    STUDIO_LOGS.append({
        "time": time.strftime("%H:%M:%S"),
        "msg": str(msg)[:500]
    })
    if len(STUDIO_LOGS) > MAX_LOGS:
        STUDIO_LOGS.pop(0)

def _get_bridge():
    try:
        import bridge
        return bridge
    except ImportError:
        return None

def run_luau(code):
    if not code or not str(code).strip():
        return False, "Code is empty"
    bridge = _get_bridge()
    if not bridge:
        return False, "Bridge module not found."
    methods = ["run_luau", "execute_script", "execute_luau", "run_script", "call_tool"]
    errors = []
    for m in methods:
        try:
            if hasattr(bridge.mgr, m):
                res = getattr(bridge.mgr, m)("execute_luau" if m == "call_tool" else m, {"code": str(code)})
                return True, {"output": str(res)[:2000], "method": m}
        except Exception as e:
            errors.append(f"{m}: {e}")
    return False, f"Failed to run Luau. Tried {len(methods)} methods. Errors: {'; '.join(errors)}"

def push_project_to_studio(pid):
    bridge = _get_bridge()
    if not bridge:
        return False, "Bridge module not found."
    files = zs_projects.list_files(pid)
    if not files:
        return False, f"Project '{pid}' is empty."
    success_count = 0
    errors = []
    for fname in files:
        if not fname.endswith(".luau"):
            continue
        code = zs_projects.read_file(pid, fname)
        if code is None:
            continue
        luau_wrapper = f'''
local script = Instance.new("Script")
script.Name = "{fname.replace('.luau', '')}"
script.Source = [==[
{code}
]==]
script.Parent = game.ServerScriptService
print("[ZeroScript] Injected script: {fname}")
'''
        ok, err = run_luau(luau_wrapper)
        if ok:
            success_count += 1
        else:
            errors.append(f"{fname}: {err}")
    if success_count == 0:
        return False, f"Failed to inject any scripts. {errors}"
    return True, {"injected": success_count, "errors": errors}

def format_luau(code):
    try:
        formatted = zs_editor.format_code(code)
        return True, {"code": formatted}
    except Exception as e:
        return False, str(e)

def ai_fix_luau(code):
    try:
        fixed = zs_ai.local_fix(code)
        return True, {"code": fixed, "note": "Locally fixed deprecated syntax."}
    except Exception as e:
        return False, str(e)

def handle_get(handler, path):
    if path == "/api2/studio/logs":
        return handler._send_json(200, {"ok": True, "logs": STUDIO_LOGS}), True
    return None, False

def handle_post(handler, path, body):
    if path == "/api2/studio/log":
        add_studio_log(body.get("message", ""))
        return handler._send_json(200, {"ok": True}), True
        
    if path == "/api2/studio/run":
        add_studio_log("Plugin requested: Run Code")
        ok, res = run_luau(body.get("code", ""))
        return handler._send_json(200 if ok else 400, {"ok": ok, "result": res if ok else None, "error": None if ok else res}), True
        
    if path == "/api2/studio/push_project":
        ok, res = push_project_to_studio(body.get("id"))
        return handler._send_json(200 if ok else 400, {"ok": ok, "result": res if ok else None, "error": None if ok else res}), True

    if path == "/api2/studio/format":
        ok, res = format_luau(body.get("code", ""))
        return handler._send_json(200 if ok else 400, {"ok": ok, "result": res if ok else None, "error": None if ok else res}), True

    if path == "/api2/studio/ai_fix":
        ok, res = ai_fix_luau(body.get("code", ""))
        return handler._send_json(200 if ok else 400, {"ok": ok, "result": res if ok else None, "error": None if ok else res}), True
        
    return None, False