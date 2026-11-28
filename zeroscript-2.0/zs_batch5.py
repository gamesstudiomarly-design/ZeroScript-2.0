# SPDX-License-Identifier: GPL-3.0-or-later
"""ZeroScript 2.0 Batch 5 - Live AI Bridge, Undo, Error Fix, Replay.

Live AI works in two modes:
  - "ws"         -> broadcast the prompt to the extension (best)
  - "clipboard"  -> copy prompt to clipboard, user pastes in AI tab
                    (always works, no extension changes required)
"""
import json
import os
import threading
import time
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))

# ---------------- Live AI sessions ----------------
_LIVE_LOCK = threading.Lock()
_LIVE_SESSIONS = {}
_LIVE_MAX = 50


def _extension_connected():
    try:
        import bridge
        return len(bridge.clients) > 0
    except Exception:
        return False


def _try_broadcast(payload):
    try:
        import app, bridge
        if not app._bridge_loop:
            return 0
        async def _do():
            sent = 0
            for ws in list(bridge.clients):
                try:
                    await ws.send(json.dumps(payload))
                    sent += 1
                except Exception:
                    pass
            return sent
        result = app._run_on_bridge_loop(_do(), timeout=3)
        return result or 0
    except Exception:
        return 0


def ai_live_start(action, input_text):
    if not (input_text or "").strip():
        return False, "input required"
    import zs_ai
    prompt = zs_ai.build_prompt(action, input_text)
    if not prompt:
        return False, f"unknown action '{action}'"
    sid = uuid.uuid4().hex[:12]
    mode = "ws" if _extension_connected() else "clipboard"
    if mode == "ws":
        if _try_broadcast({"type": "zs_ai_prompt", "session_id": sid,
                           "action": action, "prompt": prompt}) == 0:
            mode = "clipboard"
    with _LIVE_LOCK:
        _LIVE_SESSIONS[sid] = {
            "session_id": sid, "action": action, "prompt": prompt,
            "mode": mode, "created": time.time(),
            "response": "", "status": "awaiting",
        }
        if len(_LIVE_SESSIONS) > _LIVE_MAX:
            oldest = min(_LIVE_SESSIONS.values(), key=lambda s: s["created"])
            _LIVE_SESSIONS.pop(oldest["session_id"], None)
    return True, {"session_id": sid, "mode": mode, "prompt": prompt}


def ai_live_response(sid, response):
    with _LIVE_LOCK:
        sess = _LIVE_SESSIONS.get(sid)
        if not sess:
            return False, "session not found"
        sess["response"] = str(response or "")
        sess["status"] = "responded"
        sess["responded_at"] = time.time()
    return True, sess


def ai_live_get(sid):
    with _LIVE_LOCK:
        return _LIVE_SESSIONS.get(sid)


# ---------------- Undo ----------------
_UNDO_LOCK = threading.Lock()
_UNDO_STACK = []
_UNDO_MAX = 30


def undo_install(manager):
    """Monkey-patch manager.call_tool (or invoke/execute) to snapshot before
    destructive operations. Returns the method name that was hooked, or None."""
    for name in ("call_tool", "invoke_tool", "execute_tool"):
        if hasattr(manager, name) and callable(getattr(manager, name)):
            original = getattr(manager, name)

            def wrapped(*args, **kwargs):
                tool_name = str(args[0] if args else kwargs.get("name", ""))
                tool_args = (args[1] if len(args) > 1 else kwargs.get("args", {})) or {}
                snap = None
                try:
                    if "set_property" in tool_name:
                        inst = tool_args.get("instance") or tool_args.get("path") or tool_args.get("target")
                        prop = tool_args.get("property") or tool_args.get("prop") or tool_args.get("name")
                        if inst and prop:
                            try:
                                old = original("get_property",
                                               {"instance": inst, "property": prop})
                                snap = {"type": "set_property", "instance": inst,
                                        "property": prop, "old": old, "ts": time.time()}
                            except Exception:
                                pass
                    elif "destroy" in tool_name or "delete" in tool_name:
                        inst = tool_args.get("instance") or tool_args.get("path")
                        snap = {"type": "destroy", "instance": inst, "ts": time.time()}
                except Exception:
                    pass
                result = original(*args, **kwargs)
                if snap:
                    with _UNDO_LOCK:
                        _UNDO_STACK.append(snap)
                        if len(_UNDO_STACK) > _UNDO_MAX:
                            _UNDO_STACK.pop(0)
                return result
            setattr(manager, name, wrapped)
            return name
    return None


def undo_last(manager):
    with _UNDO_LOCK:
        if not _UNDO_STACK:
            return False, "Nothing to undo."
        snap = _UNDO_STACK.pop()
    if snap["type"] == "set_property":
        try:
            for name in ("call_tool", "invoke_tool", "execute_tool"):
                if hasattr(manager, name):
                    getattr(manager, name)("set_property", {
                        "instance": snap["instance"],
                        "property": snap["property"],
                        "value": snap["old"],
                    })
                    return True, {"undone": {k: v for k, v in snap.items() if k != "old"}}
            return False, "manager has no call method"
        except Exception as e:
            return False, str(e)
    if snap["type"] == "destroy":
        return False, f"Can't recreate destroyed '{snap['instance']}' automatically. Use version history."
    return False, "Unsupported"


def undo_stack():
    with _UNDO_LOCK:
        return [{"type": s["type"], "instance": s.get("instance"),
                 "property": s.get("property"),
                 "age": int(time.time() - s["ts"])}
                for s in reversed(_UNDO_STACK)]


# ---------------- Error fix ----------------
def error_fix(error_msg):
    if not (error_msg or "").strip():
        return False, "error message required"
    prompt = (
        "Fix this Roblox Studio error. Return ONLY the corrected script "
        "(or minimal change) in a ```lua fenced block, then a one-line "
        f"explanation.\n\nError:\n{error_msg.strip()}"
    )
    return True, prompt


# ---------------- Replay ----------------
def replay(limit=10):
    try:
        import bridge
    except Exception:
        return False, "bridge not available"
    with bridge.ACTIVITY_LOCK:
        items = list(bridge.ACTIVITY_BUFFER)[:int(limit)]
    items.reverse()
    manager = bridge.mgr
    ok_count = fail_count = 0
    results = []
    for it in items:
        tool = it.get("tool")
        try:
            args = json.loads(it.get("args") or "{}")
        except Exception:
            args = {}
        try:
            called = False
            for name in ("call_tool", "invoke_tool", "execute_tool"):
                if hasattr(manager, name):
                    getattr(manager, name)(tool, args)
                    called = True
                    break
            if called:
                ok_count += 1
                results.append({"tool": tool, "ok": True})
            else:
                fail_count += 1
                results.append({"tool": tool, "ok": False, "error": "no call method"})
        except Exception as e:
            fail_count += 1
            results.append({"tool": tool, "ok": False, "error": str(e)})
    return True, {"count": len(items), "ok_count": ok_count,
                  "fail_count": fail_count, "results": results}


# ---------------- Route handler ----------------
def handle_get(handler, path):
    if path == "/api2/undo/stack":
        return handler._send_json(200, {"ok": True, "stack": undo_stack()}), True
    if path == "/api2/ai/live/session":
        qs = handler.path.split("?", 1)[-1]
        params = dict(p.split("=", 1) for p in qs.split("&") if "=" in p)
        sid = params.get("id", "")
        sess = ai_live_get(sid)
        return handler._send_json(200 if sess else 404,
                                  {"ok": bool(sess), "session": sess,
                                   "error": None if sess else "not found"}), True
    return None, False


def handle_post(handler, path, body):
    if path == "/api2/ai/live/start":
        ok, res = ai_live_start(body.get("action", "generate"), body.get("input", ""))
        return handler._send_json(200 if ok else 400,
                                  {"ok": ok, **(res if ok else {"error": res})}), True
    if path == "/api2/ai/live/response":
        ok, res = ai_live_response(body.get("session_id", ""), body.get("response", ""))
        return handler._send_json(200 if ok else 404,
                                  {"ok": ok, **(res if ok else {"error": res})}), True
    if path == "/api2/undo":
        try:
            import bridge
            ok, res = undo_last(bridge.mgr)
        except Exception as e:
            ok, res = False, str(e)
        return handler._send_json(200 if ok else 400,
                                  {"ok": ok, **(res if ok else {"error": res})}), True
    if path == "/api2/debug/fix":
        ok, res = error_fix(body.get("error", ""))
        return handler._send_json(200 if ok else 400,
                                  {"ok": ok, "prompt": res if ok else None,
                                   "error": None if ok else res}), True
    if path == "/api2/replay":
        ok, res = replay(body.get("limit", 10))
        return handler._send_json(200 if ok else 400,
                                  {"ok": ok, **(res if ok else {"error": res})}), True
    return None, False