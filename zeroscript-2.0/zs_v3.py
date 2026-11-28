# SPDX-License-Identifier: GPL-3.0-or-later
"""ZeroScript 3.0 - God Mode Backend (Chat, Snapshots, Voice)"""
import os
import time
import json

HERE = os.path.dirname(os.path.abspath(__file__))
import zs_paths  # noqa: E402 - shared install folders
SNAP_DIR = zs_paths.install_dir("snapshots")
os.makedirs(SNAP_DIR, exist_ok=True)

def take_snapshot(filename, code):
    """Saves a backup of a script before AI modifies it."""
    safe_name = "".join(c for c in filename if c.isalnum() or c in "-_")
    stamp = time.strftime("%Y%m%d-%H%M%S")
    path = os.path.join(SNAP_DIR, f"{safe_name}_{stamp}.luau")
    with open(path, "w", encoding="utf-8") as f:
        f.write(code)
    return True, stamp

def list_snapshots():
    snaps = []
    for f in os.listdir(SNAP_DIR):
        if f.endswith(".luau"):
            snaps.append({"file": f, "time": f.split("_")[-1].replace(".luau", "")})
    return sorted(snaps, key=lambda x: x["time"], reverse=True)[:20]

def chat_with_ai(prompt):
    """Routes the chat prompt to the connected AI, or falls back to local."""
    try:
        import bridge
        import app
        if app._bridge_loop:
            async def _do():
                sent = 0
                for ws in list(bridge.clients):
                    try:
                        await ws.send(json.dumps({"type": "zs_ai_prompt", "prompt": prompt}))
                        sent += 1
                    except: pass
                return sent
            if app._run_on_bridge_loop(_do(), timeout=3) > 0:
                return True, "🚀 Prompt sent to AI tab! Check your browser."
    except Exception:
        pass
    
    # Local fallback if no AI tab is connected
    prompt_lower = prompt.lower()
    if "part" in prompt_lower:
        return True, "```lua\nlocal p = Instance.new('Part')\np.Parent = workspace\nprint('Created Part!')\n```\n*(Local Fallback)*"
    return True, "I am running in local mode. Connect the browser extension to use full AI.\n\nYou said: " + prompt

def handle_post(handler, path, body):
    if path == "/api2/v3/snapshot":
        ok, res = take_snapshot(body.get("name", "unknown"), body.get("code", ""))
        return handler._send_json(200, {"ok": ok, "stamp": res}), True
        
    if path == "/api2/v3/chat":
        ok, res = chat_with_ai(body.get("prompt", ""))
        return handler._send_json(200, {"ok": ok, "reply": res}), True

    return None, False

def handle_get(handler, path):
    if path == "/api2/v3/snapshots":
        return handler._send_json(200, {"ok": True, "snapshots": list_snapshots()}), True
    return None, False