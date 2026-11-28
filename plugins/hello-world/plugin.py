def on_load(payload):
    print("[hello-world] loaded")
    return {"ok": True}

def on_tool_call(payload):
    print(f"[hello-world] tool call: {payload.get('tool')}")
    return {"ok": True}

def on_tool_result(payload):
    print(f"[hello-world] result: {payload.get('tool')} -> ok={payload.get('ok')}")
    return {"ok": True}