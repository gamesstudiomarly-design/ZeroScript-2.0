_count = 0

def on_tool_result(payload):
    global _count
    _count += 1
    if _count % 10 == 0:
        try:
            import zs_projects
            for p in zs_projects.list_projects():
                zs_projects.backup(p["id"])
            return {"ok": True, "backed_up_at_call": _count}
        except Exception as e:
            return {"ok": False, "error": str(e)}
    return {"ok": True}