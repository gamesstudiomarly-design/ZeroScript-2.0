# SPDX-License-Identifier: GPL-3.0-or-later
"""ZeroScript 2.0 - Project Manager backend.

Multi-project registry with templates, automatic backups (JSON snapshots),
import/export, recent projects, and a project health checker.
"""
import json
import os
import shutil
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECTS_DIR = os.path.join(HERE, "projects")
BACKUPS_DIR = os.path.join(HERE, "projects_backups")
os.makedirs(PROJECTS_DIR, exist_ok=True)
os.makedirs(BACKUPS_DIR, exist_ok=True)
INDEX_PATH = os.path.join(PROJECTS_DIR, "index.json")

TEMPLATES = {
    "blank": {"name": "Blank Project", "files": {"Main.luau": "--!strict\nprint('hello')\n"}},
    "obby": {"name": "Obby", "files": {"Main.luau": "--!strict\n-- obby checkpoint logic\n",
                                       "Checkpoint.luau": "return function(player) end\n"}},
    "simulator": {"name": "Simulator", "files": {"Economy.luau": "return {}\n",
                                                 "Rebirth.luau": "return {}\n"}},
    "rpg": {"name": "RPG", "files": {"Combat.luau": "return {}\n", "Inventory.luau": "return {}\n"}},
    "tycoon": {"name": "Tycoon", "files": {"Dropper.luau": "return {}\n",
                                            "Upgrades.luau": "return {}\n"}},
    "ui-kit": {"name": "UI Kit", "files": {"HUD.luau": "return {}\n", "Theme.luau": "return {}\n"}},
}


def _load_index():
    if os.path.isfile(INDEX_PATH):
        try:
            with open(INDEX_PATH, "r", encoding="utf-8") as f:
                d = json.load(f)
                if isinstance(d, dict) and isinstance(d.get("projects"), list):
                    return d
        except Exception:
            pass
    return {"projects": [], "recent": []}


def _save_index(data):
    tmp = INDEX_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, INDEX_PATH)


def _proj_dir(pid):
    safe = "".join(c for c in str(pid) if c.isalnum() or c in "-_")[:80] or "project"
    return os.path.join(PROJECTS_DIR, safe)


def create_project(name, template="blank"):
    name = str(name or "").strip()[:120]
    if not name:
        return False, "name required"
    pid = "".join(c for c in name.lower().replace(" ", "-") if c.isalnum() or c in "-_")[:60]
    d = _proj_dir(pid)
    if os.path.isdir(d):
        return False, f"project '{pid}' already exists"
    os.makedirs(d, exist_ok=True)
    tpl = TEMPLATES.get(template) or TEMPLATES["blank"]
    for fname, code in tpl["files"].items():
        with open(os.path.join(d, fname), "w", encoding="utf-8") as f:
            f.write(code)
    with open(os.path.join(d, "project.json"), "w", encoding="utf-8") as f:
        json.dump({"id": pid, "name": name, "template": template,
                   "created": time.strftime("%Y-%m-%d %H:%M:%S")}, f, indent=2)
    idx = _load_index()
    idx["projects"].append({"id": pid, "name": name, "template": template,
                            "created": time.strftime("%Y-%m-%d %H:%M:%S")})
    idx["recent"] = ([pid] + [r for r in idx["recent"] if r != pid])[:10]
    _save_index(idx)
    backup(pid)
    return True, {"id": pid, "name": name, "template": template}


def list_projects():
    idx = _load_index()
    return idx["projects"]


def get_recent():
    idx = _load_index()
    by_id = {p["id"]: p for p in idx["projects"]}
    return [by_id[r] for r in idx["recent"] if r in by_id]


def delete_project(pid):
    d = _proj_dir(pid)
    if not os.path.isdir(d):
        return False, "project not found"
    shutil.rmtree(d, ignore_errors=True)
    idx = _load_index()
    idx["projects"] = [p for p in idx["projects"] if p["id"] != pid]
    idx["recent"] = [r for r in idx["recent"] if r != pid]
    _save_index(idx)
    return True, None


def list_files(pid):
    d = _proj_dir(pid)
    if not os.path.isdir(d):
        return []
    return sorted(f for f in os.listdir(d) if os.path.isfile(os.path.join(d, f)))


def read_file(pid, fname):
    d = _proj_dir(pid)
    p = os.path.join(d, os.path.basename(fname))
    if not os.path.isfile(p):
        return None
    with open(p, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def write_file(pid, fname, content):
    d = _proj_dir(pid)
    if not os.path.isdir(d):
        return False, "project not found"
    p = os.path.join(d, os.path.basename(fname))
    with open(p, "w", encoding="utf-8") as f:
        f.write(str(content or ""))
    return True, None


def backup(pid):
    d = _proj_dir(pid)
    if not os.path.isdir(d):
        return False, "project not found"
    stamp = time.strftime("%Y%m%d-%H%M%S")
    dst = os.path.join(BACKUPS_DIR, f"{os.path.basename(d)}-{stamp}")
    try:
        shutil.copytree(d, dst)
        return True, dst
    except Exception as e:
        return False, str(e)


def list_backups(pid):
    base = os.path.basename(_proj_dir(pid))
    out = []
    for entry in os.listdir(BACKUPS_DIR):
        if entry.startswith(base + "-"):
            out.append(entry)
    return sorted(out, reverse=True)


def export_project(pid):
    d = _proj_dir(pid)
    if not os.path.isdir(d):
        return False, "project not found"
    files = {}
    for f in list_files(pid):
        files[f] = read_file(pid, f)
    return True, {"id": pid, "files": files, "exported": time.strftime("%Y-%m-%d %H:%M:%S")}


def import_project(payload):
    if not isinstance(payload, dict) or not isinstance(payload.get("files"), dict):
        return False, "invalid import payload"
    name = str(payload.get("name") or payload.get("id") or "imported")[:120]
    ok, res = create_project(name, "blank")
    if not ok:
        return False, res
    pid = res["id"]
    for fname, code in payload["files"].items():
        write_file(pid, fname, code)
    return True, {"id": pid, "name": name}


def health_check(pid):
    """Return a list of health findings for the project."""
    d = _proj_dir(pid)
    if not os.path.isdir(d):
        return {"ok": False, "error": "project not found"}
    findings = []
    for f in list_files(pid):
        if not f.endswith(".luau"):
            continue
        code = read_file(pid, f) or ""
        if "--!strict" not in code:
            findings.append({"severity": "warn", "file": f,
                             "message": "missing --!strict directive"})
        if "wait(" in code and "task.wait(" not in code:
            findings.append({"severity": "warn", "file": f,
                             "message": "uses deprecated wait()"})
        if "RemoteEvent" in code and "OnServerEvent" not in code and "FireServer" in code:
            findings.append({"severity": "error", "file": f,
                             "message": "client FireServer with no server handler in file"})
        if len(code) > 20000:
            findings.append({"severity": "info", "file": f,
                             "message": f"large file ({len(code)} chars) - consider splitting"})
    return {"ok": True, "findings": findings,
            "score": max(0, 100 - 10 * sum(1 for x in findings if x["severity"] == "error")
                         - 5 * sum(1 for x in findings if x["severity"] == "warn"))}