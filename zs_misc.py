# SPDX-License-Identifier: GPL-3.0-or-later
"""ZeroScript 2.0 - Miscellaneous systems.

  - Script Library (save reusable scripts)
  - Dependency analyzer (require graph)
  - Security analyzer (RemoteEvent / DataStore patterns)
  - Code Diff (LCS-based)
  - Version History (per-file snapshots + restore)
  - Network diagnostics (bridge + Studio status summary)
"""
import difflib
import json
import os
import re
import time

HERE = os.path.dirname(os.path.abspath(__file__))
LIB_DIR = os.path.join(HERE, "script_library")
HIST_DIR = os.path.join(HERE, "script_history")
os.makedirs(LIB_DIR, exist_ok=True)
os.makedirs(HIST_DIR, exist_ok=True)


# ---------- Script Library ----------
def library_save(title, code, tags=None):
    title = str(title or "").strip()[:120]
    if not title:
        return False, "title required"
    rec = {"title": title, "code": str(code or ""),
           "tags": [str(t)[:40] for t in (tags or [])][:20],
           "saved": time.strftime("%Y-%m-%d %H:%M:%S")}
    safe = re.sub(r"[^a-zA-Z0-9_-]+", "-", title)[:80] or "script"
    with open(os.path.join(LIB_DIR, safe + ".json"), "w", encoding="utf-8") as f:
        json.dump(rec, f, indent=2)
    return True, rec


def library_list():
    out = []
    for fn in os.listdir(LIB_DIR):
        if fn.endswith(".json"):
            try:
                with open(os.path.join(LIB_DIR, fn), "r", encoding="utf-8") as f:
                    out.append(json.load(f))
            except Exception:
                continue
    out.sort(key=lambda r: r["title"].lower())
    return out


def library_delete(title):
    safe = re.sub(r"[^a-zA-Z0-9_-]+", "-", str(title or ""))[:80]
    p = os.path.join(LIB_DIR, safe + ".json")
    if os.path.isfile(p):
        os.remove(p)
        return True
    return False


# ---------- Dependency analyzer ----------
def analyze_dependencies(files):
    """files: dict[fname] = code. Returns require graph + cycles + orphans."""
    req_re = re.compile(r'require\s*\(\s*(?:script\.Parent\.)?([A-Za-z_][\w.]*)')
    graph = {}
    for fname, code in files.items():
        deps = set()
        for m in req_re.finditer(code or ""):
            deps.add(m.group(1).split(".")[-1])
        graph[fname] = sorted(deps)
    # cycles (simple DFS)
    cycles = []
    visited, stack = set(), set()

    def dfs(node, path):
        if node in stack:
            i = path.index(node)
            cycles.append(path[i:])
            return
        if node in visited:
            return
        visited.add(node)
        stack.add(node)
        for nxt in graph.get(node, []):
            cand = next((f for f in files if f.lower().startswith(nxt.lower())), None)
            if cand:
                dfs(cand, path + [cand])
        stack.discard(node)

    for f in files:
        dfs(f, [f])
    # orphans = files nothing requires and which require nothing
    referenced = set()
    for deps in graph.values():
        referenced.update(deps)
    orphans = [f for f in files if not graph[f]
               and not any(f.lower().startswith(r.lower()) for r in referenced)]
    return {"graph": graph, "cycles": cycles, "orphans": orphans}


# ---------- Security analyzer ----------
SECURITY_PATTERNS = [
    (re.compile(r"OnServerEvent\s*:\s*Connect\s*\(\s*function\s*\(\s*player"),
     "good", "validates first arg as player"),
    (re.compile(r"FireServer\s*\("), "info", "client FireServer call - server must validate"),
    (re.compile(r"InvokeServer\s*\("), "info", "client InvokeServer call - server must validate"),
    (re.compile(r"GetAsync\s*\("), "info", "DataStore GetAsync - handle nil"),
    (re.compile(r"SetAsync\s*\("), "warn", "SetAsync can overwrite - prefer UpdateAsync for profiles"),
    (re.compile(r"HttpService\s*:\s*GetAsync|PostAsync"), "info", "external HTTP - validate response"),
    (re.compile(r"loadstring\s*\("), "error", "loadstring on user input is a remote-code risk"),
    (re.compile(r"game\.Workspace\.\w+\s*="), "warn", "direct client-side workspace mutation may not replicate"),
    (re.compile(r"while\s+true\s+do"), "warn", "infinite while loop - ensure task.wait() inside"),
]


def security_scan(code):
    findings = []
    for i, line in enumerate((code or "").splitlines(), 1):
        for pat, sev, msg in SECURITY_PATTERNS:
            if pat.search(line):
                findings.append({"line": i, "severity": sev, "message": msg,
                                 "excerpt": line.strip()[:160]})
    score = 100 - 15 * sum(1 for f in findings if f["severity"] == "error") \
                - 5 * sum(1 for f in findings if f["severity"] == "warn")
    return {"findings": findings, "score": max(0, score)}


# ---------- Code diff ----------
def diff(old, new):
    old_lines = (old or "").splitlines()
    new_lines = (new or "").splitlines()
    sm = difflib.SequenceMatcher(None, old_lines, new_lines)
    hunks = []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        hunks.append({"tag": tag, "oldStart": i1 + 1, "oldEnd": i2,
                      "newStart": j1 + 1, "newEnd": j2,
                      "oldLines": old_lines[i1:i2],
                      "newLines": new_lines[j1:j2]})
    return {"hunks": hunks,
            "added": sum(len(h["newLines"]) for h in hunks if h["tag"] == "insert"),
            "removed": sum(len(h["oldLines"]) for h in hunks if h["tag"] == "delete")}


# ---------- Version history ----------
def _hist_dir(file_id):
    safe = re.sub(r"[^a-zA-Z0-9_-]+", "-", str(file_id or "file"))[:80]
    d = os.path.join(HIST_DIR, safe)
    os.makedirs(d, exist_ok=True)
    return d


def snapshot(file_id, code, note=""):
    d = _hist_dir(file_id)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    p = os.path.join(d, stamp + ".json")
    with open(p, "w", encoding="utf-8") as f:
        json.dump({"ts": stamp, "note": str(note)[:200], "code": str(code or "")}, f)
    return True, stamp


def history_list(file_id):
    d = _hist_dir(file_id)
    out = []
    for fn in sorted(os.listdir(d), reverse=True):
        if fn.endswith(".json"):
            try:
                with open(os.path.join(d, fn), "r", encoding="utf-8") as f:
                    rec = json.load(f)
                    rec["id"] = fn[:-5]
                    rec.pop("code", None)
                    out.append(rec)
            except Exception:
                continue
    return out


def history_restore(file_id, version_id):
    d = _hist_dir(file_id)
    p = os.path.join(d, version_id + ".json")
    if not os.path.isfile(p):
        return None
    with open(p, "r", encoding="utf-8") as f:
        return json.load(f).get("code", "")


# ---------- Network diagnostics ----------
def network_diagnostics(bridge_stats, studio_status, tools_count):
    return {
        "bridge": bridge_stats,
        "studio": studio_status,
        "toolsAvailable": tools_count,
        "verdict": ("healthy" if studio_status and tools_count > 0 else
                    "degraded" if bridge_stats and bridge_stats.get("online") else
                    "offline"),
    }