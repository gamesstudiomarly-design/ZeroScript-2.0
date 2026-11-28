# SPDX-License-Identifier: GPL-3.0-or-later
"""ZeroScript 2.0 - Advanced Luau Script Editor backend.

Pure stdlib. Provides:
  - Luau tokenizer (keywords, strings, numbers, comments, operators)
  - Syntax highlighting spans (server returns token spans; UI colors them)
  - Bracket/quote matching + error detection
  - Code formatter (indent normalization, spacing)
  - Multi-tab document store (in-memory + disk persistence)
  - Autocomplete index (keywords, globals, Roblox API surface, local symbols)
  - Diagnostics (unbalanced brackets, unterminated strings, TODO markers)
"""
import json
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
DOCS_DIR = os.path.join(HERE, "editor_docs")
os.makedirs(DOCS_DIR, exist_ok=True)

LUAU_KEYWORDS = {
    "and", "break", "do", "else", "elseif", "end", "false", "for", "function",
    "if", "in", "local", "nil", "not", "or", "repeat", "return", "then", "true",
    "until", "while", "continue", "type", "export", "typeof",
}
LUAU_BUILTINS = {
    "print", "warn", "error", "assert", "pcall", "xpcall", "select", "type",
    "typeof", "tostring", "tonumber", "unpack", "rawget", "rawset", "rawequal",
    "setmetatable", "getmetatable", "pairs", "ipairs", "next", "require",
    "loadstring", "tick", "wait", "spawn", "delay", "time", "os", "math",
    "string", "table", "coroutine", "task", "debug", "utf8", "bit32", "buffer",
}
ROBLOX_GLOBALS = {
    "game", "workspace", "script", "Instance", "Enum", "CFrame", "Vector3",
    "Vector2", "Color3", "UDim", "UDim2", "BrickColor", "Ray", "Region3",
    "Random", "TweenInfo", "NumberRange", "NumberSequence", "ColorSequence",
    "Rect", "Font", "TextLabel", "TextButton", "Frame", "ScrollingFrame",
    "UIListLayout", "UIGridLayout", "UIPadding", "UICorner", "UIStroke",
    "UIStroke", "ImageLabel", "ImageButton", "TextBox", "ScreenGui", "BillboardGui",
    "SurfaceGui", "RemoteEvent", "RemoteFunction", "BindableEvent", "BindableFunction",
    "ModuleScript", "Script", "LocalScript", "Folder", "Model", "Part", "MeshPart",
    "Humanoid", "HumanoidRootPart", "Animator", "Animation", "Motor6D", "Weld",
    "Attachment", "ParticleEmitter", "Sound", "SoundService", "Lighting",
    "ReplicatedStorage", "ServerScriptService", "ServerStorage", "StarterGui",
    "StarterPack", "StarterPlayer", "Players", "TweenService", "RunService",
    "UserInputService", "ContextActionService", "MarketplaceService", "DataStoreService",
    "HttpService", "TeleportService", "PathfindingService", "PhysicsService",
    "CollectionService", "ProximityPromptService", "TextService", "GuiService",
    "VirtualUser", "Debris", "ContentProvider", "InsertService", "MessagingService",
    "MemoryStoreService", "PolicyService", "GroupService", "BadgeService",
    "AssetService", "SocialService", "LocalizationService", "Chat", "Teams",
    "Terrain", "Camera", "FOV", "LoadCharacter", "GetChildren", "FindFirstChild",
    "WaitForChild", "GetService", "GetDescendants", "Destroy", "Clone", "IsA",
    "SetAttribute", "GetAttribute", "GetAttributes", "Changed", "Connect",
    "Disconnect", "Fire", "FireServer", "InvokeServer", "OnServerEvent",
    "OnServerInvoke", "OnClientEvent", "Heartbeat", "Stepped", "RenderStepped",
    "PreSimulation", "PostSimulation", "PreRender", "BindToRenderStep",
    "HttpService", "JSONEncode", "JSONDecode", "GenerateGUID",
}

_TOKEN_RE = re.compile(
    r"""
    (?P<comment>--\[(=*)\[.*?\]\2\]|--[^\n]*)
  | (?P<string>\[(=*)\[.*?\]\2\]|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')
  | (?P<number>0[xX][0-9a-fA-F]+|\d+\.?\d*(?:[eE][+-]?\d+)?|\.\d+)
  | (?P<name>[A-Za-z_][A-Za-z0-9_]*)
  | (?P<op>==|~=|<=|>=|\.\.|::|->|[-+*/%^#=<>~&|.,:;()\[\]{}])
  | (?P<ws>\s+)
  | (?P<other>.)
    """,
    re.VERBOSE | re.DOTALL,
)


def tokenize(code):
    """Return list of {type, text, start, end, line, col} tokens."""
    tokens = []
    line = 1
    col = 0
    for m in _TOKEN_RE.finditer(code or ""):
        kind = m.lastgroup
        text = m.group(0)
        if kind == "comment":
            t = "comment"
        elif kind == "string":
            t = "string"
        elif kind == "number":
            t = "number"
        elif kind == "name":
            if text in LUAU_KEYWORDS:
                t = "keyword"
            elif text in ROBLOX_GLOBALS:
                t = "global"
            elif text in LUAU_BUILTINS:
                t = "builtin"
            else:
                t = "name"
        elif kind == "op":
            t = "op"
        elif kind == "ws":
            t = "ws"
        else:
            t = "other"
        tokens.append({
            "type": t, "text": text,
            "start": m.start(), "end": m.end(),
            "line": line, "col": col,
        })
        # advance line/col
        nl = text.count("\n")
        if nl:
            line += nl
            col = len(text) - text.rfind("\n") - 1
        else:
            col += len(text)
    return tokens


def highlight(code):
    """Return spans for the UI highlighter (only non-ws tokens)."""
    return [t for t in tokenize(code) if t["type"] != "ws"]


def diagnostics(code):
    """Return list of diagnostic dicts: {severity, line, col, message}."""
    out = []
    stack = []
    pairs = {"(": ")", "[": "]", "{": "}"}
    opens = set(pairs)
    closes = set(pairs.values())
    # bracket matching
    for t in tokenize(code):
        if t["type"] == "string" or t["type"] == "comment":
            continue
        if t["type"] == "op":
            ch = t["text"]
            if ch in opens:
                stack.append((ch, t["line"], t["col"]))
            elif ch in closes:
                if not stack:
                    out.append({"severity": "error", "line": t["line"], "col": t["col"],
                                "message": f"Unmatched closing '{ch}'"})
                else:
                    op, ol, oc = stack.pop()
                    if pairs[op] != ch:
                        out.append({"severity": "error", "line": t["line"], "col": t["col"],
                                    "message": f"Mismatched '{ch}' (expected '{pairs[op]}' from line {ol})"})
    for op, ol, oc in stack:
        out.append({"severity": "error", "line": ol, "col": oc,
                    "message": f"Unclosed '{op}'"})
    # unterminated strings (single/double quote only)
    for i, line_text in enumerate((code or "").splitlines(), 1):
        stripped = re.sub(r'--.*$', '', line_text)
        for q in ('"', "'"):
            if stripped.count(q) % 2 == 1:
                out.append({"severity": "warning", "line": i, "col": 0,
                            "message": f"Possible unterminated {q} string"})
    # TODO/FIXME markers
    for i, line_text in enumerate((code or "").splitlines(), 1):
        for mark in ("TODO", "FIXME", "HACK", "XXX"):
            if mark in line_text:
                out.append({"severity": "info", "line": i, "col": line_text.find(mark),
                            "message": f"{mark} marker"})
    return out


def format_code(code, indent_str="\t"):
    """Lightweight Luau formatter: normalize indentation by block depth,
    trim trailing whitespace, collapse >2 blank lines, single-space operators."""
    lines = (code or "").replace("\r\n", "\n").split("\n")
    out = []
    depth = 0
    block_open = re.compile(r"\b(function|if|for|while|do|repeat)\b")
    block_close = re.compile(r"^\s*(end|until|else|elseif)\b")
    for raw in lines:
        line = raw.rstrip()
        if not line.strip():
            out.append("")
            continue
        stripped = line.lstrip()
        # dedent before closing keywords
        if block_close.match(stripped):
            depth = max(0, depth - 1)
        # one-liner "if x then return end" stays inline
        opens = len(re.findall(r"\b(function|if|for|while|do|repeat)\b", stripped))
        closes = len(re.findall(r"\b(end|until)\b", stripped))
        out.append(indent_str * depth + stripped)
        depth = max(0, depth + opens - closes)
        if re.match(r"^\s*(else|elseif)\b", stripped):
            depth += 1
    # collapse 3+ blank lines to 1
    cleaned = []
    blank = 0
    for ln in out:
        if ln == "":
            blank += 1
            if blank <= 1:
                cleaned.append(ln)
        else:
            blank = 0
            cleaned.append(ln)
    return "\n".join(cleaned).strip() + "\n"


def autocomplete(prefix, code=""):
    """Return suggestions matching prefix from keywords, builtins, globals,
    and local symbols found in code."""
    q = (prefix or "").strip()
    pool = set(LUAU_KEYWORDS) | set(LUAU_BUILTINS) | set(ROBLOX_GLOBALS)
    # local symbols
    for m in re.finditer(r"\blocal\s+([A-Za-z_][A-Za-z0-9_]*)", code or ""):
        pool.add(m.group(1))
    for m in re.finditer(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)", code or ""):
        pool.add(m.group(1))
    items = sorted(pool)
    if not q:
        return items[:200]
    return [x for x in items if x.lower().startswith(q.lower())][:200]


# ---------------- document store ----------------
def _doc_path(doc_id):
    safe = re.sub(r"[^a-zA-Z0-9_-]+", "-", str(doc_id or ""))[:80] or "untitled"
    return os.path.join(DOCS_DIR, safe + ".json")


def save_doc(doc):
    if not isinstance(doc, dict):
        return False, "invalid doc"
    did = doc.get("id") or doc.get("name") or "untitled"
    rec = {
        "id": did,
        "name": str(doc.get("name") or did)[:120],
        "code": str(doc.get("code") or ""),
        "updated": doc.get("updated") or "",
    }
    try:
        with open(_doc_path(did), "w", encoding="utf-8") as f:
            json.dump(rec, f, indent=2)
        return True, rec
    except Exception as e:
        return False, str(e)


def list_docs():
    out = []
    for fn in os.listdir(DOCS_DIR):
        if fn.endswith(".json"):
            try:
                with open(os.path.join(DOCS_DIR, fn), "r", encoding="utf-8") as f:
                    out.append(json.load(f))
            except Exception:
                continue
    out.sort(key=lambda d: d.get("name", ""))
    return out


def get_doc(doc_id):
    p = _doc_path(doc_id)
    if os.path.isfile(p):
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    return None


def delete_doc(doc_id):
    p = _doc_path(doc_id)
    if os.path.isfile(p):
        os.remove(p)
        return True
    return False