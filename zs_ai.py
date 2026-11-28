# SPDX-License-Identifier: GPL-3.0-or-later
"""ZeroScript 2.0 - AI Coding Assistant backend.

Builds structured prompts for the connected AI and provides deterministic
local fallbacks so the assistant always returns something useful even with
no AI tab attached.
"""
import re

PROMPTS = {
    "generate": (
        "You are a Luau expert for Roblox Studio. Write a complete, idiomatic "
        "Luau script for the following request. Use --!strict, task.wait, "
        "task.spawn (never deprecated wait/spawn), guard all RemoteEvents "
        "server-side, and return ONLY the code in a ```lua fenced block.\n\n"
        "Request: {input}\n"
    ),
    "explain": (
        "Explain this Luau script line-by-line in plain language, then list any "
        "bugs, then suggest one improvement. Be concise.\n\n```lua\n{input}\n```"
    ),
    "fix": (
        "Find and fix the bugs in this Luau script. Return the corrected full "
        "script in a ```lua fenced block, then a short bullet list of what you "
        "changed and why.\n\n```lua\n{input}\n```"
    ),
    "optimize": (
        "Optimize this Luau script for performance and readability without "
        "changing behaviour. Return the optimized full script in a ```lua "
        "fenced block plus a 3-bullet summary of the optimizations.\n\n"
        "```lua\n{input}\n```"
    ),
    "module": (
        "Convert this Luau script into a proper ModuleScript that returns a "
        "table of functions. Include a header comment and a .new() constructor "
        "if the code creates instances. Return only the ModuleScript code in a "
        "```lua fenced block.\n\n```lua\n{input}\n```"
    ),
}


def build_prompt(action, code_or_input):
    tpl = PROMPTS.get(action)
    if not tpl:
        return None
    return tpl.replace("{input}", str(code_or_input or ""))


def local_generate(request):
    """Deterministic template generator used when no AI is connected."""
    r = (request or "").lower()
    if "leaderboard" in r or "leaderstat" in r:
        return (
            '--!strict\n'
            '-- Leaderstats starter (ServerScriptService)\n'
            'local Players = game:GetService("Players")\n'
            'Players.PlayerAdded:Connect(function(player)\n'
            '\tlocal stats = Instance.new("Folder")\n'
            '\tstats.Name = "leaderstats"\n'
            '\tlocal coins = Instance.new("IntValue")\n'
            '\tcoins.Name = "Coins"\n'
            '\tcoins.Value = 0\n'
            '\tcoins.Parent = stats\n'
            '\tstats.Parent = player\n'
            'end)\n'
        )
    if "remote" in r or "client" in r or "server" in r:
        return (
            '--!strict\n'
            '-- RemoteEvent pattern (ReplicatedStorage + server handler)\n'
            'local ReplicatedStorage = game:GetService("ReplicatedStorage")\n'
            'local remote = Instance.new("RemoteEvent")\n'
            'remote.Name = "MyRemote"\n'
            'remote.Parent = ReplicatedStorage\n'
            '-- Server:\n'
            '-- remote.OnServerEvent:Connect(function(player, ...)\n'
            '-- \t-- validate player input here\n'
            '-- end)\n'
        )
    return (
        '--!strict\n'
        '-- Generated starter for: ' + (request or "request") + '\n'
        'local RunService = game:GetService("RunService")\n'
        'local function main()\n'
        '\tprint("Hello from ZeroScript")\n'
        'end\n'
        'main()\n'
    )


def local_explain(code):
    lines = (code or "").splitlines()
    notes = []
    for i, ln in enumerate(lines, 1):
        s = ln.strip()
        if not s or s.startswith("--"):
            continue
        if s.startswith("local "):
            notes.append(f"L{i}: declares a local variable.")
        elif re.match(r"function\b", s):
            notes.append(f"L{i}: defines a function.")
        elif ".Connect(" in s:
            notes.append(f"L{i}: connects an event handler.")
        elif "Instance.new" in s:
            notes.append(f"L{i}: creates a new Instance.")
        elif "RemoteEvent" in s:
            notes.append(f"L{i}: references a RemoteEvent (validate server-side!).")
    if not notes:
        notes.append("No notable constructs detected.")
    return "Local explanation:\n- " + "\n- ".join(notes)


def local_fix(code):
    """Upgrade the deprecated task calls in a Luau snippet.

    The replacements must not fire on an ALREADY correct call.  The old
    pattern was ``\\bwait\\(``, and the dot in ``task.wait(`` is a word
    boundary - so every call turned good code into ``task.task.wait(``,
    ``task.task.spawn(`` and ``task.task.delay(``, which is not valid Luau.
    The callers (the AI panel, the Studio panel and the 4.0 auto-fix route)
    all run this over the same snippet more than once, so the damage grew
    with every pass.

    ``(?<![\\w.])`` refuses a match that is preceded by a word character or
    a dot: ``task.wait(`` and ``mywait(`` are left alone, a bare ``wait(``
    is still upgraded.  The fixer is therefore idempotent.
    """
    fixed = code or ""
    # common fixes
    for old, new in (("wait", "task.wait"), ("spawn", "task.spawn"), ("delay", "task.delay")):
        fixed = re.sub(rf"(?<![\w.]){old}\(", f"{new}(", fixed)
    return fixed