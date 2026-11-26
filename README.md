<div align="center">

# ⚡ ZeroScript 2.0

**A local AI developer tool for Roblox Studio — featuring a Python bridge, a full Web Dashboard, and a custom Studio IDE Plugin.**

[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey)]()
[![License](https://img.shields.io/badge/license-GPL--3.0-blue)]()
[![Python](https://img.shields.io/badge/python-3.9%2B-blue?logo=python)]()

</div>

---

## ⚠️ Why This Is on GitHub (And Not the Roblox Creator Store)

Roblox's automated moderation system **false-flags** legitimate developer tools that use:

- **`HttpService`** — needed to talk to the local Python bridge on `127.0.0.1`
- **`loadstring`** — needed to run test code inside the Studio IDE

These are **standard features of professional developer tools**, but the automated scanner treats them the same as exploits. Many developers have faced the same "Misusing Roblox Systems" removal.

**ZeroScript is 100% safe, open-source, and runs entirely on your own machine.** Nothing is sent to any external server. All communication happens on `localhost`.

GitHub distribution is the community-standard workaround for this exact moderation issue.

---

## 📦 What's In This Repository

| File | Purpose |
|------|---------|
| **`AITOOLS.rar`** | Complete ZeroScript 2.0 package (Python backend + Web Dashboard + extension) |
| **`ZeroScriptPlugin.rbxmx`** | Roblox Studio Plugin (import into Studio manually) |
| **`README.md`** | This file — full setup guide |

---

## ✨ Features

| Component | Features |
|-----------|----------|
| **Web Dashboard** | Script Editor, AI Assistant, Studio Control, Debugging, Assets, Projects, UI Builder, Script Library, Plugins, Settings |
| **Studio Plugin** | Custom IDE, Script Search, Multi-File Editor, Format Code, AI Fix, Find & Replace, Live Web Logs, Open in Studio, Run, Sync to Web, Move All to Trash |
| **Python Bridge** | WebSocket ↔ Roblox MCP bridge, auto-restart, orphan process cleanup, live activity logging |
| **AI Integration** | Works with DeepSeek, Claude, ChatGPT, Gemini, Grok, Kimi, Qwen, and 6 more providers |
| **Skill System** | 17 built-in AAA playbooks (1:1 cloning, animations, security, etc.) |

---

## 📋 Requirements

| Requirement | Version | Download |
|-------------|---------|----------|
| **Windows** | 10 or 11 | (macOS/Linux also supported) |
| **Roblox Studio** | Latest | [roblox.com/create](https://www.roblox.com/create) |
| **Microsoft Edge or Chrome** | Latest | (For the Web Dashboard) |
| **Python** | 3.9+ | [python.org/downloads](https://www.python.org/downloads/) — **⚠️ TICK "Add python.exe to PATH"** |
| **7-Zip or WinRAR** | Any | [7-zip.org](https://www.7-zip.org/) (needed to extract `AITOOLS.rar`) |

> 💡 **Pro tip:** During Python installation, the checkbox **"Add python.exe to PATH"** at the bottom of the installer is **critical**. If you miss it, `py` won't work in PowerShell.

---

## 🚀 Full Installation (Windows / PowerShell)

### **STEP 1 — Download and Extract**

1. Go to the [**Releases**](../../releases/latest) page of this repository.
2. Download **`AITOOLS.rar`** and **`ZeroScriptPlugin.rbxmx`**.
3. Right-click `AITOOLS.rar` → **Extract All...** → Choose a folder (e.g., `C:\Users\YourName\Downloads\ZeroScript-Free`).
4. Make sure the extracted folder contains `zeroscript-2.0\` with `app2.py`, `bridge.py`, `app_ui2\`, etc.

### **STEP 2 — Verify Python is Installed**

Open **PowerShell** (press `Win + X` → "Windows Terminal" or "PowerShell") and run:

```powershell
py --version
✅ Expected: Python 3.12.x (or any 3.9+ version)

❌ If you get an error: Python isn't installed or isn't in PATH. Reinstall from python.org and tick "Add python.exe to PATH".

STEP 3 — Navigate to Your Project Folder
powershell
cd C:\Users\YourName\Downloads\ZeroScript-Free
Replace YourName with your actual Windows username. Run echo $env:USERNAME if you're unsure.

STEP 4 — Install Required Python Libraries
powershell
py -m pip install --user websockets PyQt6
This installs:

websockets — for the browser ↔ bridge WebSocket connection

PyQt6 — for the system tray icon and window management

✅ Expected: A progress bar ending with Successfully installed ...

STEP 5 — Start the Application
powershell
py .\zeroscript-2.0\app2.py
✅ Expected:

A browser window opens automatically at http://127.0.0.1:17614/2

PowerShell shows the ZeroScript Bridge banner

The window stays open (this is correct — the bridge is running)

⚠️ Do NOT close the PowerShell window. Minimize it instead. Closing it kills the bridge.

STEP 6 — Install the Studio Plugin
Open Roblox Studio.

In the Explorer panel, right-click Workspace → Insert from File...

Select ZeroScriptPlugin.rbxmx (the file you downloaded in Step 1).

The script appears inside Workspace named ZeroScriptPlugin.

Right-click the ZeroScriptPlugin script → Save as Local Plugin...

A Windows save dialog opens (already pointing to the Roblox Plugins folder) → click Save.

You can now delete the ZeroScriptPlugin script from Workspace (it's saved as a plugin).

Go to the Plugins tab in Studio → click Ultimate IDE → the dark IDE panel opens on the right.

STEP 7 — Enable Studio Settings
These are required for the plugin to run code and talk to the Python backend:

In Studio: Home tab → Game Settings → Security

✅ Turn on Allow HTTP Requests

In the Explorer, click ServerScriptService

In the Properties panel, ✅ check LoadStringEnabled

STEP 8 — Test Everything
Back in the Studio plugin:

Look at the bottom-left Live Console. Wait 3–5 seconds.

It should turn green and say [Connected] Bridge is Online.

Type test code in the editor, e.g.:

lua
local part = Instance.new("Part")
part.BrickColor = BrickColor.new("Bright red")
part.Position = Vector3.new(0, 10, 0)
part.Parent = workspace
print("Hello from ZeroScript!")
Click ▶ Run → a red part appears in Workspace.

Click ☁ Sync Web → the log appears in your Web Dashboard under 🐞 Debugging → Studio Logs.

🎉 You're done!

