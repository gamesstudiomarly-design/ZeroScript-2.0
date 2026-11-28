# SPDX-License-Identifier: GPL-3.0-or-later
"""ZeroScript 2.0 - install folder resolution.

The 2.0 workspace has its own folder, but it is part of one ZeroScript
install: the skills library, the plugin SDK folders, the projects, the script
library and the MCP server configuration are the same files the rest of
ZeroScript uses.  Sharing them keeps a single source of truth and means the
workspace starts with the skills and projects the user already has.

When the 2.0 folder is unpacked on its own (no parent folder) the local copy
is used instead, so the app still works standalone.
"""
from __future__ import annotations

import os

HERE = os.path.dirname(os.path.abspath(__file__))
PARENT = os.path.dirname(HERE)

#: Folders that belong to the 2.0 workspace itself.
WORKSPACE_DIRS = {
    "projects", "projects_backups", "script_library", "script_history", "snapshots",
}

#: Folders that are shared with the rest of the ZeroScript install.
SHARED_DIRS = {
    "skills", "plugins", "editor_docs", "assets_catalog",
}


def install_dir(name: str) -> str:
    """Return the folder that holds ``name`` for this install.

    ``ZS_<NAME>_DIR`` overrides the location, which keeps test runs and
    portable installs away from the real content folders.
    """
    override = os.environ.get("ZS_" + name.upper() + "_DIR")
    if override:
        try:
            os.makedirs(override, exist_ok=True)
        except OSError:
            pass
        return override

    if name in WORKSPACE_DIRS:
        # Workspace state stays inside the 2.0 folder.
        local = os.path.join(HERE, name)
    else:
        shared = os.path.join(PARENT, name)
        local = shared if os.path.isdir(shared) else os.path.join(HERE, name)

    try:
        os.makedirs(local, exist_ok=True)
    except OSError:
        pass
    return local


def install_file(name: str) -> str:
    """Return the path of a shared file such as ``config.json``.

    ``ZS_<NAME>_PATH`` overrides the location.
    """
    override = os.environ.get("ZS_" + name.upper().replace(".", "_") + "_PATH")
    if override:
        return override
    shared = os.path.join(PARENT, name)
    if os.path.isfile(shared):
        return shared
    # The parent folder is the install root when it carries the runtime.
    if os.path.isfile(os.path.join(PARENT, "app.py")):
        return shared
    return os.path.join(HERE, name)
