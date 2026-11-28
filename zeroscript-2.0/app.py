# SPDX-License-Identifier: GPL-3.0-or-later
"""ZeroScript 2.0 - entry point.

The shared runtime (Studio Bridge, skills manager, toolkit, admin registry)
lives in the parent folder; the 2.0 workspace, its authentication layer and
its SQLite database live here.  This launcher wires the two together and
starts the local server.

    python app.py          # ZeroScript 2.0 workspace with authentication
    python app.py --no-tray
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import zs_server  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(zs_server.main())
