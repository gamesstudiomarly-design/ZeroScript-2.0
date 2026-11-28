# SPDX-License-Identifier: GPL-3.0-or-later
"""ZeroScript 4.0 - Launcher with zs_server injection."""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

# Set your custom Admin password
os.environ.setdefault("ZS_OWNER_USERNAME", "admin")
os.environ.setdefault("ZS_OWNER_EMAIL", "admin@zeroscript.com")
os.environ.setdefault("ZS_OWNER_PASSWORD", "admin123@111")

import zs_server  # noqa: E402
import zs_v4  # noqa: E402,F401 - importing the 4.0 engine


def _check_v4_routes():
    """Verify that the 4.0 engine really answers under /api2/v4/.

    The engine used to be injected by monkey-patching the HTTP handler class
    from this launcher.  That patch was applied to the WRONG class: it took
    the first ``BaseHTTPRequestHandler`` subclass found in ``zs_server``, and
    alphabetically that is the BASE v1 handler (``V1Handler``) - while the
    server actually serves ``ZeroScriptHandler``, which overrides
    ``do_GET``/``do_POST``.  The patch was therefore invisible: every
    ``/api2/v4/`` route answered "unknown route" and the 4.0 dashboard
    features (Visual Blueprints, Arena, Webhooks) were dead.

    The engine now rides the server's own route table (``zs_server``), which
    is where it belongs: it is served by the handler that is actually in use
    and it stays behind the normal session + CSRF checks.  A handler patch
    could only ever have bypassed those checks.

    This function only reports - it never patches - so a regression here is
    loud instead of silent.
    """
    routers = zs_server._FEATURE_MODULES.get("routers", [])
    if zs_v4 in routers:
        print("[app2] ✅ ZeroScript 4.0 engine registered - /api2/v4/* is live.")
        return True
    print("[app2] ⚠️ The ZeroScript 4.0 engine is NOT registered - "
          "/api2/v4/* will answer 'unknown route'.")
    print("[app2]    Registered feature routers: "
          + (", ".join(m.__name__ for m in routers) or "(none)"))
    return False


if __name__ == "__main__":
    _check_v4_routes()
    raise SystemExit(zs_server.main())
