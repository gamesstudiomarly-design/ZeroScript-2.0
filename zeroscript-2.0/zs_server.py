# SPDX-License-Identifier: GPL-3.0-or-later
"""ZeroScript 2.0 - HTTP server with authentication.

This module owns the request pipeline for the 2.0 workspace:

* every browser page and every ``/api2/`` or ``/api/`` call is routed through
  the authentication layer,
* anonymous visitors are sent to the login page,
* the SQLite database is opened and the first local owner account is created
  on the very first run.

The ZeroScript AI tools, the Studio Bridge, the MCP integrations, plugins,
skills and project handling all keep working exactly as before - they are
served by the inherited v1 handler.
"""
from __future__ import annotations

import importlib.util
import os
import sys
import threading
import time
from urllib.parse import quote

HERE = os.path.dirname(os.path.abspath(__file__))
PARENT = os.path.dirname(HERE)

# The 2.0 folder owns the runtime it ships (bridge, skills manager, project
# manager, plugin SDK, toolkit and admin registry).  The parent folder stays
# on the path as a fallback for anything that only exists there.
#
# The order matters: the 2.0 copies must win, otherwise a parent module with
# the same name would shadow the upgraded one.
for _p in (PARENT, HERE):
    while _p in sys.path:
        sys.path.remove(_p)
sys.path.insert(0, HERE)
sys.path.insert(1, PARENT)

import zs_auth  # noqa: E402
import zs_auth_routes  # noqa: E402
import zs_db  # noqa: E402

UI_DIR = os.path.join(HERE, "app_ui2")

#: Authentication is on by default.  Set ZS_AUTH_REQUIRED=0 to run the
#: workspace in the old open mode (useful for a single user kiosk).
AUTH_REQUIRED = os.environ.get("ZS_AUTH_REQUIRED", "1").strip().lower() not in (
    "0", "false", "no", "off")

#: Roles that may open the Ultimate Admin Panel.
ADMIN_ROLES = (zs_auth.ROLE_OWNER, zs_auth.ROLE_ADMIN, zs_auth.ROLE_MODERATOR)

HAS_V1 = True
try:
    # The full v1 implementation lives in the parent folder.  It is loaded by
    # path so that "import app" inside it cannot resolve back to the launcher
    # that sits next to this file.
    _spec = importlib.util.spec_from_file_location("app", os.path.join(PARENT, "app.py"))
    if _spec is None or _spec.loader is None:
        raise ImportError("the ZeroScript runtime could not be located")
    sys.modules["app"] = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(sys.modules["app"])
    from app import (  # noqa: E402
        AppHandler as V1Handler,
        open_app_window,
        request_shutdown,
        _start_bridge_thread,
        _shutdown_requested,
        HAS_PYQT6,
        _run_tray,
    )
except Exception as exc:  # pragma: no cover - the parent runtime is required
    print(f"[zs_server] the ZeroScript runtime could not be loaded: {exc}")
    V1Handler = object
    HAS_V1 = False
    HAS_PYQT6 = False
    open_app_window = request_shutdown = _start_bridge_thread = _run_tray = None
    _shutdown_requested = threading.Event()


# ---------------------------------------------------------------------------
# Storage bootstrap
# ---------------------------------------------------------------------------
def bootstrap_storage() -> dict:
    """Create the database and, on the very first run, the owner account."""
    zs_db.init_db()
    result = {"created": False}
    # Make sure the strongest password hashing scheme is available.
    try:
        zs_auth.ensure_strong_hasher()
    except Exception as exc:
        print(f"[zs_server] password hashing setup skipped: {exc}")
    try:
        import zs_persist
        zs_persist.install()
    except Exception as exc:
        print(f"[zs_server] automatic persistence could not be attached: {exc}")
    owner = zs_auth.bootstrap_owner()
    if owner:
        zs_db.ensure_dirs()
        path = os.path.join(zs_db.DATA_DIR, "first-run-owner.txt")
        try:
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(
                    "ZeroScript local owner account\n"
                    "================================\n"
                    f"username : {owner['username']}\n"
                    f"email    : {owner['email']}\n"
                    f"password : {owner['password']}\n\n"
                    "Sign in at /2/login and change the password from Account settings.\n"
                    "Delete this file once you have done that.\n"
                )
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
        except OSError:
            path = ""
        zs_auth.add_notification(
            owner["id"], "Owner account created",
            "Your local owner account is ready. The one-time bootstrap credentials were "
            f"written to {path or 'the data folder'}. Change the password from Account settings.",
            kind="success")
        result = {"created": True, "username": owner["username"],
                  "email": owner["email"], "password": owner["password"], "file": path}
        print("[zs_server] first run: owner account '%s' created." % owner["username"])
        print("[zs_server] bootstrap credentials written to: %s" % (path or "(unavailable)"))
    zs_db.set_setting("auth_required", "1" if AUTH_REQUIRED else "0")
    return result


# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------
if HAS_V1:
    class ZeroScriptHandler(V1Handler):
        """The 2.0 workspace handler: v1 features plus the auth layer."""

        # -- helpers -------------------------------------------------
        def _serve_file(self, path):
            """Serve a static file with the security headers attached."""
            return zs_auth_routes.send_file(self, path)

        def _gate_html(self, path: str, next_url: str = "") -> bool:
            """Redirect an anonymous browser request to the login page."""
            if not AUTH_REQUIRED:
                return False
            session, _user = zs_auth_routes.current_session(self)
            if session is not None:
                return False
            target = next_url or path or "/2/"
            zs_auth_routes.send_redirect(self, f"/2/login?next={quote(target)}")
            return True

        def _wants_html(self) -> bool:
            try:
                accept = (self.headers.get("Accept") or "").lower()
            except Exception:
                return False
            return "text/html" in accept

        # -- GET -----------------------------------------------------
        def do_GET(self):
            path = self.path.split("?", 1)[0]

            # Authentication, account, data, chat, membership and admin APIs
            # plus the login / account pages.
            if zs_auth_routes.handle_get(self, path):
                return

            if path in ("/", "/2", "/2/", "/2/index.html"):
                if self._gate_html(path, "/2/"):
                    return
                return zs_auth_routes.send_file(self, os.path.join(UI_DIR, "index.html"))

            if path == "/2/styles.css":
                return zs_auth_routes.send_file(self, os.path.join(UI_DIR, "styles.css"))

            if path == "/2/app.js":
                return zs_auth_routes.send_file(self, os.path.join(UI_DIR, "app.js"))

            if path in ("/2/ai_os.html", "/2/ai_os.css", "/2/ai_os.js"):
                name = path.rsplit("/", 1)[-1]
                return zs_auth_routes.send_file(self, os.path.join(UI_DIR, name))

            if path in ("/admin", "/admin.html"):
                return self._serve_admin_page()

            if path == "/admin.css":
                return zs_auth_routes.send_file(self, os.path.join(UI_DIR, "admin.css"))

            if path == "/admin.js":
                return zs_auth_routes.send_file(self, os.path.join(UI_DIR, "admin.js"))

            # The remaining 2.0 APIs.
            if path.startswith("/api2/"):
                for module in _FEATURE_MODULES["get"]:
                    handled = module(self, path)
                    if handled:
                        return
                return zs_auth_routes.send_json(self, 404, {"ok": False, "error": f"unknown route: {path}"})

            # The shared v1 APIs used by the 2.0 workspace.
            if path.startswith("/api/"):
                if not zs_auth_routes.precheck_get(self, path):
                    return
                return super().do_GET()

            return super().do_GET()

        def _serve_admin_page(self):
            session, user = zs_auth_routes.current_session(self)
            if AUTH_REQUIRED and session is None:
                zs_auth_routes.send_redirect(self, "/2/login?next=%2Fadmin")
                return
            if session is not None:
                role = zs_auth.effective_role(user)
                if role not in ADMIN_ROLES:
                    zs_auth_routes.send_json(self, 403, {
                        "ok": False,
                        "error": "Your role does not grant access to the admin panel.",
                    })
                    return
            return zs_auth_routes.send_file(self, os.path.join(UI_DIR, "admin.html"))

        # -- POST ----------------------------------------------------
        def _read_json(self):
            """Serve the body that was already read, then fall back to the wire."""
            cached = getattr(self, "_zs_body", None)
            if cached is not None:
                self._zs_body = None
                return cached
            return super()._read_json()

        def do_POST(self):
            path = self.path.split("?", 1)[0]

            # The body is always consumed, even when the request is rejected.
            # Leaving it unread breaks the connection for the client.
            body = self._read_json()
            self._zs_body = body
            try:
                if path.startswith("/api2/"):
                    if not zs_auth_routes.precheck(self, path):
                        return
                    if zs_auth_routes.handle_post(self, path, body):
                        return
                    for module in _FEATURE_MODULES["post"]:
                        handled = module(self, path, body)
                        if handled:
                            return
                    return zs_auth_routes.send_json(
                        self, 404, {"ok": False, "error": f"unknown route: {path}"})

                if path.startswith("/api/"):
                    # The v1 handler reads the request body itself, so only the
                    # session and CSRF check happens here.
                    if not zs_auth_routes.precheck(self, path):
                        return
                    return super().do_POST()

                return super().do_POST()
            finally:
                self._zs_body = None


# The 2.0 feature modules are wired in below, once they can import the
# server helpers without creating an import cycle.
_FEATURE_MODULES = {"routers": [], "get": [], "post": []}
_FEATURE_MODULES_BUILT = False


def _build_feature_modules():
    """Import the 2.0 feature routers and register them in call order.

    GET and POST use different signatures, so each router is wrapped for the
    verb it actually serves.

    The 4.0 engine (``zs_v4``) is registered here as well.  It used to be
    injected by ``app2.py`` monkey-patching the HTTP handler class, but that
    patch landed on the BASE v1 handler while the server serves
    ``ZeroScriptHandler``, which overrides ``do_GET``/``do_POST`` - so every
    ``/api2/v4/`` route answered "unknown route" and the 4.0 dashboard
    features (Visual Blueprints, Arena, Webhooks) never worked.  Registering
    the engine in this table fixes the routing and, unlike a handler patch,
    keeps it behind the normal session + CSRF checks that ``do_POST`` runs
    before any router is called.

    A broken or missing 4.0 engine must not take the other routers down
    with it, so its import is isolated.
    """
    import routes_2
    import zs_batch5
    import zs_studio
    import zs_v3

    try:
        import zs_v4
    except Exception as _exc:  # pragma: no cover - defensive
        print(f"[zs_server] the 4.0 engine could not be loaded: {_exc}")
        zs_v4 = None

    def _getter(fn):
        def _call(handler, path, body=None):
            _res, handled = fn(handler, path)
            return handled
        return _call

    def _poster(fn):
        def _call(handler, path, body=None):
            _res, handled = fn(handler, path, body or {})
            return handled
        return _call

    routers = []
    if zs_v4 is not None:
        routers.append(zs_v4)
    routers.extend((zs_v3, zs_batch5, zs_studio, routes_2))

    return {
        "routers": routers,
        "get": [_getter(m.handle_get) for m in routers],
        "post": [_poster(m.handle_post) for m in routers],
    }


# The automatic persistence hooks are attached as soon as this module loads,
# so projects, files, skills, plugins and AI conversations are mirrored into
# the database no matter how the server was started.
try:
    import zs_persist

    zs_persist.install()
except Exception as _exc:  # pragma: no cover - defensive
    print(f"[zs_server] automatic persistence could not be attached: {_exc}")

# The feature routers are attached as soon as this module loads, so the
# handler works even when it is used without the launcher (tests, embedding).
try:
    _FEATURE_MODULES = _build_feature_modules()
    _FEATURE_MODULES_BUILT = True
except Exception as _exc:  # pragma: no cover - defensive
    print(f"[zs_server] the 2.0 feature routes could not be attached: {_exc}")
    _FEATURE_MODULES = {"routers": [], "get": [], "post": []}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    if not HAS_V1:
        print("ZeroScript needs the shared runtime from the parent folder.")
        return 1

    bootstrap_storage()

    import app as v1
    from http.server import ThreadingHTTPServer

    settings = v1.skills_manager.load_settings()
    port = int(os.environ.get("ZS_APP_PORT") or settings.get("appPort") or 17614)
    app_url = f"http://127.0.0.1:{port}/2/"

    global _FEATURE_MODULES, _FEATURE_MODULES_BUILT
    if not _FEATURE_MODULES_BUILT:
        _FEATURE_MODULES = _build_feature_modules()
        _FEATURE_MODULES_BUILT = True

    if v1._existing_instance_alive(port) or not v1._acquire_single_instance_mutex():
        v1.open_app_window(app_url)
        return 0

    try:
        http_server = ThreadingHTTPServer(("127.0.0.1", port), ZeroScriptHandler)
    except OSError:
        if v1._existing_instance_alive(port):
            v1.open_app_window(app_url)
            return 0
        raise

    v1._http_server = http_server
    v1._start_bridge_thread()
    threading.Thread(target=http_server.serve_forever, daemon=True).start()

    if settings.get("autoOpenWindow", True) and "--no-window" not in sys.argv:
        threading.Timer(0.35, lambda: v1.open_app_window(app_url)).start()

    print(f"[zs_server] ZeroScript 2.0 is running at {app_url}")
    print(f"[zs_server] authentication: {'required' if AUTH_REQUIRED else 'disabled'}")

    if HAS_PYQT6 and "--no-tray" not in sys.argv:
        v1._run_tray(app_url)
    else:
        try:
            while not v1._shutdown_requested.is_set():
                time.sleep(0.5)
        except KeyboardInterrupt:
            v1.request_shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
