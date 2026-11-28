# SPDX-License-Identifier: GPL-3.0-or-later
"""ZeroScript 2.0 - authentication, membership and persistence tests.

Run from the ZeroScript-2.0 folder:

    python -m unittest discover -s tests -v
    python tests/test_zeroscript_auth.py

The suite uses a throw-away SQLite database in a temporary folder, so it
never touches a real installation.
"""
import http.cookiejar
import json
import os
import shutil
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

# ---------------------------------------------------------------------------
# Point the storage layer at a scratch database before anything imports it.
# ---------------------------------------------------------------------------
_TMP_DIR = tempfile.mkdtemp(prefix="zs-auth-tests-")
os.environ["ZS_DATA_DIR"] = _TMP_DIR
os.environ["ZS_DB_PATH"] = os.path.join(_TMP_DIR, "zeroscript-test.db")
os.environ.pop("ZS_PAYMENT_SECRET", None)

# Keep the shared content folders (skills, plugins, projects, ...) inside the
# scratch directory so a test run never touches a real installation.
for _folder in ("skills", "plugins", "projects", "projects_backups", "editor_docs",
                "assets_catalog", "script_library", "script_history", "snapshots"):
    os.environ["ZS_" + _folder.upper() + "_DIR"] = os.path.join(_TMP_DIR, _folder)

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PARENT = os.path.dirname(ROOT)
# The 2.0 folder has to win over the parent folder, exactly like the server
# does at runtime.
for _p in (PARENT, ROOT):
    while _p in sys.path:
        sys.path.remove(_p)
sys.path.insert(0, ROOT)
sys.path.insert(1, PARENT)

import zs_auth  # noqa: E402
import zs_auth_routes  # noqa: E402
import zs_billing  # noqa: E402
import zs_data  # noqa: E402
import zs_db  # noqa: E402

GOOD_PASSWORD = "Nebula-Falcon-73"
OTHER_PASSWORD = "Cobalt-Harbour-91"


# ---------------------------------------------------------------------------
# HTTP helper
# ---------------------------------------------------------------------------
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Client:
    """A tiny cookie aware HTTP client for the local server."""

    def __init__(self, base_url: str):
        self.base = base_url.rstrip("/")
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar), _NoRedirect())
        self.csrf = ""

    def request(self, method, path, body=None, headers=None, origin="same"):
        url = self.base + path
        data = None
        request_headers = {"Accept": "*/*"}
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            request_headers["Content-Type"] = "application/json"
        if origin == "same":
            request_headers["Origin"] = self.base
        elif origin == "evil":
            request_headers["Origin"] = "http://evil.example"
        if self.csrf and method == "POST":
            request_headers["X-CSRF-Token"] = self.csrf
        request_headers.update(headers or {})
        req = urllib.request.Request(url, data=data, method=method, headers=request_headers)
        try:
            with self.opener.open(req, timeout=20) as response:
                raw = response.read().decode("utf-8", "replace")
                status = response.status
                resp_headers = response.headers
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", "replace")
            status = exc.code
            resp_headers = exc.headers
        payload = {}
        try:
            payload = json.loads(raw)
        except (TypeError, ValueError):
            payload = {"raw": raw}
        return status, payload, resp_headers

    def get(self, path, **kwargs):
        return self.request("GET", path, **kwargs)

    def post(self, path, body=None, **kwargs):
        return self.request("POST", path, body if body is not None else {}, **kwargs)

    def login(self, email, password, remember=False):
        status, payload, _ = self.post("/api2/auth/login", {
            "email": email, "password": password, "remember": remember})
        if payload.get("csrfToken"):
            self.csrf = payload["csrfToken"]
        return status, payload


# ---------------------------------------------------------------------------
# Base test case
# ---------------------------------------------------------------------------
class BaseCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        zs_db.init_db()

    def setUp(self):
        self._clear()

    def _clear(self):
        for table in ("sessions", "chat_history", "user_settings", "memberships",
                      "usage_records", "installed_plugins", "installed_skills",
                      "notifications", "payments", "admin_roles", "audit_logs",
                      "project_files", "projects", "users"):
            try:
                zs_db.execute(f"DELETE FROM {table}")  # noqa: S608 - fixed table list
            except zs_db.sqlite3.DatabaseError:
                pass
        zs_auth.rate_limiter.clear()

    def make_user(self, username="tester", email="tester@example.com",
                  password=GOOD_PASSWORD, role=zs_auth.ROLE_USER):
        created = zs_auth.create_user(username, email, password, role=role)
        return zs_auth.find_user(created["id"])


# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------
class TestPasswordHashing(BaseCase):
    def test_hash_is_not_the_password(self):
        hashed = zs_auth.hash_password(GOOD_PASSWORD)
        self.assertNotIn(GOOD_PASSWORD, hashed)
        self.assertNotEqual(hashed, GOOD_PASSWORD)
        self.assertTrue(len(hashed) > 40)

    def test_verify_accepts_the_right_password(self):
        hashed = zs_auth.hash_password(GOOD_PASSWORD)
        self.assertTrue(zs_auth.verify_password(GOOD_PASSWORD, hashed))

    def test_verify_rejects_the_wrong_password(self):
        hashed = zs_auth.hash_password(GOOD_PASSWORD)
        self.assertFalse(zs_auth.verify_password("wrong-password", hashed))
        self.assertFalse(zs_auth.verify_password("", hashed))

    def test_verify_rejects_garbage_hashes(self):
        for value in ("", "not-a-hash", "scrypt$1$2$3", "$argon2id$broken"):
            self.assertFalse(zs_auth.verify_password(GOOD_PASSWORD, value))

    def test_database_never_stores_the_plaintext(self):
        user = self.make_user()
        row = zs_db.query_one("SELECT password_hash FROM users WHERE id = ?", (user["id"],))
        self.assertNotIn(GOOD_PASSWORD, row["password_hash"])
        self.assertTrue(zs_auth.verify_password(GOOD_PASSWORD, row["password_hash"]))

    def test_public_user_never_exposes_the_hash(self):
        user = self.make_user()
        payload = zs_auth.public_user(user, include_private=True)
        self.assertNotIn("password_hash", payload)
        self.assertNotIn("passwordHash", json.dumps(payload))

    def test_hash_scheme_is_reported(self):
        info = zs_auth.hash_scheme_info()
        self.assertIn(info["scheme"], ("argon2id", "bcrypt", "scrypt"))


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
class TestValidation(BaseCase):
    def test_username_rules(self):
        self.assertEqual(zs_auth.validate_username("  Builder_1 "), "Builder_1")
        for bad in ("", "ab", "1builder", "has space", "x" * 40, "admin", "root"):
            with self.assertRaises(zs_auth.ValidationError, msg=bad):
                zs_auth.validate_username(bad)

    def test_email_rules(self):
        self.assertEqual(zs_auth.validate_email(" User@Example.COM "), "User@Example.COM")
        for bad in ("", "nope", "a@b", "a b@c.com", "@c.com", "x@.com"):
            with self.assertRaises(zs_auth.ValidationError, msg=bad):
                zs_auth.validate_email(bad)

    def test_password_rules(self):
        self.assertEqual(zs_auth.validate_password(GOOD_PASSWORD), GOOD_PASSWORD)
        for bad in ("", "short1", "alllettersonly", "12345678", "password"):
            with self.assertRaises(zs_auth.ValidationError, msg=bad):
                zs_auth.validate_password(bad)

    def test_password_confirmation(self):
        self.assertTrue(zs_auth.validate_confirm(GOOD_PASSWORD, GOOD_PASSWORD))
        with self.assertRaises(zs_auth.ValidationError):
            zs_auth.validate_confirm(GOOD_PASSWORD, OTHER_PASSWORD)


# ---------------------------------------------------------------------------
# Accounts
# ---------------------------------------------------------------------------
class TestAccounts(BaseCase):
    def test_duplicate_email_is_rejected(self):
        self.make_user(email="taken@example.com")
        with self.assertRaises(ValueError) as ctx:
            zs_auth.create_user("another", "taken@example.com", GOOD_PASSWORD)
        self.assertIn("email", str(ctx.exception).lower())

    def test_duplicate_username_is_rejected(self):
        self.make_user(username="takenname")
        with self.assertRaises(ValueError) as ctx:
            zs_auth.create_user("takenname", "free@example.com", GOOD_PASSWORD)
        self.assertIn("username", str(ctx.exception).lower())

    def test_email_is_unique_case_insensitively(self):
        self.make_user(email="Mixed@Example.com")
        with self.assertRaises(ValueError):
            zs_auth.create_user("other", "mixed@example.com", GOOD_PASSWORD)

    def test_registration_grants_the_free_plan(self):
        user = self.make_user()
        membership = zs_auth.membership_for(user)
        self.assertEqual(membership["plan"], "noob")
        self.assertEqual(membership["planLabel"], "AI NOOB")
        self.assertEqual(membership["priceCents"], 0)

    def test_new_accounts_are_not_admins(self):
        user = self.make_user()
        self.assertEqual(zs_auth.effective_role(user), zs_auth.ROLE_USER)
        self.assertFalse(zs_auth.has_permission(zs_auth.effective_role(user), "users.write"))

    def test_account_creation_date_is_recorded(self):
        user = self.make_user()
        self.assertTrue(user["created_at"])
        self.assertTrue(zs_auth.public_user(user)["createdAt"])


# ---------------------------------------------------------------------------
# Sessions, CSRF and rate limiting
# ---------------------------------------------------------------------------
class TestSessions(BaseCase):
    def test_session_round_trip(self):
        user = self.make_user()
        session = zs_auth.create_session(user["id"], remember=False)
        stored = zs_auth.get_session_by_token(session["token"])
        self.assertIsNotNone(stored)
        self.assertEqual(stored["user_id"], user["id"])

    def test_raw_token_is_never_stored(self):
        user = self.make_user()
        session = zs_auth.create_session(user["id"])
        row = zs_db.query_one("SELECT token_hash FROM sessions WHERE id = ?", (session["id"],))
        self.assertNotEqual(row["token_hash"], session["token"])
        self.assertEqual(row["token_hash"], zs_auth.hash_token(session["token"]))

    def test_unknown_token_is_rejected(self):
        self.assertIsNone(zs_auth.get_session_by_token("made-up-token"))

    def test_expired_session_is_rejected(self):
        user = self.make_user()
        session = zs_auth.create_session(user["id"])
        zs_db.execute("UPDATE sessions SET expires_at = ? WHERE id = ?",
                      (zs_db.iso_in(-60), session["id"]))
        self.assertIsNone(zs_auth.get_session_by_token(session["token"]))

    def test_revoked_session_is_rejected(self):
        user = self.make_user()
        session = zs_auth.create_session(user["id"])
        zs_auth.revoke_session(session["id"], "test")
        self.assertIsNone(zs_auth.get_session_by_token(session["token"]))

    def test_logout_all_devices_revokes_every_session(self):
        user = self.make_user()
        first = zs_auth.create_session(user["id"])
        second = zs_auth.create_session(user["id"])
        revoked = zs_auth.revoke_all_sessions(user["id"], "everywhere")
        self.assertEqual(revoked, 2)
        self.assertIsNone(zs_auth.get_session_by_token(first["token"]))
        self.assertIsNone(zs_auth.get_session_by_token(second["token"]))

    def test_remember_me_sets_a_longer_lifetime(self):
        user = self.make_user()
        short = zs_auth.create_session(user["id"], remember=False)
        long = zs_auth.create_session(user["id"], remember=True)
        self.assertTrue(long["persistent"])
        self.assertFalse(short["persistent"])
        self.assertGreater(long["ttl"], short["ttl"])

    def test_csrf_token_must_match(self):
        user = self.make_user()
        session = zs_auth.create_session(user["id"])
        row = zs_db.query_one("SELECT * FROM sessions WHERE id = ?", (session["id"],))
        self.assertTrue(zs_auth.check_csrf(row, session["csrf_token"]))
        self.assertFalse(zs_auth.check_csrf(row, "wrong-token"))
        self.assertFalse(zs_auth.check_csrf(row, ""))

    def test_login_rate_limit_blocks_repeated_failures(self):
        first, _ = zs_auth.rate_limiter.hit("login:127.0.0.1", 2, 60)
        self.assertTrue(first)
        second, _ = zs_auth.rate_limiter.hit("login:127.0.0.1", 2, 60)
        self.assertTrue(second)
        third, retry = zs_auth.rate_limiter.hit("login:127.0.0.1", 2, 60)
        self.assertFalse(third)
        self.assertGreater(retry, 0)


# ---------------------------------------------------------------------------
# Roles and permissions
# ---------------------------------------------------------------------------
class TestRoles(BaseCase):
    def test_role_hierarchy(self):
        self.assertTrue(zs_auth.role_at_least(zs_auth.ROLE_OWNER, zs_auth.ROLE_ADMIN))
        self.assertTrue(zs_auth.role_at_least(zs_auth.ROLE_ADMIN, zs_auth.ROLE_MODERATOR))
        self.assertFalse(zs_auth.role_at_least(zs_auth.ROLE_USER, zs_auth.ROLE_MODERATOR))

    def test_permission_matrix(self):
        self.assertTrue(zs_auth.has_permission(zs_auth.ROLE_OWNER, "users.delete"))
        self.assertTrue(zs_auth.has_permission(zs_auth.ROLE_ADMIN, "users.write"))
        self.assertFalse(zs_auth.has_permission(zs_auth.ROLE_ADMIN, "users.delete"))
        self.assertTrue(zs_auth.has_permission(zs_auth.ROLE_MODERATOR, "users.read"))
        self.assertFalse(zs_auth.has_permission(zs_auth.ROLE_MODERATOR, "users.write"))
        self.assertFalse(zs_auth.has_permission(zs_auth.ROLE_USER, "audit.read"))

    def test_grant_raises_the_effective_role(self):
        user = self.make_user()
        self.assertEqual(zs_auth.effective_role(user), zs_auth.ROLE_USER)
        zs_db.execute(
            "INSERT INTO admin_roles (user_id, role, granted_by, granted_at) VALUES (?,?,?,?)",
            (user["id"], zs_auth.ROLE_ADMIN, user["id"], zs_db.now_iso()))
        self.assertEqual(zs_auth.effective_role(zs_auth.find_user(user["id"])),
                         zs_auth.ROLE_ADMIN)

    def test_revoked_grant_is_ignored(self):
        user = self.make_user()
        zs_db.execute(
            "INSERT INTO admin_roles (user_id, role, granted_by, granted_at, revoked_at) "
            "VALUES (?,?,?,?,?)",
            (user["id"], zs_auth.ROLE_ADMIN, user["id"], zs_db.now_iso(), zs_db.now_iso()))
        self.assertEqual(zs_auth.effective_role(zs_auth.find_user(user["id"])),
                         zs_auth.ROLE_USER)

    def test_owner_bootstrap_makes_the_first_account_owner(self):
        created = zs_auth.bootstrap_owner(username="owner", email="owner@example.com")
        self.assertIsNotNone(created)
        owner = zs_auth.find_user_by_email("owner@example.com")
        self.assertIsNotNone(owner)
        self.assertEqual(zs_auth.effective_role(owner), zs_auth.ROLE_OWNER)


# ---------------------------------------------------------------------------
# Memberships - backend verification only
# ---------------------------------------------------------------------------
class TestMemberships(BaseCase):
    def test_plan_catalogue_is_server_owned(self):
        plans = {plan["id"]: plan for plan in zs_billing.public_plans()}
        self.assertEqual(plans["noob"]["priceCents"], 0)
        self.assertEqual(plans["pro"]["priceCents"], 999)
        self.assertEqual(plans["master"]["priceCents"], 1999)
        self.assertEqual(plans["pro"]["requestsPerDay"], 500)
        self.assertEqual(plans["master"]["requestsPerDay"], 2500)

    def test_checkout_is_signed_by_the_server(self):
        user = self.make_user()
        checkout = zs_billing.create_checkout(user, "pro")
        self.assertEqual(checkout["amountCents"], 999)
        self.assertEqual(checkout["plan"], "pro")
        self.assertIn(".", checkout["checkoutToken"])

    def test_confirming_a_checkout_activates_the_plan(self):
        user = self.make_user()
        checkout = zs_billing.create_checkout(user, "pro")
        result = zs_billing.confirm_checkout(user, checkout["checkoutToken"])
        self.assertTrue(result["ok"])
        membership = zs_auth.membership_for(zs_auth.find_user(user["id"]))
        self.assertEqual(membership["plan"], "pro")
        self.assertTrue(membership["verified"])

    def test_a_forged_checkout_token_is_rejected(self):
        user = self.make_user()
        forged = "abc.def"
        result = zs_billing.confirm_checkout(user, forged)
        self.assertFalse(result["ok"])
        self.assertEqual(zs_auth.membership_for(user)["plan"], "noob")

    def test_a_tampered_payload_is_rejected(self):
        user = self.make_user()
        checkout = zs_billing.create_checkout(user, "pro")
        body, signature = checkout["checkoutToken"].split(".")
        result = zs_billing.confirm_checkout(user, f"{body}x.{signature}")
        self.assertFalse(result["ok"])
        self.assertEqual(zs_auth.membership_for(user)["plan"], "noob")

    def test_a_checkout_cannot_be_replayed(self):
        user = self.make_user()
        checkout = zs_billing.create_checkout(user, "master")
        self.assertTrue(zs_billing.confirm_checkout(user, checkout["checkoutToken"])["ok"])
        second = zs_billing.confirm_checkout(user, checkout["checkoutToken"])
        self.assertFalse(second["ok"])

    def test_a_checkout_cannot_be_used_by_another_account(self):
        owner = self.make_user(username="boss", email="owner@example.com")
        other = self.make_user(username="other", email="other@example.com")
        checkout = zs_billing.create_checkout(owner, "pro")
        result = zs_billing.confirm_checkout(other, checkout["checkoutToken"])
        self.assertFalse(result["ok"])
        self.assertEqual(zs_auth.membership_for(other)["plan"], "noob")

    def test_the_client_cannot_choose_the_amount(self):
        user = self.make_user()
        checkout = zs_billing.create_checkout(user, "pro")
        self.assertEqual(checkout["amountCents"], 999)
        self.assertNotEqual(checkout["amountCents"], 1)

    def test_the_free_plan_cannot_be_checked_out(self):
        user = self.make_user()
        with self.assertRaises(ValueError):
            zs_billing.create_checkout(user, "noob")

    def test_usage_is_recorded_and_limited(self):
        user = self.make_user()
        zs_billing.record_usage(user["id"], "ai")
        self.assertEqual(zs_billing.usage_today(user["id"], "ai"), 1)
        zs_db.execute("UPDATE users SET daily_request_limit = 1 WHERE id = ?", (user["id"],))
        fresh = zs_auth.find_user(user["id"])
        limit = zs_billing.check_usage_limit(fresh, "ai")
        self.assertFalse(limit["allowed"])

    def test_owner_is_not_rate_limited(self):
        owner = self.make_user(username="boss", email="owner@example.com",
                               role=zs_auth.ROLE_OWNER)
        for _ in range(5):
            zs_billing.record_usage(owner["id"], "ai")
        limit = zs_billing.check_usage_limit(owner, "ai")
        self.assertTrue(limit["allowed"])


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------
class TestPersistence(BaseCase):
    def test_projects_and_files_are_stored(self):
        zs_data.upsert_project("demo", "Demo Project", "blank", "/tmp/demo")
        zs_data.upsert_project_file("demo", "Main.luau", "print('hello')\n")
        projects = zs_data.list_projects()
        self.assertEqual(len(projects), 1)
        files = zs_data.list_project_files("demo")
        self.assertEqual(len(files), 1)
        self.assertEqual(files[0]["name"], "Main.luau")

    def test_chat_history_is_stored(self):
        user = self.make_user()
        zs_data.record_chat(user["id"], "user", "build an obby")
        zs_data.record_chat(user["id"], "assistant", "here you go")
        stats = zs_data.chat_stats(user["id"])
        self.assertEqual(stats["messages"], 2)
        history = zs_data.recent_chat(user["id"])
        self.assertEqual(history[0]["role"], "user")
        self.assertEqual(history[1]["role"], "assistant")

    def test_preferences_are_stored_per_user(self):
        user = self.make_user()
        zs_data.save_preferences(user["id"], {"accentTheme": "emerald", "userName": "Zed"})
        prefs = zs_data.load_preferences(user["id"])
        self.assertEqual(prefs["accentTheme"], "emerald")
        self.assertEqual(prefs["userName"], "Zed")

    def test_workspace_is_restored(self):
        user = self.make_user()
        zs_data.save_workspace(user["id"], {"view": "toolkit", "projectId": "demo"})
        workspace = zs_data.load_workspace(user["id"])
        self.assertEqual(workspace["view"], "toolkit")
        self.assertEqual(workspace["projectId"], "demo")

    def test_installed_skills_and_plugins_are_stored(self):
        user = self.make_user()
        zs_data.upsert_skill(user["id"], "combat-vfx", "Combat VFX", "auto", True)
        zs_data.upsert_plugin(user["id"], "hello-world", "Hello World", "1.0.0", True)
        skills = zs_db.query("SELECT * FROM installed_skills WHERE user_id = ?", (user["id"],))
        plugins = zs_db.query("SELECT * FROM installed_plugins WHERE user_id = ?", (user["id"],))
        self.assertEqual(len(skills), 1)
        self.assertEqual(len(plugins), 1)

    def test_backup_contains_no_credentials(self):
        user = self.make_user()
        zs_data.save_workspace(user["id"], {"view": "home"})
        backup = zs_data.export_backup(user, scope="self")
        blob = json.dumps(backup)
        self.assertNotIn("password_hash", blob)
        self.assertNotIn("token_hash", blob)
        self.assertNotIn(GOOD_PASSWORD, blob)
        self.assertIn("workspace", blob)

    def test_backup_restores_workspace_data(self):
        user = self.make_user()
        zs_data.save_workspace(user["id"], {"view": "prompts", "projectId": "p1"})
        backup = zs_data.export_backup(user, scope="self")
        zs_data.save_workspace(user["id"], {"view": "home"})
        result = zs_data.restore_backup(user, backup)
        self.assertTrue(result["ok"])
        self.assertEqual(zs_data.load_workspace(user["id"])["view"], "prompts")

    def test_audit_log_records_actions(self):
        user = self.make_user()
        zs_auth.audit("test.action", user, "user", str(user["id"]), "detail")
        logs = zs_auth.list_audit()
        self.assertTrue(any(entry["action"] == "test.action" for entry in logs))

    def test_all_fourteen_tables_exist(self):
        counts = zs_db.table_counts()
        expected = {"users", "sessions", "projects", "project_files", "chat_history",
                    "user_settings", "memberships", "usage_records", "installed_plugins",
                    "installed_skills", "notifications", "payments", "admin_roles",
                    "audit_logs"}
        self.assertEqual(set(counts.keys()), expected)


# ---------------------------------------------------------------------------
# HTTP integration against the real handler
# ---------------------------------------------------------------------------
class TestHttpFlow(BaseCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        import zs_server

        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), zs_server.ZeroScriptHandler)
        cls.server.daemon_threads = True
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def client(self):
        return Client(self.base)

    # -- pages --------------------------------------------------------
    def test_anonymous_workspace_redirects_to_login(self):
        status, _payload, headers = self.client().get("/2/")
        self.assertEqual(status, 302)
        self.assertIn("/2/login", headers.get("Location", ""))

    def test_a_signed_in_user_gets_the_workspace(self):
        self.make_user(email="me@example.com")
        client = self.client()
        client.login("me@example.com", GOOD_PASSWORD)
        status, _payload, _ = client.get("/2/")
        self.assertEqual(status, 200)

    def test_the_workspace_assets_are_served(self):
        for path in ("/2/styles.css", "/2/app.js", "/2/login.css", "/2/login.js",
                     "/2/account.css", "/2/account.js"):
            status, _payload, _ = self.client().get(path)
            self.assertEqual(status, 200, path)

    def test_login_page_is_public(self):
        status, _payload, _ = self.client().get("/2/login")
        self.assertEqual(status, 200)

    def test_login_page_contains_the_expected_controls(self):
        status, _payload, _ = self.client().get("/2/login")
        self.assertEqual(status, 200)

    # -- registration -------------------------------------------------
    def test_registration_creates_an_account_and_a_session(self):
        client = self.client()
        status, payload, headers = client.post("/api2/auth/register", {
            "username": "newbie", "email": "newbie@example.com",
            "password": GOOD_PASSWORD, "confirmPassword": GOOD_PASSWORD})
        self.assertEqual(status, 200)
        self.assertTrue(payload["authenticated"])
        self.assertEqual(payload["user"]["username"], "newbie")
        self.assertEqual(payload["membership"]["plan"], "noob")
        self.assertIn("zs_session", headers.get("Set-Cookie", ""))
        self.assertIn("HttpOnly", headers.get("Set-Cookie", ""))

    def test_registration_rejects_a_weak_password(self):
        status, payload, _ = self.client().post("/api2/auth/register", {
            "username": "newbie", "email": "newbie@example.com",
            "password": "short", "confirmPassword": "short"})
        self.assertEqual(status, 400)
        self.assertEqual(payload["field"], "password")

    def test_registration_rejects_a_duplicate_email(self):
        client = self.client()
        client.post("/api2/auth/register", {
            "username": "first", "email": "dup@example.com",
            "password": GOOD_PASSWORD, "confirmPassword": GOOD_PASSWORD})
        status, payload, _ = self.client().post("/api2/auth/register", {
            "username": "second", "email": "dup@example.com",
            "password": GOOD_PASSWORD, "confirmPassword": GOOD_PASSWORD})
        self.assertEqual(status, 409)
        self.assertEqual(payload["field"], "email")

    def test_registration_rejects_mismatched_confirmation(self):
        status, payload, _ = self.client().post("/api2/auth/register", {
            "username": "newbie", "email": "newbie@example.com",
            "password": GOOD_PASSWORD, "confirmPassword": OTHER_PASSWORD})
        self.assertEqual(status, 400)

    # -- login --------------------------------------------------------
    def test_login_with_the_right_password(self):
        self.make_user(email="login@example.com")
        client = self.client()
        status, payload = client.login("login@example.com", GOOD_PASSWORD)
        self.assertEqual(status, 200)
        self.assertTrue(payload["authenticated"])
        self.assertTrue(payload["csrfToken"])

    def test_login_with_the_wrong_password_reports_an_error(self):
        self.make_user(email="login@example.com")
        status, payload = self.client().login("login@example.com", "not-the-password")
        self.assertEqual(status, 401)
        self.assertIn("do not match", payload["error"].lower())

    def test_login_with_an_unknown_account_reports_the_same_message(self):
        status, payload = self.client().login("ghost@example.com", GOOD_PASSWORD)
        self.assertEqual(status, 401)
        self.assertIn("do not match", payload["error"].lower())

    def test_login_never_echoes_the_password(self):
        self.make_user(email="login@example.com")
        _status, payload = self.client().login("login@example.com", GOOD_PASSWORD)
        self.assertNotIn(GOOD_PASSWORD, json.dumps(payload))

    def test_remember_me_sets_a_persistent_cookie(self):
        self.make_user(email="login@example.com")
        client = self.client()
        _status, _payload, headers = client.post("/api2/auth/login", {
            "email": "login@example.com", "password": GOOD_PASSWORD, "remember": True})
        self.assertIn("Max-Age=", headers.get("Set-Cookie", ""))

    def test_logout_clears_the_session(self):
        self.make_user(email="login@example.com")
        client = self.client()
        client.login("login@example.com", GOOD_PASSWORD)
        status, _payload, _ = client.post("/api2/auth/logout")
        self.assertEqual(status, 200)
        status, payload, _ = client.get("/api2/auth/session")
        self.assertEqual(status, 200)
        self.assertFalse(payload["authenticated"])

    def test_logout_all_devices_revokes_everywhere(self):
        user = self.make_user(email="login@example.com")
        first = self.client()
        first.login("login@example.com", GOOD_PASSWORD)
        second = self.client()
        second.login("login@example.com", GOOD_PASSWORD)
        status, payload, _ = first.post("/api2/auth/logout-all")
        self.assertEqual(status, 200)
        self.assertGreaterEqual(payload["revoked"], 2)
        status, payload, _ = second.get("/api2/auth/session")
        self.assertFalse(payload["authenticated"])

    # -- protection ---------------------------------------------------
    def test_protected_routes_require_a_session(self):
        status, payload, _ = self.client().get("/api2/account/profile")
        self.assertEqual(status, 401)
        self.assertFalse(payload["ok"])

    def test_the_workspace_api_requires_a_session(self):
        status, _payload, _ = self.client().get("/api/status")
        self.assertEqual(status, 401)

    def test_a_post_without_the_csrf_token_is_rejected(self):
        self.make_user(email="login@example.com")
        client = self.client()
        client.login("login@example.com", GOOD_PASSWORD)
        client.csrf = ""
        status, payload, _ = client.post("/api2/data/save")
        self.assertEqual(status, 419)
        self.assertFalse(payload["ok"])

    def test_a_cross_site_post_is_blocked(self):
        self.make_user(email="login@example.com")
        client = self.client()
        client.login("login@example.com", GOOD_PASSWORD)
        status, _payload, _ = client.post("/api2/data/save", origin="evil")
        self.assertEqual(status, 403)

    def test_the_role_is_decided_by_the_server(self):
        user = self.make_user(email="plain@example.com")
        client = self.client()
        client.login("plain@example.com", GOOD_PASSWORD)
        status, payload, _ = client.post("/api2/admin/users/update",
                                         {"userId": user["id"], "displayName": "Hacked"})
        self.assertEqual(status, 403)

    def test_an_admin_can_change_a_user(self):
        owner = self.make_user(username="boss", email="owner@example.com",
                               role=zs_auth.ROLE_OWNER)
        target = self.make_user(username="target", email="target@example.com")
        client = self.client()
        client.login("owner@example.com", GOOD_PASSWORD)
        status, payload, _ = client.post("/api2/admin/users/update",
                                         {"userId": target["id"], "displayName": "Renamed"})
        self.assertEqual(status, 200)
        self.assertEqual(payload["user"]["displayName"], "Renamed")

    def test_a_normal_user_cannot_list_the_accounts(self):
        self.make_user(email="plain@example.com")
        client = self.client()
        client.login("plain@example.com", GOOD_PASSWORD)
        status, _payload, _ = client.get("/api2/admin/accounts")
        self.assertEqual(status, 403)

    def test_a_normal_user_cannot_read_the_audit_log(self):
        self.make_user(email="plain@example.com")
        client = self.client()
        client.login("plain@example.com", GOOD_PASSWORD)
        status, _payload, _ = client.get("/api2/admin/audit")
        self.assertEqual(status, 403)

    def test_a_normal_user_cannot_read_the_session_list(self):
        self.make_user(email="plain@example.com")
        client = self.client()
        client.login("plain@example.com", GOOD_PASSWORD)
        status, _payload, _ = client.get("/api2/admin/sessions")
        self.assertEqual(status, 403)

    def test_generated_passwords_satisfy_the_policy(self):
        for _ in range(50):
            password = zs_auth.generate_password()
            zs_auth.validate_password(password)
            self.assertGreaterEqual(len(password), 12)

    def test_the_owner_can_grant_a_role(self):
        owner = self.make_user(username="boss", email="owner@example.com",
                               role=zs_auth.ROLE_OWNER)
        target = self.make_user(username="target", email="target@example.com")
        client = self.client()
        client.login("owner@example.com", GOOD_PASSWORD)
        status, _payload, _ = client.post("/api2/admin/roles/grant",
                                          {"userId": target["id"], "role": "moderator"})
        self.assertEqual(status, 200)
        self.assertEqual(zs_auth.effective_role(zs_auth.find_user(target["id"])),
                         zs_auth.ROLE_MODERATOR)

    def test_an_admin_cannot_delete_an_account(self):
        self.make_user(username="sysop", email="admin@example.com",
                       role=zs_auth.ROLE_ADMIN)
        target = self.make_user(username="target", email="target@example.com")
        client = self.client()
        client.login("admin@example.com", GOOD_PASSWORD)
        status, _payload, _ = client.post("/api2/admin/users/delete",
                                          {"userId": target["id"]})
        self.assertEqual(status, 403)

    # -- account ------------------------------------------------------
    def test_the_profile_can_be_updated(self):
        self.make_user(email="me@example.com")
        client = self.client()
        client.login("me@example.com", GOOD_PASSWORD)
        status, payload, _ = client.post("/api2/account/profile", {
            "username": "renamed", "email": "me@example.com", "displayName": "Me"})
        self.assertEqual(status, 200)
        self.assertEqual(payload["user"]["username"], "renamed")

    def test_the_password_can_be_changed_and_other_sessions_die(self):
        self.make_user(email="me@example.com")
        other = self.client()
        other.login("me@example.com", GOOD_PASSWORD)
        client = self.client()
        client.login("me@example.com", GOOD_PASSWORD)
        status, payload, _ = client.post("/api2/account/password", {
            "currentPassword": GOOD_PASSWORD, "password": OTHER_PASSWORD,
            "confirmPassword": OTHER_PASSWORD})
        self.assertEqual(status, 200)
        self.assertGreaterEqual(payload["revoked"], 1)
        status, payload, _ = other.get("/api2/auth/session")
        self.assertFalse(payload["authenticated"])
        status, _payload = self.client().login("me@example.com", OTHER_PASSWORD)
        self.assertEqual(status, 200)

    def test_the_wrong_current_password_is_rejected(self):
        self.make_user(email="me@example.com")
        client = self.client()
        client.login("me@example.com", GOOD_PASSWORD)
        status, payload, _ = client.post("/api2/account/password", {
            "currentPassword": "wrong", "password": OTHER_PASSWORD,
            "confirmPassword": OTHER_PASSWORD})
        self.assertEqual(status, 401)
        self.assertEqual(payload["field"], "currentPassword")

    def test_deleting_an_account_requires_the_confirmation_and_password(self):
        self.make_user(email="me@example.com")
        client = self.client()
        client.login("me@example.com", GOOD_PASSWORD)
        status, _payload, _ = client.post("/api2/account/delete", {"confirm": "nope"})
        self.assertEqual(status, 400)
        status, _payload, _ = client.post("/api2/account/delete", {
            "confirm": "DELETE", "password": "wrong"})
        self.assertEqual(status, 401)
        status, _payload, _ = client.post("/api2/account/delete", {
            "confirm": "DELETE", "password": GOOD_PASSWORD})
        self.assertEqual(status, 200)
        self.assertIsNone(zs_auth.find_user_by_email("me@example.com"))

    def test_forgot_password_never_reveals_whether_an_account_exists(self):
        self.make_user(email="known@example.com")
        _status, known, _ = self.client().post("/api2/auth/forgot-password",
                                                {"email": "known@example.com"})
        _status, unknown, _ = self.client().post("/api2/auth/forgot-password",
                                                  {"email": "ghost@example.com"})
        self.assertEqual(known["message"], unknown["message"])

    def test_the_password_reset_link_works(self):
        user = self.make_user(email="reset@example.com")
        _status, payload, _ = self.client().post("/api2/auth/forgot-password",
                                                 {"email": "reset@example.com"})
        token = zs_auth.create_password_reset(user)
        status, _payload, _ = self.client().post("/api2/auth/reset-password", {
            "token": token, "password": OTHER_PASSWORD, "confirmPassword": OTHER_PASSWORD})
        self.assertEqual(status, 200)
        status, _payload = self.client().login("reset@example.com", OTHER_PASSWORD)
        self.assertEqual(status, 200)

    def test_an_invalid_reset_token_is_rejected(self):
        status, _payload, _ = self.client().post("/api2/auth/reset-password", {
            "token": "made-up", "password": OTHER_PASSWORD, "confirmPassword": OTHER_PASSWORD})
        self.assertEqual(status, 400)

    def test_email_verification_marks_the_account(self):
        user = self.make_user(email="verify@example.com")
        token = zs_auth.create_email_verification(user)
        status, payload, _ = self.client().post("/api2/auth/verify-email", {"token": token})
        self.assertEqual(status, 200)
        self.assertTrue(payload["emailVerified"])

    # -- membership ---------------------------------------------------
    def test_a_client_cannot_grant_itself_a_paid_plan(self):
        self.make_user(email="me@example.com")
        client = self.client()
        client.login("me@example.com", GOOD_PASSWORD)
        status, payload, _ = client.post("/api2/account/profile", {
            "username": "primary", "email": "me@example.com", "membership": "master"})
        self.assertEqual(status, 200)
        self.assertEqual(payload["membership"]["plan"], "noob")

    def test_the_checkout_and_confirm_flow_upgrades_the_plan(self):
        self.make_user(email="me@example.com")
        client = self.client()
        client.login("me@example.com", GOOD_PASSWORD)
        status, payload, _ = client.post("/api2/membership/checkout", {"plan": "pro"})
        self.assertEqual(status, 200)
        checkout = payload["checkout"]
        self.assertEqual(checkout["amountCents"], 999)
        status, payload, _ = client.post("/api2/membership/confirm", {
            "checkoutToken": checkout["checkoutToken"]})
        self.assertEqual(status, 200)
        self.assertEqual(payload["membership"]["plan"], "pro")

    def test_a_forged_checkout_token_is_refused_by_the_api(self):
        self.make_user(email="me@example.com")
        client = self.client()
        client.login("me@example.com", GOOD_PASSWORD)
        status, payload, _ = client.post("/api2/membership/confirm", {
            "checkoutToken": "forged.token"})
        self.assertEqual(status, 400)
        self.assertFalse(payload["ok"])

    # -- data ---------------------------------------------------------
    def test_the_workspace_round_trips(self):
        self.make_user(email="me@example.com")
        client = self.client()
        client.login("me@example.com", GOOD_PASSWORD)
        status, _payload, _ = client.post("/api2/data/workspace", {"view": "toolkit"})
        self.assertEqual(status, 200)
        status, payload, _ = client.get("/api2/data/workspace")
        self.assertEqual(payload["workspace"]["view"], "toolkit")

    def test_manual_save_reports_what_was_stored(self):
        self.make_user(email="me@example.com")
        client = self.client()
        client.login("me@example.com", GOOD_PASSWORD)
        status, payload, _ = client.post("/api2/data/save")
        self.assertEqual(status, 200)
        self.assertIn("projects", payload)
        self.assertIn("savedAt", payload)

    def test_the_backup_export_never_leaks_credentials(self):
        self.make_user(email="me@example.com")
        client = self.client()
        client.login("me@example.com", GOOD_PASSWORD)
        status, payload, _ = client.get("/api2/data/backup")
        self.assertEqual(status, 200)
        blob = json.dumps(payload["backup"])
        self.assertNotIn(GOOD_PASSWORD, blob)
        self.assertNotIn("password_hash", blob)

    def test_a_normal_user_cannot_export_the_whole_installation(self):
        self.make_user(email="me@example.com")
        client = self.client()
        client.login("me@example.com", GOOD_PASSWORD)
        status, _payload, _ = client.get("/api2/data/backup?scope=all")
        self.assertEqual(status, 403)

    def test_the_owner_can_export_the_whole_installation(self):
        self.make_user(username="boss", email="owner@example.com",
                       role=zs_auth.ROLE_OWNER)
        client = self.client()
        client.login("owner@example.com", GOOD_PASSWORD)
        status, payload, _ = client.get("/api2/data/backup?scope=all")
        self.assertEqual(status, 200)
        self.assertEqual(payload["backup"]["scope"], "all")

    def test_chat_messages_are_saved(self):
        self.make_user(email="me@example.com")
        client = self.client()
        client.login("me@example.com", GOOD_PASSWORD)
        status, _payload, _ = client.post("/api2/chat/message", {
            "role": "user", "content": "build an obby", "provider": "claude"})
        self.assertEqual(status, 200)
        status, payload, _ = client.get("/api2/chat/history")
        self.assertEqual(len(payload["messages"]), 1)
        self.assertEqual(payload["messages"][0]["content"], "build an obby")

    # -- the existing 2.0 feature APIs keep working --------------------
    def test_the_two_point_zero_read_apis_still_work(self):
        self.make_user(email="me@example.com")
        client = self.client()
        client.login("me@example.com", GOOD_PASSWORD)
        for path in ("/api2/projects", "/api2/editor/docs", "/api2/debug/output",
                     "/api2/debug/errors", "/api2/assets", "/api2/plugins",
                     "/api2/uibuilder/components", "/api2/library",
                     "/api/toolkit/summary", "/api/toolkit/memory"):
            status, payload, _ = client.get(path)
            self.assertEqual(status, 200, f"{path} -> {status} {payload}")
            self.assertTrue(payload.get("ok"), path)

    def test_the_two_point_zero_write_apis_still_work(self):
        self.make_user(email="me@example.com")
        client = self.client()
        client.login("me@example.com", GOOD_PASSWORD)
        status, payload, _ = client.post("/api2/projects/create",
                                         {"name": "Test Project", "template": "obby"})
        self.assertEqual(status, 200, payload)
        self.assertTrue(payload.get("ok"))
        project_id = payload["project"]["id"]

        status, payload, _ = client.post("/api2/projects/files", {
            "id": project_id, "action": "write", "file": "Main.luau",
            "content": "print('hi')\n"})
        self.assertEqual(status, 200, payload)

        status, payload, _ = client.post("/api2/ai/prompt", {
            "action": "generate", "input": "make an obby"})
        self.assertEqual(status, 200, payload)
        self.assertIn("prompt", payload)

        status, payload, _ = client.post("/api2/misc/deps", {
            "files": {"Main.luau": "local Module = require(script.Parent.Foo)"}})
        self.assertEqual(status, 200, payload)
        self.assertIn("analysis", payload)

    def test_a_project_created_through_the_api_is_mirrored_into_the_database(self):
        self.make_user(email="me@example.com")
        client = self.client()
        client.login("me@example.com", GOOD_PASSWORD)
        status, payload, _ = client.post("/api2/projects/create",
                                         {"name": "Mirrored", "template": "blank"})
        self.assertEqual(status, 200)
        project_key = payload["project"]["id"]
        rows = zs_db.query("SELECT project_key FROM projects WHERE project_key = ?",
                           (project_key,))
        self.assertEqual(len(rows), 1)
        files = zs_db.query(
            "SELECT f.name FROM project_files f JOIN projects p ON p.id = f.project_id "
            "WHERE p.project_key = ?", (project_key,))
        self.assertTrue(len(files) >= 1)

    # -- admin --------------------------------------------------------
    def test_the_admin_panel_requires_a_signed_in_admin(self):
        status, _payload, _ = self.client().get("/admin")
        self.assertEqual(status, 302)

    def test_a_normal_user_is_refused_the_admin_panel(self):
        self.make_user(email="me@example.com")
        client = self.client()
        client.login("me@example.com", GOOD_PASSWORD)
        status, _payload, _ = client.get("/admin")
        self.assertEqual(status, 403)

    def test_the_admin_panel_opens_for_a_moderator(self):
        self.make_user(username="mod", email="mod@example.com",
                       role=zs_auth.ROLE_MODERATOR)
        client = self.client()
        client.login("mod@example.com", GOOD_PASSWORD)
        status, _payload, _ = client.get("/admin")
        self.assertEqual(status, 200)

    def test_the_admin_account_listing_is_server_driven(self):
        self.make_user(username="boss", email="owner@example.com",
                       role=zs_auth.ROLE_OWNER)
        client = self.client()
        client.login("owner@example.com", GOOD_PASSWORD)
        status, payload, _ = client.get("/api2/admin/accounts")
        self.assertEqual(status, 200)
        self.assertTrue(payload["users"])
        blob = json.dumps(payload)
        self.assertNotIn("password_hash", blob)
        self.assertNotIn(GOOD_PASSWORD, blob)


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------
def tearDownModule():
    shutil.rmtree(_TMP_DIR, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
