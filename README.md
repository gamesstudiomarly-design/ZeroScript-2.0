## ZeroScript 4.0.1 — bug fixes + full source tree

This branch publishes the complete ZeroScript Free source tree and fixes four
real defects that were breaking the 4.0 dashboard.

### Fixed

1. **The entire ZeroScript 4.0 engine was unreachable.** `app2.py` injected
   `zs_v4` by monkey-patching the HTTP handler class, but it selected the
   *first* `BaseHTTPRequestHandler` subclass in `zs_server` — alphabetically
   the base v1 handler `AppHandler` — while the server actually serves
   `ZeroScriptHandler`, which overrides `do_GET`/`do_POST`. The patch was
   invisible: every `/api2/v4/` route answered `404 unknown route`, so Visual
   Blueprints, Arena and Webhooks never ran.

   The engine is now registered in the server's own route table
   (`zs_server._build_feature_modules()`), so it is served by the handler that
   is actually in use — and, unlike a handler patch, it stays behind the
   normal session + CSRF checks instead of bypassing them.

2. **Dashboard 4.0 buttons failed with `419 - session expired`.** `index.html`
   carried a duplicate inline `<script>` placed *after* `/2/app.js`, so its
   copies of `addNode` / `compileGraph` / `runArena` / `testWebhook`
   overwrote the working ones. Those copies called `fetch()` directly,
   without the per-session `X-CSRF-Token` header, so the server rejected every
   action. The duplicate was removed; `app.js` uses the CSRF-aware `api()`
   helper.

3. **The local AI fixer corrupted already-correct Luau.** `local_fix()` used
   `\bwait\(`, and the dot in `task.wait(` is a word boundary — so correct
   `task.wait(` became the invalid `task.task.wait(` (likewise
   `task.task.spawn(` / `task.task.delay(`), and the damage grew with every
   pass. It now uses a `(?<![\w.])` lookbehind and is idempotent.

4. **The 4.0 engine could be crashed.** `node_to_luau()` indexed
   `node["type"]` / `node["data"]` unguarded, so a malformed graph returned a
   server error; `send_discord_webhook()` had no timeout, so a hanging
   endpoint blocked a server thread forever; `auto_fix_error()` ignored the
   error it was given and returned the untouched script as if it had been
   repaired. All three are hardened.

Also: version bumped to `1.9.3` (bridge + extension manifest kept in sync),
and the README keeps the curated distribution guide while documenting the
update and the source layout.

### Validation

| Check | Result |
|---|---|
| `python -m unittest discover -s tests` | **103 passed** |
| Live server: `POST /api2/v4/node_graph` | was `404 unknown route` → now `200` + generated Luau |
| Live server: `/api2/v4/*` without session / without CSRF | `401` / `419` (auth gate intact) |
| Chromium: "Compile to Luau" button | was empty output → now returns the generated Luau |
| Chromium: Arena "FIGHT!" button | was `Error` → now returns a real reply |
| `local_fix("task.wait(1)")` | was `task.task.wait(1)` → now `task.wait(1)` |
| Blob integrity of all 172 pushed files | 0 missing, 0 SHA/size mismatches |

Runtime state is not published: the SQLite database (account hashes, session
records, chat history), `first-run-owner.txt`, logs and local settings are
excluded by the project's own `.gitignore`.

### Known gap

The binary release archive (`.rar`) is **not** included in this branch — the
release asset for 4.0.1 still has to be uploaded from a machine with
7-Zip/WinRAR, and the source tree omits the three PNG assets
(`assets/banner.png`, `assets/icon.png`, `zeroscript-extension/icon.png`)
because they cannot be published as text.
