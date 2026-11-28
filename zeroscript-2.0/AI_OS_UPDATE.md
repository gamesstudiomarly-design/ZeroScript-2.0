# ZeroScript 2.0 — AI OS UI update

The `app_ui2` folder now contains the updated dashboard and companion pages:

- `index.html`, `styles.css`, `app.js`: modern ZeroScript dashboard
- `ai_os.html`, `ai_os.css`, `ai_os.js`: AI OS workspace, tools, projects, membership and plugin marketplace UI
- `admin.html`, `admin.css`, `admin.js`: admin interface assets

The ZeroScript handler in `zs_server.py` serves these pages under the `/2` route
(`app2.py` is the launcher that starts it):

- `http://127.0.0.1:17614/2/`
- `http://127.0.0.1:17614/2/ai_os.html`
- `http://127.0.0.1:17614/2/admin.html`

Membership amounts ($0, $9.99/month, $19.99/month) are illustrative UI prices. They do not create or verify subscriptions. AI generation, provider access, payments, plugin installation from remote sources, and real terminal execution require configured backend services and appropriate permissions.
