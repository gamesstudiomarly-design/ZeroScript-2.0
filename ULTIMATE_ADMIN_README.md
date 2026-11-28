# ZeroScript Ultimate Admin Panel

## Open
1. Start ZeroScript normally (`start.bat` or `start_app.bat`).
2. Click **Ultimate Admin** in the left sidebar, or open `http://127.0.0.1:17614/admin` (use the configured app port if changed).
3. The first launch creates `admin_data.json` beside `app.py` with the three default membership tiers.

## Included
- Overview dashboard, local telemetry placeholders, membership distribution and audit feed
- User registry, AI model catalog, membership definitions, plugin and tool listing management
- Local transaction ledger, announcement drafts, support tickets, feature flag and beta cohort records
- Local release metadata/update manager, admin role labels, owner configuration and command shortcuts
- Admin audit history and JSON backup/export
- Loopback admin API with local client/Host/Origin checks

## Important limits
This is a local desktop administration layer added to ZeroScript Free. It is not a production hosted SaaS control plane. The current repository does not provide cloud account authentication, real-time online sessions, live AI usage/token billing, payment checkout/webhook verification, remote notifications, multi-admin authentication/2FA, package upload/execution, cloud feature-flag enforcement, or automatic update delivery. The interface marks these as unavailable and uses zero/local records rather than fabricating live platform data.

Do not store user passwords or raw provider API keys in `admin_data.json`. Payment state must only be changed after server-side verification from a trusted payment provider. Protect the local application folder with your OS account and back up the JSON file regularly.


## ZeroScript AI OS workspace
Open `http://127.0.0.1:17614/ai_os.html` or use the **ZeroScript AI OS** launch item in the main sidebar. The new workspace includes dashboard, local project records, AI chat/tool task briefs, plugin selection, skills, membership display, theme/search/notifications, and terminal preview. Provider-backed generation, actual plugin package installation, payment checkout, and real command execution require secure backend integrations; this UI labels those features as previews and does not claim they are live.
