# GazeTouch Cloud (opt-in encrypted syncing)

Architecture: GitHub Pages frontend -> Cloudflare Worker -> D1. The browser encrypts data with AES-256-GCM, key derived from a **strong passphrase** using PBKDF2/SHA-256 (310,000 iterations). Worker only receives base64 ciphertext, a SHA-256 hash of a random access token, and update metadata. TLS protects transport. **This is a personal experimental backup, not a formally audited security solution.**

## Setup in Cloudflare

1. In Cloudflare dashboard -> Workers & Pages -> D1 -> Create database `gazetouch-sync`.
2. Create database table by running `schema.sql` in D1 Console (paste its SQL).
3. In Cloudflare Workers & Pages -> Create Worker named `gazetouch-sync`, paste contents of `worker.js` into its editor and deploy.
4. Worker Settings -> Bindings -> Add D1 binding, name `DB`, select `gazetouch-sync`.
5. Worker Settings -> Variables -> Add `ALLOWED_ORIGIN` (text) with exact value `https://haibao753.github.io`.
6. Check `https://YOUR-WORKER.workers.dev/health` responds with `{"ok":true,"version":1}`.
7. Open the game -> cloud sync settings, enter Worker HTTPS URL. Choose **Create cloud vault**; save the generated 43-character recovery token and encryption passphrase **outside GitHub**, preferably in a password manager. The token is like a password.
8. Future devices: enter same Worker URL, recovery token, passphrase and tap **Connect and restore**.

For CLI users: `npx wrangler d1 create gazetouch-sync`; fill in database ID in wrangler.toml; `npx wrangler d1 execute gazetouch-sync --remote --file=cloud/schema.sql`; `npx wrangler deploy --config cloud/wrangler.toml`.

**Caveats:** Worker token is a bearer credential; do not paste it into screenshots or public issues. Anyone holding the token can read, replace or delete the ciphertext, although they still need your passphrase to decrypt. Worker does not authenticate a legal identity. Origin checks are not an authentication mechanism. There is no server-side account recovery. The encrypted data has some traffic/size metadata; D1 is not fully zero-knowledge metadata-wise. Cloud sync is opt-in, uses localStorage for token/URL, session-only passphrase, and never ships raw camera frames. Sync is automatic only while the page is open and unlocked; offline queue stays local. Clearing browser data without having saved your token and passphrase will permanently prevent recovery. Worker is not yet configured in a Cloudflare account just by merging these files.
