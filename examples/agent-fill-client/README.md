# Fill-only Agent API client

Two Python processes for this fork's Agent API. The AI process lists login metadata and creates a one-time fill ticket. The fill process redeems that ticket and, when you give it the unlocked vault key, decrypts the login fields locally.

The server stores Bitwarden ciphertext and cannot decrypt it. The AI token never receives the redeem body.

```text
fill host (trusted)                         AI host
------------------------------------        ---------------------------------
VW_FILL_TOKEN=vwfill_...                    VW_AGENT_TOKEN=vwagent_...
BW_USER_KEY=<bw unlock session>             FILL_AGENT_ID=<UUID from /admin/agents>
python3 fill_agent.py poll --reveal

                                            python3 ai_agent.py items --url https://example.com
                                            python3 ai_agent.py fill --item <item-uuid> --origin https://example.com
```

Start the fill process first. Tickets expire after `AGENT_FILL_TICKET_TTL_SECS` (default 60). `poll` redeems one ticket and prints JSON on stdout.

For this deployment, set `VW_BASE_URL=https://vault.bo0lean.com`. The server must be running with `AGENT_API_ENABLED=true`.

## Setup

Python 3.9 or newer. HTTP is the standard-library client. Install `cryptography` before decrypting (the AI script does not import it):

```bash
python3 -m pip install -r examples/agent-fill-client/requirements.txt
```

Run the scripts from this directory, or pass their paths. Do not commit tokens. The repository ignores `.env`.

Create both credentials on `/admin/agents` (admin token required). Each plaintext secret is shown once. Only a SHA-256 hash is stored.

| Environment variable | Process | Value |
| --- | --- | --- |
| `VW_BASE_URL` | both | Server origin only, such as `https://vault.bo0lean.com`. No `/api` suffix. |
| `VW_AGENT_TOKEN` | AI | `vwagent_` plus 64 hex characters. |
| `FILL_AGENT_ID` | AI | Fill agent UUID. Not the `vwfill_` secret. |
| `VW_FILL_TOKEN` | fill | `vwfill_` plus 64 hex characters. |
| `BW_USER_KEY` | fill | Unlocked user symmetric key. Omit to leave ciphertext undecrypted. |
| `VW_REVEAL_PLAINTEXT` | fill | Set to `1` to print password and TOTP. Same as `--reveal`. |

`ai_agent.py` refuses a `vwfill_` token. `fill_agent.py` refuses a `vwagent_` token.

### Fill agent id

On `/admin/agents`, the **Fill agents** table has an **Id** column. That UUID is `fillAgentId`. The **Prefix** column is only the start of the secret (`vwfill_` and a few hex characters). The full `vwfill_` value is the bearer token for `VW_FILL_TOKEN`, shown once when the fill agent is created.

The id is public. The AI client sends it on create. It does not redeem anything.

## AI process

```bash
export VW_BASE_URL=https://vault.bo0lean.com
export VW_AGENT_TOKEN='vwagent_<64 hex characters>'
export FILL_AGENT_ID='<fill agent UUID>'

python3 ai_agent.py items --url https://example.com --q example
python3 ai_agent.py fill --item <item-uuid> --origin https://example.com
python3 ai_agent.py status --ticket <ticket-uuid>
```

`items` calls `GET /api/agent/items`. `fill` calls `POST /api/agent/fills` with `itemId`, `origin`, and `fillAgentId`. `status` calls `GET /api/agent/fills/<ticket-id>`.

Stdout is the ticket object and nothing else:

```json
{
  "object": "fillTicket",
  "id": "<ticket uuid>",
  "status": "pending",
  "expiresAt": "2026-11-05T00:01:00.000000Z",
  "fillAgentId": "<fill agent uuid>"
}
```

List output is `id`, `name`, `folderId`, plaintext `folderName`, normalized `uris`, `reprompt`, and `username` only when the server has `AGENT_REVEAL_USERNAMES=true`. `name` may be an encrypted label; this script does not decrypt it. If a response contains a field this path must not return (`password`, `login`, `key`, `redeemSecret`, a ciphertext username or folder name, and anything else unknown), the script drops it and writes a warning to stderr.

Password-reprompt items can appear in the list and cannot be filled.

## Fill process

```bash
export VW_BASE_URL=https://vault.bo0lean.com
export VW_FILL_TOKEN='vwfill_<64 hex characters>'
# BW_USER_KEY must already be supplied privately by the trusted operator process.
# It is the decrypted account encryption key, not BW_SESSION.

python3 fill_agent.py pending
python3 fill_agent.py poll --reveal
python3 fill_agent.py redeem --ticket <ticket-uuid> --reveal
```

`pending` calls `GET /api/agent/fill-agent/pending`. The one-time `redeemSecret` is hidden unless you pass `--show-secret`. `poll` waits up to `--wait` seconds (default 90) and redeems one ticket, the soonest expiry, or `--ticket` if you set it. `redeem` redeems immediately. Pass `--secret` only when you already printed it with `--show-secret`; otherwise the script reads the secret from pending and does not print it.

Redeem calls `POST /api/agent/fill-agent/redeem` once. The server deletes the secret on success. A second redeem fails.

Stdout is one JSON object. `received` is the username, password, TOTP, and cipher key exactly as redeem returned them. It is always printed: redeem is single-use, so dropping those fields would discard the ticket. `login.password` and `login.totp` are the decrypted plaintext and stay `null` unless you pass `--reveal` or set `VW_REVEAL_PLAINTEXT=1`. A password that was already plaintext on the server is still present in `received`. Username is copied into `login` when it was plaintext or decryption succeeded. Diagnostics go to stderr. Do not send this JSON to the AI process.

```json
{
  "object": "fillResult",
  "ticketId": "<ticket uuid>",
  "itemId": "<item uuid>",
  "origin": "https://example.com",
  "revealed": true,
  "login": {
    "username": "alice",
    "password": "secret-value",
    "totp": "otpauth://totp/Example"
  },
  "received": {
    "key": "2.<item key wrapped by the user key>",
    "username": "2.<username ciphertext>",
    "password": "2.<password ciphertext>",
    "totp": "2.<totp ciphertext>"
  },
  "decryption": {
    "userKey": "present",
    "itemKey": "unwrapped",
    "username": "decrypted",
    "password": "decrypted",
    "totp": "decrypted"
  }
}
```

`decryption.userKey` is `present` or `missing`. `decryption.itemKey` is `none` (the redeem payload had no cipher key, so fields use the user key), `unwrapped`, `unwrapped-base64` (older clients encrypted the base64 text of the item key), `skipped` (a cipher key was present but `BW_USER_KEY` was not), or `failed`. Field states are `plaintext`, `decrypted`, `ciphertext`, `empty`, `absent`, `invalid`, or `failed`.

`login.totp`, when revealed, is the stored TOTP secret, usually an `otpauth://` URI or a base32 seed. This client does not turn that seed into a 6-digit code.

Exit status is `1` when decryption was attempted and failed. The JSON is still printed, with `error` set and the received fields intact, so a bad key does not destroy the ticket. `login.password` stays `null` until a later local decrypt succeeds.

## Decrypting

`BW_USER_KEY` is the decrypted account encryption key: 64 raw bytes, standard base64, base64url, or hex. It is **not** Bitwarden CLI's `BW_SESSION`, which is a separately generated session key. The MCP setup below authenticates the vault account and unwraps the account key locally; it does not require manually exporting a key. Advanced callers of the legacy fill CLI must supply the actual account key privately to that trusted process.

Those 64 bytes are a 32-byte AES-256 key followed by a 32-byte HMAC-SHA256 key. A 32-byte value is accepted only for legacy type-0 fields.

This client does not derive a key from the master password (no PBKDF2 or Argon2). Do not pass:

- the master password
- the 32-byte stretched master key
- the encrypted account key (`2.iv|ct|mac` stored on the user)
- either agent bearer token
- Bitwarden CLI's `BW_SESSION`

Modern vaults encrypt fields as Bitwarden EncString type 2:

```text
2.<iv b64>|<ciphertext b64>|<mac b64>
```

The MAC is HMAC-SHA256 over the raw IV bytes concatenated with the raw ciphertext bytes. It is checked before AES-256-CBC decryption. Padding is PKCS#7. Type 0 (`0.<iv>|<ciphertext>`) is the older unauthenticated AES-256-CBC form and is still decrypted. RSA EncStrings (types 3–6) and type 1 (AES-128-HMAC) produce an error instead of a guessed plaintext.

When the redeem payload includes `key`, that blob is unwrapped with the user key and the login fields are decrypted with the item key. When `key` is null, the fields are decrypted with the user key directly. The key never leaves this process.

You can call the same function yourself:

```python
import os
from bw_crypto import decrypt_fill, load_user_key

decrypted = decrypt_fill(
    username=payload["login"].get("username"),
    password=payload["login"].get("password"),
    totp=payload["login"].get("totp"),
    cipher_key=payload.get("key"),
    user_key=load_user_key(os.environ["BW_USER_KEY"]),
)
if not decrypted.ok:
    raise SystemExit(decrypted.error)
print(decrypted.password.value)
```

Run that from this directory, or add it to `PYTHONPATH`. `value` is never the original ciphertext.

## URI index

Create fill returns `Origin not allowed` when the item has no published URI index entry for that origin. Vault URIs are normally ciphertext, so the server cannot read them. Saving a cipher indexes plaintext `http` and `https` URIs only. Encrypted URIs are ignored and do not clear an older index.

Publish with the vault user, not with `vwagent_` or `vwfill_`. Nothing here edits the database.

On the web vault, unlock, open the personal login, and use **Agent sites**. That button is served by this fork when the Agent API is enabled. It asks before it sends websites, and it does not read password fields.

From a shell, `publish_uri.py` signs in with the account email and master password (or uses a one-shot user access token) and publishes websites. Passwords are not decrypted and are not printed. Set `VW_MASTER_PASSWORD` only for a non-interactive run. The prompt is the normal path. WebAuthn and Duo are not entered here; use Agent sites for those accounts.

```bash
export VW_BASE_URL=https://vault.bo0lean.com
python3 publish_uri.py publish --email you@example.com --name Example
python3 publish_uri.py publish --email you@example.com --item <cipher-uuid>
python3 publish_uri.py publish --email you@example.com --all

# Websites you already know, with a one-shot user access token:
export VW_USER_TOKEN='<vault user access token>'
python3 publish_uri.py put --item <cipher-uuid> --uri https://example.com/login

# Actual account key supplied privately, plus the same user access token:
python3 publish_uri.py publish --item <cipher-uuid>

python3 publish_uri.py clear --item <cipher-uuid>
```

`--dry-run` prints the websites and does not call uri-index. A password sign-in still contacts the server so it can read the vault. `put --dry-run` and `clear --dry-run` do not.

The direct route, if you already have a user access token, is:

```http
PUT /api/agent/items/<cipher-id>/uri-index
Authorization: Bearer <user access token>
Content-Type: application/json

{"uris":[{"uri":"https://example.com/login","match":1}]}
```

Use the item id from `ai_agent.py items` or from the login's URL in the web vault. The indexed URI can include a path; matching uses the origin (`https://example.com`). Request the fill with that origin. Match `1` (and the default null match) requires the same scheme, host, and port. `example.com` does not allow `login.example.com`. Match `0` allows subdomains of the indexed host. `DELETE /api/agent/items/<cipher-id>/uri-index` clears it.

IP literals are denied unless the server has `AGENT_ALLOW_IP_ORIGINS=true`. The user access token is the normal Bitwarden login token, not `BW_USER_KEY` and not an agent token. `BW_USER_KEY` is only the local decryption key.

## Security

- Keep `vwfill_` and `BW_USER_KEY` off the AI host. The AI script has no pending or redeem call.
- Do not pipe fill stdout or stderr into an AI session, a shared log, or a ticket. `received` is the redeem body even when `--reveal` is off. `--show-secret` prints the one-time redeem secret from `pending`.
- The fill bearer and the redeem secret are single-purpose. Revoke either credential on `/admin/agents` if it is exposed. Revocation takes effect immediately.
- The client sends the bearer token only to `VW_BASE_URL` and refuses redirects, so a 30x response cannot move the token to another host.
- Redeem is not retried. The server clears the secret after one success.
- Type 0 ciphertext has no MAC. Current clients use type 2, which is authenticated.

## Tests

From the repository root:

```bash
python3 examples/agent-fill-client/test_client.py
python3 examples/agent-fill-client/test_publish.py
```

Crypto tests build EncStrings with OpenSSL AES-256-CBC and check HMAC-SHA256 in the test, then decrypt through `bw_crypto.py`. The CLI tests run the scripts against a local stand-in and assert that stdout never contains a password, a redeem secret, or a fill token. `test_publish.py` also checks that `publish_uri.py` sends websites only.

## Codex MCP and private browser login

The optional MCP package logs in through a browser owned by the trusted MCP
server. The AI selects a configured site; it cannot supply a URL, selector,
password or script. The server returns fixed states, not the redeem body, DOM,
screenshots, cookies, browser errors or page text. The original reference CLIs
above retain their existing output contracts and are not used as MCP tools.

The default provider handles username/password forms. The optional native
provider below supports passkeys with private operator confirmation. Neither
provider automates cross-origin SSO or arbitrary actions after login. The approved
website necessarily receives its own password. An unrestricted agent with
access to the trusted process's files or memory can bypass this boundary;
deploy the trusted server on a separate OS account/host when that isolation is
required. Never expose its private browser through another MCP/CDP tool.

For the dedicated-account deployment, restricted SSH entry point and production
acceptance gates, see [production setup](../../docs/agent-mcp-production.md).

### Install

Python 3.11+ is required for the MCP extra. The standalone reference scripts
still support Python 3.9+.

```bash
python3.13 -m venv "$HOME/.local/share/vaultwarden-agent/venv"
"$HOME/.local/share/vaultwarden-agent/venv/bin/pip" install './examples/agent-fill-client[mcp]'
"$HOME/.local/share/vaultwarden-agent/venv/bin/python" -m playwright install chromium
```

Copy `sites.example.json` to your own operator configuration and replace the
item UUID, exact HTTPS login URL, form selectors, post-login path and success
selector. All three form elements must belong to the same visible top-level
POST form, with a same-origin action. A success path alone is insufficient;
choose a selector that exists only after authentication. Cross-origin network
requests, popups, downloads, WebSockets and service workers are blocked.

Publish the item's URI index using **Agent sites** or `publish_uri.py` first.
Create a narrowly scoped AI token and a separate Fill Agent credential in
Admin. In your own terminal, run the non-echoing setup command:

```bash
"$HOME/.local/share/vaultwarden-agent/venv/bin/vaultwarden-agent-setup" --sites /absolute/path/sites.json
```

Setup asks for the server origin, vault account email/master password, both
scoped credentials and the Fill Agent UUID. It reuses the normal prelogin/KDF
authentication flow and unwraps the account encryption key locally. Vault
two-step authentication is handled by the existing login helper; the website's
own MFA is outside the browser integration. Neither the master password nor
normal user access token is saved. Setup writes an operator-owned 0600 file in
the private `~/.config/vaultwarden-agent` directory. It refuses redirected input
and existing destination files. Run setup outside the AI transcript; never send
those values to the model. Passwords and wrapped item keys must use authenticated
type-2 encryption. Configuration, traces and vault data do not belong in Git.
Use `--headless` on a trusted Linux host without a display. For credential
rotation, create a new private config path with `--config`, validate it, and
have the operator switch the deployed path; setup never overwrites a file.

Register the command with Codex without copying secrets into its configuration:

```bash
codex mcp add vaultwarden-agent -- "$HOME/.local/share/vaultwarden-agent/venv/bin/vaultwarden-agent-mcp"
codex mcp get vaultwarden-agent
```

Reload the MCP connection after installation or configuration changes. A missing
or invalid private configuration exposes the tool catalog but returns
`not_configured`. The tools are:

| Tool | Input | Output |
| --- | --- | --- |
| `vault_sites` | none | Approved site identifiers and origins |
| `vault_login` | `site` | Fixed authenticated/needs-approval/failed state and a bounded reason code |
| `vault_status` | `site` | Verified authentication state without page contents |

For multiple stdio/SSH clients, run one broker under the trusted account and
point every client at its private Unix socket:

```bash
vaultwarden-agent-broker --config /private/config.json --socket /private/runtime/broker.sock
vaultwarden-agent-mcp --broker-socket /private/runtime/broker.sock
```

The socket parent must be owned by that account and mode 0700; the socket is
0600. The socket accepts only the same three fixed actions. Clients do not load
the vault configuration, and disconnecting a client leaves the shared browser
alive. Restarting the broker ends its sessions. Keep this socket on the trusted
host, outside the AI host's filesystem access.

Without a shared broker, sessions stay in memory for the MCP process lifetime;
they are not exported or saved to disk. Failed submissions are not retried automatically.
Debug logging is rejected before browser startup. Authentication is reported
only when both the configured origin/path and post-login selector match.

### Native passkey provider

Use `native.example.json` for a single approved passkey site. Replace its expected
account selector and verify the site selectors before activation. The configuration
contains only provider paths and site metadata; the native extension owns vault
authentication, decryption and signing. Enable master-password re-prompt on the
selected login item. This mode uses normal vault-account permissions, not Agent
folder tokens; review the account's accessible vault contents before enrollment.

Run the shared broker under a separate unprivileged account, with a root-owned
pinned Bitwarden extension, full sandboxed Chromium, a private display and an
operator-only confirmation channel. The profile parent must be account-owned
0700. `profile_path` is a private container; each browser start creates a fresh
profile below it, requiring private operator enrollment again after closure.
Use a volatile runtime directory for the profile, browser home, cache and
configuration. Prepare any local TLS trust only in that browser user's NSS
database; never disable certificate verification or change the system trust store.

The operator privately enrolls the correct self-hosted account in the native UI.
Operator-opened pages at the approved site's exact origin also support private
account/passkey enrollment. They do not create an authenticated MCP session;
unapproved destinations and cross-origin credential submissions remain blocked.
`vault_login` then returns `needs_approval` while the operator selects the passkey
and completes native confirmation. `vault_status` checks the post-login path,
visible success element and expected account selector. It also requires the
provider's password-confirmation field to have appeared for this pending request;
it never reads its value. Approval expires after five minutes and closes the
private browser. Do not automate confirmation for a personal credential.

One native site per runtime keeps confirmation bound to the requested site.
There is no arbitrary URL, page, cookie, screenshot or credential-export tool.

### Verify the complete flow

```bash
"$HOME/.local/share/vaultwarden-agent/venv/bin/python" examples/agent-fill-client/test_mcp.py
"$HOME/.local/share/vaultwarden-agent/venv/bin/python" tools/verify-agent-mcp.py --vaultwarden-binary /absolute/path/vaultwarden --report /absolute/path/report.json
```

The second command creates a private, disposable local Vaultwarden instance,
registers a user through the normal API, stores type-2 encrypted demo credentials
with a wrapped item key, publishes the URI index, creates scoped credentials,
and uses the actual MCP stdio transport to log in to the external HTTPS
demonstration at `the-internet.herokuapp.com`. Demo values are read and used
inside the trusted verifier; they are never printed. MCP output and diagnostics
are scanned for credentials and keys. It terminates its browser and local
server. A private temporary directory is retained for operator diagnosis; move
it to your system trash after inspection. This does not validate a personal
website/account or touch production vault data.

Implementation scope and the threat model are in
[`docs/agent-mcp-spec.md`](../../docs/agent-mcp-spec.md).
