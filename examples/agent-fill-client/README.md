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
export BW_USER_KEY='<BW_SESSION from bw unlock>'

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

`BW_USER_KEY` is the unlocked user symmetric key: 64 raw bytes, standard base64, base64url, or hex. Bitwarden CLI prints that value as `BW_SESSION` from `bw unlock`. Put it only in the fill process:

```bash
bw unlock
export BW_USER_KEY="$BW_SESSION"
```

Those 64 bytes are a 32-byte AES-256 key followed by a 32-byte HMAC-SHA256 key. A 32-byte value is accepted only for legacy type-0 fields.

This client does not derive a key from the master password (no PBKDF2 or Argon2). Do not pass:

- the master password
- the 32-byte stretched master key
- the encrypted account key (`2.iv|ct|mac` stored on the user)
- either agent bearer token

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

Publish origins with the vault user's own access token. `vwagent_` and `vwfill_` are rejected on this route. This example does not publish the index, and you do not need to edit the database.

```http
PUT /api/agent/items/<cipher-id>/uri-index
Authorization: Bearer <user access token>
Content-Type: application/json

{"uris":[{"uri":"https://example.com/login","match":1}]}
```

Use the item id from `ai_agent.py items`. The indexed URI can include a path; matching uses the origin (`https://example.com`). Request the fill with that origin. Match `1` (and the default null match) requires the same scheme, host, and port. `example.com` does not allow `login.example.com`. Match `0` allows subdomains of the indexed host. `DELETE /api/agent/items/<cipher-id>/uri-index` clears it.

IP literals are denied unless the server has `AGENT_ALLOW_IP_ORIGINS=true`. The user access token is the normal Bitwarden login token, not `BW_USER_KEY` and not an agent token.

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
```

Crypto tests build EncStrings with OpenSSL AES-256-CBC and check HMAC-SHA256 in the test, then decrypt through `bw_crypto.py`. The CLI tests run both scripts against a local stand-in of the Agent API and assert that the AI stdout never contains a password, a redeem secret, or the fill token.
