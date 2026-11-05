# Fill-only Agent API

This is a fork-specific API. It is not Bitwarden's official agent, Secrets Manager, or fill-assist product, and it does not change official client routes.

The API is off unless `AGENT_API_ENABLED=true`. While it is off, `/api/agent/*` responds with `Agent API is disabled`.

Vaultwarden stores client-encrypted cipher fields. This server cannot decrypt them. The fill agent receives the stored login fields (usually ciphertext) plus the cipher key blob and decrypts them locally. The AI token never receives that payload.

## Credentials

Create and revoke both credentials from the admin page at `/admin/agents` (requires the normal admin token). The plaintext credential is shown once. Only its SHA-256 hash is stored.

| Credential | Prefix | Can call |
| --- | --- | --- |
| AI agent token | `vwagent_` | Metadata and ticket create/status |
| Fill agent | `vwfill_` | Pending tickets and redeem |

These bearers are rejected by the normal user, organization, and send authenticators. They are not Bitwarden login JWTs and cannot call `/api/sync` or cipher detail routes.

Revoke from the admin page. Revoked credentials stop working immediately. Deleting the user deletes their agent credentials, tickets, and audit rows.

## What the AI can see

`GET /api/agent/items?url=&q=`

Returns login items the token is allowed to see:

- id, name, folder id, plaintext folder name, normalized origins, reprompt flag
- plaintext username only when `AGENT_REVEAL_USERNAMES=true`

It does not return passwords, TOTP, cipher keys, notes, custom fields, cards, identities, SSH keys, attachments, or password history. Encrypted username ciphertext is never returned. Query strings and URL userinfo are stripped before a URI is indexed.

Only personal login items are visible. Organization items are not part of this API.

When `AGENT_REQUIRE_FOLDER_ACL=false` (the default), a token created with no folder allowlist can see that user's eligible personal login items. Set it to `true` to require at least one folder when the token is created; an empty allowlist then sees nothing. A token that has a folder allowlist only sees logins in those folders, whether or not the setting is on.

On `/admin/agents`, enter the user email and the page loads that user's folders. Check the folders to store their ids with the token. Plaintext folder names are shown as labels. Encrypted names are labeled so they can be selected without typing ids. Fill agents do not use a folder allowlist.

## URI index

Matching uses a server-side URI index, because vault URIs are normally encrypted and cannot be read here.

### When a save already contains plaintext websites

Saving a personal login indexes plaintext `http` and `https` URIs from the cipher data. Query strings and URL userinfo are stripped. Official Bitwarden clients encrypt URIs before they are saved, so this path indexes nothing for those items. An encrypted save does not delete a URI index that was already published.

### From the unlocked web vault

When the Agent API is enabled, the web vault page loads `/vw_static/vw-agent-uri.js` and shows **Agent sites**. Unlock the vault, open a personal login, and use the button. It reads the user access token already stored in that tab and sends only the websites you confirm. It does not read password fields, and an AI token cannot call it.

The script is added to the web vault shell by this server. It is not a fork of the official web vault. If a future web vault moves the access token out of the tab, the button says the vault is locked and `publish_uri.py` still works.

### From the command line

`examples/agent-fill-client/publish_uri.py` is the path that does not need the web vault button.

Sign in as the vault user. The master password is used to derive the account key and is not sent as itself. Websites are decrypted in that process. Passwords are not decrypted and are not printed. Authenticator, email, and YubiKey codes work. WebAuthn and Duo stay on the web vault button.

```bash
export VW_BASE_URL=https://vault.example.com
python3 examples/agent-fill-client/publish_uri.py publish --email you@example.com --name Example
python3 examples/agent-fill-client/publish_uri.py publish --email you@example.com --all
```

A one-shot user access token can publish websites you already know. `vwagent_` and `vwfill_` are rejected.

```bash
export VW_USER_TOKEN='<vault user access token>'
python3 examples/agent-fill-client/publish_uri.py put --item <cipher-id> --uri https://example.com/login
```

`VW_USER_TOKEN` plus `BW_USER_KEY` (the unlocked key from `bw unlock`) publishes decrypted websites without asking for the master password again.

### Direct request

The vault user (normal login, not the AI token) can also call the route directly:

```http
PUT /api/agent/items/<cipher-id>/uri-index
Authorization: Bearer <user access token>

{"uris":[{"uri":"https://example.com/login","match":1}]}
```

`DELETE` on that path clears the index.

Default match (null) is strict host, scheme, and port. `example.com` does not allow `login.example.com`. Match type `0` allows subdomains of the item host, not the parent and not a different registrable name. IP literals are denied unless `AGENT_ALLOW_IP_ORIGINS=true`. Regex match (type `4`) is denied unless `AGENT_ALLOW_REGEX_URI_MATCH=true`, and patterns containing `.*` or `.+` are still rejected.

### Which path to use

- Plaintext cipher data is indexed on save. Encrypted clients never take this path, so it is not enough on its own.
- **Agent sites** is the one-click path on this server. It needs the official web vault to keep the user access token in the unlocked tab. It does not require copying a bearer token out of DevTools.
- `publish_uri.py` works against the current API, including before the button is deployed. Password login avoids hunting for a token. WebAuthn and Duo are not entered by the script.
- A cipher-save field for already-decrypted origins would not run for official clients unless the web vault were forked. This server does not add that field.
- The AI token stays unable to publish or decrypt. `uri-index` remains limited to the owning user. Operators do not insert rows into the database.

## Fill ticket

```http
POST /api/agent/fills
Authorization: Bearer vwagent_...

{"itemId":"<cipher uuid>","origin":"https://example.com","fillAgentId":"<fill agent uuid>"}
```

The response is status, ticket id, expiry, and fill agent id. It does not include a redeem secret or any login field.

The fill agent polls `GET /api/agent/fill-agent/pending` and receives the redeem secret, then:

```http
POST /api/agent/fill-agent/redeem
Authorization: Bearer vwfill_...

{"ticketId":"<id>","secret":"<redeem secret>"}
```

That response contains `login.username`, `login.password`, optional `login.totp`, and the cipher `key`. It is single-use. A second redeem fails, and the secret is cleared. Tickets expire after `AGENT_FILL_TICKET_TTL_SECS` (10–300, default 60).

Password reprompt items can be listed but cannot be filled.

## Audit

Match, ticket create, redeem, deny, and URI-index updates are written to `agent_audit_log`. The admin page shows the latest rows. Details are fixed reason codes. Raw queries and secrets are not stored.

## Environment

| Variable | Default |
| --- | --- |
| `AGENT_API_ENABLED` | `false` |
| `AGENT_REQUIRE_FOLDER_ACL` | `false` |
| `AGENT_REVEAL_USERNAMES` | `false` |
| `AGENT_ALLOW_IP_ORIGINS` | `false` |
| `AGENT_ALLOW_REGEX_URI_MATCH` | `false` |
| `AGENT_FILL_INCLUDE_TOTP` | `true` |
| `AGENT_FILL_TICKET_TTL_SECS` | `60` |

The same settings appear in the admin config page and `.env.template`.

## Reference client

A Python client for this flow is in [`examples/agent-fill-client`](../examples/agent-fill-client/README.md). Run `ai_agent.py` with the `vwagent_` token and `fill_agent.py` with the `vwfill_` token in a separate process. The fill script redeems one ticket and, when `BW_USER_KEY` is set to the unlocked user symmetric key, decrypts login fields locally. The AI process never receives the fill token or the redeem body.

`fillAgentId` is the UUID in the Id column on `/admin/agents`, not the `vwfill_` secret. Create fill returns `Origin not allowed` until a URI index is published with `PUT /api/agent/items/<id>/uri-index` using the vault user's access token. The example does not publish that index.
