# Agent MCP and trusted browser login

## Outcome and scope

Provide an installable stdio MCP server for Codex. The server uses the existing
Agent API and local Bitwarden decryption helpers to log in through its own
Chromium browser. The model chooses an operator-approved site, and receives only
site identifiers, origins and fixed execution states. No server API, database
schema, official-client behavior or existing CLI output contract changes.

The initial acceptance target was the public The Internet login demonstration. A disposable local
Vaultwarden instance supplies real encrypted vault items and scoped credentials;
the login itself must reach the external HTTPS website and verify its logged-in
state. A mocked HTTP response is not sufficient for this acceptance check.

The user has now selected the personal production target: GitHub account
`zqy5608`, entry `Github`, using a passkey stored in **1Password**. Do not assume
this credential already exists in Vaultwarden. Version 0.1.2's username/password
integration does not satisfy this acceptance. 1Password's official Agents
integration currently excludes passkeys. The user approved a native encrypted
copy of only this item into Vaultwarden, retaining the 1Password original.
The copy has not been performed; native-provider calibration comes first.

## Trust boundary

The MCP server and its private browser are trusted. The model-facing tools are
`vault_sites`, `vault_login` and `vault_status`. There is no arbitrary URL,
selector, script, screenshot, DOM, cookie, credential or browser-debugging tool.
Site profiles bind a cipher UUID to an exact HTTPS origin, login URL, form
selectors and independent post-login selector/path. Only an operator edits these
profiles. Secrets are supplied through a non-echoing setup command, never tool
arguments or Codex configuration values.

The guarantee covers MCP requests/responses, captured diagnostics and browser
artifacts produced by this integration. It does not protect against a host
administrator or an agent with arbitrary access to the trusted process's files,
memory or browser. Strong hostile-agent isolation requires running the trusted
server under a separate OS account/host inaccessible to that agent. Two Python
processes under the same unrestricted account are not a security boundary.

The approved website necessarily receives its own login credentials. Profiles
are a trust decision, not a promise that arbitrary websites are safe.

## Implementation decisions

- Package the existing Python client directory; reuse its HTTP, ticket and
  authenticated EncString decryption code. Add the official MCP SDK and
  Playwright only to an optional `mcp` installation extra.
- Keep credentials in an operator-owned, non-symlink configuration file with
  mode 0600 inside a private directory. Do not put secrets in the repository or
  Codex's MCP command/environment configuration.
- Use isolated in-memory browser contexts. Do not enable tracing, HAR, video,
  screenshots, console forwarding, downloads, service workers or a debug port.
- Validate a visible top-level POST form and same-origin action before requesting
  a ticket. Bind the redeemed item, origin and ticket to the requested profile.
  Require authenticated type-2 encryption for passwords and wrapped item keys.
- Recheck the form and origin in the same browser operation that enters the
  credentials. Block unapproved network origins, popups and WebSockets. Clear
  password inputs on failure. Never return page text, URLs with query strings,
  raw API errors, Playwright exception messages or the redeem body.
- Treat ticket redemption and verified authentication as separate states. Report
  authentication only after the approved post-login path and selector match.
  Failed/ambiguous submissions are not automatically retried.
- Keep the authenticated browser in memory for the MCP lifetime. No session or
  cookie export. MFA/passkeys/SSO and arbitrary post-login browser control are
  outside this initial username/password flow.

## Acceptance checks

1. MCP initialize, tools/list and tools/call work over stdio using the official
   client; register the server through Codex's supported MCP command.
2. Real local Vaultwarden registration, encrypted item creation, URI publishing,
   scoped ticket creation/redemption and real external website login succeed.
3. Authenticated status requires both the configured path and selector; a second
   status check verifies the retained session. Unconfigured sites fail closed.
4. Cross-origin redirects/form actions, GET forms, hidden/password-lookalike
   fields, wrong credentials, tampered ciphertext, missing configuration,
   concurrent calls and reflected-secret exceptions are checked.
5. Unique secret sentinels never occur in MCP result/error content or captured
   stdout/stderr. Tests do not print real demo credentials or vault keys.
6. Existing reference-client and URI-publishing tests continue to pass. Close
   test browsers/servers and retain only non-secret verification summaries.

## Production rollout acceptance

The production setup must obtain the account encryption key by authenticating
the vault user and unwrapping the encrypted account key locally, using the
existing prelogin/KDF/login helpers. Bitwarden CLI `BW_SESSION` is a separately
generated session key; it is not an account encryption key. The operator enters
the master password only in their own non-echoing terminal. Neither that password
nor a normal user access token is persisted in the MCP configuration.

Deploy the trusted process and private browser under a dedicated, unprivileged
account on the existing Oracle host. The Codex SSH key must have a forced MCP
command and forwarding/PTY/user-rc restrictions; it must not grant a remote shell,
file transfer, or access to an administrator's SSH key. Keep application code and
SSH authorization root-owned, and the runtime config private to the broker.
Do not alter the running Vaultwarden service, its data, or backup configuration.

Production is complete only after all of these checks pass:

1. Setup obtains a real account key through the normal authentication flow;
   master password, login token and account key do not appear in diagnostics.
2. Existing client checks and new onboarding checks pass. The external HTTPS
   verifier uses the new account-unlock path, not an injected generated key.
3. The deployed limited SSH identity can initialize/call MCP, but cannot obtain
   a shell, transfer files, forward ports or read the private configuration.
4. The user selects a personal website and vault entry. Publish its exact URI,
   issue a folder-limited AI credential and independent fill credential, then
   configure the profile through the operator's private terminal.
5. Current Codex tools return the approved site and authenticate the selected
   account. Verify retained status, a denied site and credential revocation.
   Record versions, checks and rollback without copying any secret values.

The first release still supports username/password forms only. A production
target requiring MFA, passkeys or cross-origin SSO needs a separate explicit
design; do not silently disable that site's account protections.

## GitHub passkey acceptance

- Preserve the selected passkey authentication method. Use the existing native
  provider, retaining its user-presence/verification ceremony. Do not export the
  production private key or import it into a testing virtual authenticator.
- Keep authentication material, verification codes, page contents and cookies
  outside the model context. MCP receives only approved site metadata and fixed
  action states. Operator authentication happens through a private human channel.
- The existing Agent API deliberately excludes FIDO2 credentials. Do not expose
  them through AI metadata tools or silently broaden the fill API. If a native
  browser extension is used, document its vault permissions, profile lifetime and
  operator verification path before configuring real credentials.
- Keep the trusted runtime isolated from the AI host. A logged-in local browser
  or existing GitHub CLI token is not evidence of a new isolated MCP login.
- Verify a real assertion for `github.com`, the authenticated `zqy5608` identity,
  retained session state, rejection of an unapproved site, and a bounded failure
  when the native provider is locked or the user cancels verification.
- Only declare formal activation after those live checks pass. The earlier
  public-demo test and remote MCP connectivity checks remain separate evidence.

After restarting Codex, all three tools were called directly over restricted
Oracle SSH and returned `not_configured`. A later native-calibration SSH
interruption closed the original current-chat transport. A fresh independent
restricted MCP session still initializes and returns `not_configured`; this does
not re-establish the original chat connection or prove a personal login.

Draft PR #12 adds shared broker state and a native provider control plane; all 61
local checks pass. It remains unmerged and undeployed. The source provider is
1Password; the one-item native copy is approved but not performed. The user also
approved a dedicated Vaultwarden account containing only that item. Native UI
launch passed on Oracle/Xvfb. CI passes loopback TLS, vault login, native passkey
registration and prompt cancellation; assertion verification is still blocked.
Renewed operator access confirmed production healthy, both loopback health
endpoints HTTP 200 and the old disposable container no longer running. Private
operator enrollment and real GitHub login remain unfinished.

## Sources

- [Codex MCP configuration](https://learn.chatgpt.com/docs/extend/mcp?surface=cli)
- [Official MCP Python SDK](https://py.sdk.modelcontextprotocol.io/)
- [Playwright browser isolation and request interception](https://playwright.dev/python/docs/api/class-browsercontext)
- [Public acceptance application](https://github.com/saucelabs/the-internet)
- [GitHub passkey and second-factor authentication](https://docs.github.com/en/authentication/securing-your-account-with-two-factor-authentication-2fa/accessing-github-using-two-factor-authentication)
- [Bitwarden native passkey provider](https://contributing.bitwarden.com/architecture/deep-dives/passkeys/implementations/provider/browser-extension/)
- [Chromium extension support](https://playwright.dev/python/docs/chrome-extensions)
