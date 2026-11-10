# Agent MCP and trusted browser login

## Complete workflow release gates

The project remains in progress. A successful owned-site login is a milestone,
not acceptance of the whole Agent workflow. The owned RP remains the selected
acceptance target; do not reintroduce personal GitHub as a mandatory test.

Reuse the isolated browser and operator-owned site configuration for named
post-login operations. Add `vault_actions(site)` for safe action/field names,
`vault_action(site, action, values)` for nonsecret form inputs, and
`vault_logout(site)` to close and discard the private session. Operators bind
each operation to an exact same-origin URL, form fields, submit control and
independent success path/marker. The AI supplies neither URLs nor selectors.
No scripts, DOM, page text, screenshots, cookies, credential values or raw
exceptions cross this interface. Existing profiles without operations stay valid.

Actions require an authenticated session and a visible same-origin POST form;
credential fields, password forms, duplicate/hidden targets and cross-origin
submission are rejected before input. Errors return fixed states without input
reflection. Status checks must preserve a task page while verifying the approved
account in the same context. No new browser-control dependency is required.

Complete acceptance requires login, discovery, a useful authenticated form
operation, persisted server-side result, reuse from another MCP connection,
logout and refusal after logout/revocation, plus restart/recovery and privacy
checks. Use an owned-site workspace fixture and clear its nonsecret test data.
Retain the existing account/passkey and production data through deployment.

Native confirmation also needs a usable operator path without VNC or repeated
provider setup. Keep real user presence for personal passkeys/MFA; do not expose
FIDO2 keys, replace them with API tokens or claim synthetic calibration is a
personal login. This gate remains open until a secure replacement is implemented
and exercised. Keep the overall goal active through review, CI, deployment,
current-chat acceptance and all three Notion handoff updates.

## Outcome and scope

Provide an installable stdio MCP server for Codex. The server uses the existing
Agent API and local Bitwarden decryption helpers to log in through its own
Chromium browser. The model chooses an operator-approved site, and receives only
site identifiers, origins and fixed execution states. No server API, database
schema, official-client behavior or existing CLI output contract changes.

The acceptance target is now the owned Oracle test service at
`https://agent-test.bo0lean.com`, replacing external demonstrations and personal
GitHub login. A disposable vault supplies real encrypted test items and scoped
credentials. Verify actual password login and native passkey signatures on the
server; mocked HTTP responses do not satisfy acceptance. Follow the
[owned-site plan](agent-test-site-plan.md) for deployment and current-chat gates.

The earlier personal target was GitHub account
`zqy5608`, entry `Github`, using a passkey stored in **1Password**. Do not assume
this credential already exists in Vaultwarden. Version 0.1.2's username/password
integration does not satisfy this acceptance. 1Password's official Agents
integration currently excludes passkeys. The user approved a native encrypted
copy of only this item into Vaultwarden, retaining the 1Password original.
The operator reports completing that copy privately; it has not been independently
inspected. Preserve the item and its original; do not repeat the import. Use an
independent test credential for the owned site's distinct RP ID.

## Trust boundary

The MCP server and its private browser are trusted. The model-facing tools are
`vault_sites`, `vault_login`, `vault_status`, `vault_actions`, `vault_action` and
`vault_logout`. There is no arbitrary URL,
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
  cookie export. Named post-login form operations retain these boundaries.
  Cross-origin SSO and arbitrary browser control are not exposed. Native
  confirmation remains a separate release gate until its operator path is usable.

## Acceptance checks

1. MCP initialize, tools/list and tools/call work over stdio using the official
   client; register the server through Codex's supported MCP command.
2. Real local Vaultwarden registration, encrypted item creation, URI publishing,
   scoped ticket creation/redemption and owned HTTPS website login succeed.
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
4. Use the operator-approved website and vault entry. Publish its exact URI,
   issue a folder-limited AI credential and independent fill credential, then
   configure the profile through the operator's private terminal.
5. Current Codex tools return the approved site and authenticate the selected
   account. Verify retained status, a denied site and credential revocation.
   Record versions, checks and rollback without copying any secret values.

The accepted password milestone supports same-origin username/password forms
and named authenticated operations. Native passkeys require the operator path
in the [confirmation plan](agent-native-operator-plan.md). Cross-origin SSO
remains unsupported; never disable a site's account protections.

## Native passkey acceptance

Use the owned RP for release acceptance. The previously selected GitHub item
and its 1Password original remain intact; personal GitHub login is not a required
substitute for this test and must not be restarted without a new user request.

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
- Verify a real assertion for the configured RP and expected account identity,
  retained session state, rejection of an unapproved site, and a bounded failure
  when the native provider is locked or the user cancels verification.
- Only declare formal activation after those live checks pass. The earlier
  public-demo test and remote MCP connectivity checks remain separate evidence.

Operational history and previous rollout checkpoints are retained in the three
Notion handoff pages. They are not current acceptance evidence.

## Sources

- [Codex MCP configuration](https://learn.chatgpt.com/docs/extend/mcp?surface=cli)
- [Official MCP Python SDK](https://py.sdk.modelcontextprotocol.io/)
- [Playwright browser isolation and request interception](https://playwright.dev/python/docs/api/class-browsercontext)
- [Public acceptance application](https://github.com/saucelabs/the-internet)
- [GitHub passkey and second-factor authentication](https://docs.github.com/en/authentication/securing-your-account-with-two-factor-authentication-2fa/accessing-github-using-two-factor-authentication)
- [Bitwarden native passkey provider](https://contributing.bitwarden.com/architecture/deep-dives/passkeys/implementations/provider/browser-extension/)
- [Chromium extension support](https://playwright.dev/python/docs/chrome-extensions)
