# Agent MCP and trusted browser login

## Outcome and scope

Provide an installable stdio MCP server for Codex. The server uses the existing
Agent API and local Bitwarden decryption helpers to log in through its own
Chromium browser. The model chooses an operator-approved site, and receives only
site identifiers, origins and fixed execution states. No server API, database
schema, official-client behavior or existing CLI output contract changes.

The first acceptance target is the public The Internet login demonstration. The
user has deferred selecting a personal website/account. A disposable local
Vaultwarden instance supplies real encrypted vault items and scoped credentials;
the login itself must reach the external HTTPS website and verify its logged-in
state. A mocked HTTP response is not sufficient for this acceptance check.

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

## Sources

- [Codex MCP configuration](https://learn.chatgpt.com/docs/extend/mcp?surface=cli)
- [Official MCP Python SDK](https://py.sdk.modelcontextprotocol.io/)
- [Playwright browser isolation and request interception](https://playwright.dev/python/docs/api/class-browsercontext)
- [Public acceptance application](https://github.com/saucelabs/the-internet)
