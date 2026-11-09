# Owned Agent authentication test site

## Current unattended acceptance

Use the existing scoped password broker for the user's requested unattended
workflow. Native passkey confirmation is optional and is not a deployment gate.
Create a separate generated automation identity for the owned RP, leaving the
operator's account and passkey intact. An isolated, loopback-only Vaultwarden
stores only that identity; registration is disabled except for its admin invite.
Enable folder ACLs and keep the broker's three site-bound MCP tools unchanged.

Systemd encrypted credentials hold scoped tokens and the account key at rest;
only the unprivileged broker receives a private, read-only runtime credential.
Headless Chromium fills the owned HTTPS form without exposing secrets to the AI.
TLS, sandboxing, exact origin/account checks and single-use fills remain.

Acceptance requires direct current-chat login, retained state across independent
MCP connections, denied destinations, revocation blocking a fresh login and
rotation restoring it, plus unattended service restart. Remove task-installed
VNC software, forwarding, display units and temporary fixtures after switching.
Keep production vault data and the operator's existing credentials intact.

## Scope and deployment

Deploy an independent test service on the existing Oracle host at
`https://agent-test.bo0lean.com`. Keep its process, data and credentials separate
from production Vaultwarden. Use a dedicated locally managed Cloudflare Tunnel,
provisioned through the existing authenticated CLI, with separate ingress/egress
networks. Do not modify the production Tunnel or expose a new Oracle port. The
test service must not mount production vault/TLS private state or Tunnel credentials.

Use generated or operator-created test credentials only. Keep the existing
GitHub item and 1Password original intact. A passkey registered for GitHub cannot
authenticate to this site's distinct RP ID. The acceptance target is now this
owned site, replacing external demo sites and personal GitHub login.

## Minimum behavior

- Create a test account and sign in with a normal same-origin password form.
- Add a discoverable passkey to the authenticated test account, requiring UV.
- Sign out and sign in with that passkey, verifying the actual assertion on the
  server before issuing an authenticated session.
- Show an account-specific success marker and retain it after reload and across
  independent MCP clients. Reject an unapproved destination.
- Keep passwords, private keys, session cookies, verification values and raw
  browser responses outside model-visible tools, reports and diagnostics.

## Implementation

Reuse Python, Starlette and Uvicorn already used by the client test environment.
Use pinned `webauthn` for WebAuthn generation/verification and SQLite for users,
credential public keys/counters, sessions and short-lived challenges. Do not
implement signature or attestation parsing. The browser uses native WebAuthn
JSON conversion APIs; no frontend framework or client library is required.

Passwords use a random salt and PBKDF2-HMAC-SHA256. Session cookies are Secure,
HttpOnly, SameSite=Strict and host-only. Validate the exact configured Origin on
state-changing requests and in WebAuthn verification. Challenges are bound to a
session, expire and are consumed once atomically. Bound request and stored-test
data sizes. Do not log request bodies or raw verification exceptions.

Allow five minutes consistently for broker approval, browser WebAuthn confirmation
and the server challenge. The former two-minute window expired during real VNC
confirmation. Keep single-use consumption, exact origin/RP binding, required
user verification and rejection at the expiry boundary.

## HTTP contract

| Route | Behavior |
| --- | --- |
| GET /health | Fixed health result, no credentials or session details |
| GET /register; POST /register | Test-only account creation; redirect to /profile |
| GET /login; POST /login | Visible username/password form; redirect to /profile |
| POST /logout | Invalidate session; redirect to /login |
| GET /profile | Authenticated account-specific marker; otherwise redirect |
| POST /registration/options | Authenticated WebAuthn creation options |
| POST /registration/verification | Actual registration validation and public-key storage |
| POST /authentication/options | Discoverable authentication options and bound challenge |
| POST /authentication/verification | Actual signature/UV/origin/RP validation; fixed verified result |

## Browser correction

Private enrollment must work in an operator-opened tab at the approved origin,
without injecting that tab into the broker's MCP session registry. Keep the same
origin and resource restrictions, and require a separate MCP login with native
confirmation afterward. Cover operator navigation, same-origin enrollment POSTs,
denied destinations and absence of a synthetic MCP-authenticated state.

The observed native confirmation window is narrower than Playwright's fixed
1280x720 emulated viewport, clipping controls. Use the native window's viewport
for the native provider only. Verify real native popup bounds and full crypto
flow; retain sandboxing, origin/account binding and the three-tool MCP contract.

## Tasks and acceptance

1. Implement the isolated test service and fixed-data light UI; check layout
   before browser integration. Add focused password/session/origin/challenge
   tests and verify generic errors do not echo credentials.
2. Replace external login targets in the relevant live verifier with this owned
   RP (loopback HTTPS equivalent in CI). Test password autofill and real native
   registration, assertion, UV cancellation, replay/origin rejection and session
   retention. Use synthetic credentials and the pinned official extension.
3. Review and merge passing changes, deploy immutable source with rollback, and
   validate public HTTPS, expected origin, isolation and production health.
4. Configure the approved test destination in the current-chat MCP and complete
   its actual login/status/reuse/denied-site flow without exposing credentials.
   Update the three existing Notion handoffs with observed results and limits.

Do not claim completion from a rendered page, an empty-provider approval prompt,
synthetic unit checks alone or the operator's earlier GitHub copy confirmation.
