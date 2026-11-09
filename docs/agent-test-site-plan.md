# Owned Agent authentication test site

## Scope and deployment

Deploy an independent test service on the existing Oracle host at
`https://agent-test.bo0lean.com`. Keep its process, data and credentials separate
from production Vaultwarden. Reuse the existing HTTPS/Tunnel ingress if its live
configuration permits a separate loopback service. Do not expose a new public
Oracle port or mount production vault/TLS private state into the test service.

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
