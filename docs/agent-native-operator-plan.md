# Native confirmation without a remote desktop

The complete-workflow goal remains active. Keep the accepted password backend
and add a usable native path; do not reinstall VNC or turn personal user
verification into unattended signing. The owned RP remains the acceptance target.

## Operator experience

A passkey login requests one private confirmation on the operator's Mac. The
native dialog names the configured HTTPS origin and accepts the dedicated vault
master password through a masked OS control. A trusted local helper captures it
privately and forwards it only to the isolated operator endpoint. It never writes
the value to a file, command argument, environment variable, log or MCP stream.
Cancel and expiry terminate the request. No password is collected through chat.

The isolated worker automates the official extension's nonsecret environment,
server and email setup. It forwards the operator's freshly supplied password to
the provider's normal login/unlock and required re-prompt for this one request,
then discards its reference. Do not retain the master password across requests
or substitute a stored password for fresh human confirmation. An existing valid
website session continues without another confirmation.

## Boundaries and reuse

- Reuse the pinned official Bitwarden extension, existing normal vault login,
  passkey implementation and account-bound native checks. Do not implement a
  WebAuthn authenticator, export private FIDO2 keys or use API tokens as evidence
  of website sign-in.
- Replace the native display's VNC server with private Xvfb only if the provider
  needs a display. No viewer, desktop streaming, public listener or browser
  debugging interface is exposed to the AI.
- Keep operator approval on a separate bounded SSH/Unix protocol with a
  dedicated restricted identity. The six model-facing tools cannot retrieve
  credentials or submit operator approvals. Each approval binds a fresh request
  identifier, exact site and expiry, and is consumed once.
- A local stdio connection helper relays ordinary MCP unchanged and handles
  private native confirmation outside that stream. It has no general shell,
  forwarding or file-transfer capability on Oracle. Native cancellation and
  protocol errors yield fixed states, never raw exceptions or secret inputs.
- Keep password and native sessions separate while exposing their approved
  names through one MCP connection. Reuse the existing broker implementation
  for each provider. Existing password profiles remain compatible.
- Native network access must be limited to the configured vault, website and
  approved static resource origins, including redirect hops. Provider metadata
  contains no vault credentials.

## Implementation status

Client 0.1.10 implements the private operator socket, separate forced SSH bridge,
Mac stdio connection helper and masked native dialog. The password broker can
compose one native provider under a distinct site name. Provider setup is
automatic after fresh operator input; no human master password is persisted.
The existing display unit now runs Xvfb with a private X authorization cookie,
without any VNC listener or viewer. Native connections have an exact-origin proxy
allowlist in addition to routing checks.

Unit checks cover leases, cancellation, stale requests, expiry, mixed-provider
routing and the private dialog pipe. The real-provider CI verifier also exercises
fresh setup, cancellation, wrong input, replay and an authenticated workspace
operation. Their implementation does not imply those release gates have passed.
Keep deployment and the overall goal pending until observed results are recorded.

## Release gates

Exercise the actual official extension with generated credentials and real
WebAuthn verification, including first setup, fresh restart, cancellation,
incorrect confirmation, expiry, replay and account mismatch. Scan both MCP and
operator diagnostics with unique secret sentinels. Then complete the operator's
owned-site confirmation privately and run useful same-session actions/logout
from the current Codex chat. Retain original accounts/passkeys and all data
through migration. The overall goal is not complete while any of these gates,
deployment, cleanup or handoff updates are outstanding.
