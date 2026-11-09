# GitHub passkey activation decision

## Confirmed target and current state

- Site: `https://github.com`; account: `zqy5608`; item name: `Github`.
- The user confirmed that the original passkey is stored in **1Password** and
  reports completing the approved one-item copy to the dedicated Vaultwarden
  account. Direct GitHub login acceptance is still required. No password or
  passkey was read into the model context.
- PR #12 merged and its native client 0.1.3 was deployed on Oracle. Fresh
  restricted SSH/MCP sessions return the approved GitHub site and
  `not_authenticated`. Retiring the old password-only processes closed the
  current chat's transport; reload that connection before personal acceptance.
- 1Password's supported-agent interface explicitly excludes passkeys. Its normal
  browser extension supports passkeys, including native operator verification.
  Do not treat API tokens or an existing browser session as passkey acceptance.

## Approved narrow activation path

The user approved copying only `Github / zqy5608` into Vaultwarden, retaining
the 1Password original. Native-provider calibration passed before enrollment;
the operator now reports completing that copy. Do not repeat the import.
The user selected a dedicated account email and an iPhone running iOS 26 or
later. Keep the email in private operations notes; registration and transfer
were private operator actions.

Current calibration: the pinned official extension 2026.10.0 opened successfully
under UID 995 on Oracle with full Chromium and native sandboxing. CI passes
validated loopback TLS, official vault login, real passkey registration and
required-verification assertion, prompt cancellation, matching account and
retained session. The same real broker then passes native login through stdio
MCP, session reuse across independent clients, denied-site and secret-output
checks. Only synthetic credentials and disposable loopback vaults were used.
Renewed operator access confirmed production healthy, both loopback health
endpoints HTTP 200, and the old temporary container no longer running. A new
backup succeeded. Private Unix VNC and loopback TLS prerequisites are staged;
personal credentials have not been enrolled.

The initial native environment failure had a confirmed cause: the official 2026.10.0
extension rejects HTTP self-hosted URLs outside development builds. Do not
remove that validator or disable certificate verification. Calibrate a pinned
Caddy TLS proxy bound only to loopback, trusting its public CA only in the
dedicated Chromium user's NSS database. Keep the CA private key outside that
user's access in production. This leaves the production vault's public endpoint
and application configuration unchanged.

The selected login must require the provider's master-password re-prompt. The
pinned extension's FIDO2 code explicitly invokes that prompt for `reprompt != 0`;
without it, its legacy path can report the requested verification flag without
a new prompt. Test a synthetic credential with re-prompt enabled, including
cancel, before enrolling the personal item. Never set UV flags in this project.

Use the mobile operating system's native Credential Exchange Protocol (CXP) to
copy **only the selected Github item** from 1Password into the user's approved
Vaultwarden account at `https://vault.bo0lean.com`. The 1Password original remains
in place. Do not create a CSV/1PUX export, export a whole vault, disclose a private
key, or register/revoke a GitHub credential as part of this copy.

Before any transfer:

1. Keep the transfer within the approved one-item scope.
2. Confirm a supported device and current 1Password/Bitwarden apps. The vendor
   guides support native CXP on iOS 26+ or Android 14+.
3. The operator privately signs in to the correct self-hosted Bitwarden account
   and confirms the destination. No master password or verification code belongs
   in chat or tool output.
4. In the native transfer UI, select only `Github` for `zqy5608`. If the provider
   cannot transfer that passkey, stop; do not fall back to a plaintext export or
   create a replacement credential without separate approval.

The native Bitwarden provider is implemented, calibrated and deployed in the
isolated browser. Verify the private operator channel before real enrollment.
Keep keys with the native provider; do not load a production private key into
a testing virtual authenticator.

Acceptance still requires a fresh GitHub passkey login through the current
Codex MCP, the correct authenticated account, retained status, denied-site and
cancel/locked-provider checks, and confirmation that no credentials reach the
model-visible protocol or diagnostics. A successful copy alone is not acceptance.

## Native browser implementation and verification plan

Reuse the official Bitwarden browser extension rather than implementing a
WebAuthn authenticator or exposing FIDO2 keys through the Agent API. Pin the
published extension archive and verify its SHA-256 digest. First exercise it
against a disposable local vault and synthetic passkey; no personal credential
is needed for that calibration.

The native provider needs full Chromium with a persistent context. Keep its
profile on a private runtime filesystem on the isolated host; do not export
cookies or retain an unlocked vault across runtime restarts. Native confirmation
windows are operator-only. A private VNC Unix socket, accessed through an
administrator's temporary SSH channel, can provide that UI without opening a
public desktop or adding UI access to the MCP key. Disable clipboard sharing.
Validate this channel before the operator enters any credential.

Version 0.1.4 creates a fresh private browser profile on every browser start,
including recovery after expired or failed approval. The profile container is
volatile; no old directory is reused or manually deleted. Re-enrollment after
closure is intentional. A real native restart check must return to an empty
email login form with no website cookies; the encrypted server item is retained.

The MCP contract remains three tools. A passkey request may return
`needs_approval`; subsequent status calls check the approved success path and
the expected account. Approval expires after a bounded interval. Only the
operator unlocks the provider and confirms a real passkey assertion. Never
automate confirmation with a personal credential. Keep the authenticated session
on the trusted host for later status calls.

The native broker supports one approved site per runtime so its private provider
confirmation is bound to that site's pending request. Authentication requires
the expected post-login path, a visible success element, an account-specific
selector, and observation of the provider's password-confirmation field. It
observes only field presence, never its value. A success marker without that
native confirmation fails closed. Additional native sites require separate
private runtimes until per-request confirmation binding is extended.

The configured passkey button may appear after DOMContentLoaded. Wait within
the existing browser timeout, then recheck its unique match and exact origin
before requesting native approval. Never force a hidden button or skip these checks.

Live inspection found four simultaneous SSH/MCP processes under the broker
account. A native persistent profile cannot be independently opened by each
process. Run one trusted broker behind a private Unix socket and keep the stdio
MCP processes as fixed-action clients, so all three tools observe the same
approval and authenticated session. This socket must not expose browser/CDP
operations or authentication material.

The extension uses normal vault authentication, unlike the folder-scoped Agent
API. The user explicitly approved creating a dedicated Vaultwarden account that
can access only the selected GitHub item. Registration, master password and
verification remain private operator actions. Do not claim that folder-scoped
Agent tokens constrain the extension or enroll the user's broader vault.

Implementation reaches browser/config validation, MCP setup and status handling,
the sample GitHub profile, production launcher/runbook, and focused tests. It
must preserve the existing password tests. Validate native extension launch and
real synthetic WebAuthn registration/assertion, pending/cancel/timeout states,
account mismatch and unapproved origins. Then deploy and verify the private UI,
complete the approved native copy, and accept a fresh GitHub login from this chat.

PR #12's shared broker and native control plane passed all 63 client checks and
final native CI before merge and deployment. Version 0.1.4 adds fresh-profile
recovery after browser closure. Its rollout requires the complete native restart
check as well as those existing gates. The operator reports completing private
registration, the approved one-item copy and provider enrollment. The first real
current-chat GitHub attempt exposed a delayed button-rendering race; version
0.1.5 waits for readiness before applying the existing safety checks. Personal
GitHub acceptance remains required after rollout and private provider re-login.

## Alternative not selected

Design a separate native 1Password/browser path that retains operator approval
and keeps the authenticated browser isolated. Its official Agents interface is
not an available passkey transport. Do not sync the user's entire 1Password
account to Oracle or export authenticated browser cookies to simplify this path.
No such broader account/device enrollment has been authorized.

## Sources

- [1Password for Agents limitations](https://support.1password.com/1password-for-agents/)
- [1Password native passkey use](https://support.1password.com/save-use-passkeys/)
- [1Password mobile credential exchange and retained originals](https://support.1password.com/export/)
- [Bitwarden import from 1Password and native CXP](https://bitwarden.com/help/import-from-1password/)
- [Bitwarden native provider](https://contributing.bitwarden.com/architecture/deep-dives/passkeys/implementations/provider/browser-extension/)
- [Bitwarden browser interaction tests and current MV3 headless limitation](https://github.com/bitwarden/browser-interactions-testing#headless-mode)
- [Pinned extension HTTPS validator](https://github.com/bitwarden/clients/blob/browser-v2026.10.0/libs/angular/src/auth/self-hosted-env-config-dialog/self-hosted-env-config-dialog.component.ts)
- [Pinned extension native password re-prompt](https://github.com/bitwarden/clients/blob/browser-v2026.10.0/apps/browser/src/autofill/popup/fido2/fido2.component.ts)
- [Caddy local HTTPS](https://caddyserver.com/docs/automatic-https#local-https)
- [Chromium Linux certificate trust](https://chromium.googlesource.com/chromium/src/+/main/docs/linux/cert_management.md)
