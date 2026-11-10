# Trusted MCP production deployment

The client requires no Vaultwarden server upgrade or database migration.
Use the existing server API and deploy the client under a separate unprivileged
account. The AI host receives only an SSH key restricted to the MCP protocol.
Administrators and the trusted process remain outside this isolation guarantee.

## Workflow upgrade acceptance

The overall project remains active. Owned-site password login is an accepted
milestone; the complete release also requires useful post-login operations and
a usable native confirmation path without VNC. See the
[operator plan](agent-native-operator-plan.md) before native activation.

The 0.1.9 client adds `vault_actions`, `vault_action` and `vault_logout` alongside
the original three tools. Site operations are operator metadata; no URL,
selector, DOM or credential is supplied by the model. `sign-out` performs the
configured server logout, then the broker discards its private context even if
server logout cannot be confirmed.

Deploy the owned RP 0.1.2 workspace/schema addition with its normal SQLite backup
and immutable image rollback. Preserve existing users and passkeys. Upgrade the
client wheel and run the private setup script's `configure` action to add the
three owned-site operations to the encrypted config without replacing keys,
scoped credentials, item IDs or accounts. Reconnect the current MCP connection
only after independent SSH/MCP validation exposes exactly the six intended tools.

Actual acceptance is login, list operations, save a nonsecret note, verify it
through the authenticated server check, preserve state across an independent
connection, clear the note, invalidate server/browser sessions, reject a later
operation and log in again. Repeat the restart and revocation/rotation gates.
Require real request/redirect boundary tests and secret-output checks. Do not
claim this milestone finishes the native operator gate or the whole project.

## Default unattended owned-site deployment

The owned test site uses the existing password broker in headless mode. A new,
generated machine identity is separate from the operator's `agent-test` account
and its passkey. No human vault password or personal credential is required.
This unattended password path is the default. Passkey support has a separate
acceptance gate; passing the password path does not complete the whole project.

Keep that machine identity in a separate Vaultwarden bound only to loopback,
with public registration disabled and folder ACLs required. Reuse the verified
production image by digest, without mounting production data or changing its
configuration. Only the TLS proxy joins the additional bridge needed to publish
its port on host loopback; the credential vault stays on the internal network.
Its admin token and broker config are encrypted using
`systemd-creds --with-key=host`; plaintext exists only in trusted process memory
or private runtime credentials under `/run`. This protects the AI boundary,
not against the host administrator. It does not automate personal-site MFA.

Install the following root-owned deployment files. Keep `/etc/vaultwarden-agent`
root-owned 0700, and create `/var/lib/vaultwarden-agent-automation` and
`/var/lib/vaultwarden-agent-automation-tls` as root-owned 0700 directories.

| Source | Destination |
| --- | --- |
| `tools/agent-automation-compose.yml` | `/etc/vaultwarden-agent/automation-compose.yml` |
| `tools/agent-automation-Caddyfile` | `/etc/vaultwarden-agent/automation-Caddyfile` |
| `tools/agent-automation-setup.py` | `/opt/vaultwarden-agent/bin/agent-automation-setup.py` |
| `tools/verify-agent-mcp.py` | `/opt/vaultwarden-agent/bin/verify-agent-mcp.py` (shared API/crypto helpers) |
| `tools/vaultwarden-agent-automation.service` | `/etc/systemd/system/vaultwarden-agent-automation.service` |
| `tools/vaultwarden-agent-password.service` | `/etc/systemd/system/vaultwarden-agent-broker.service` |
| `tools/agent-mcp-ssh.sh` | `/opt/vaultwarden-agent/bin/mcp-ssh` (0755) |

The encrypted config is delivered by `LoadCredentialEncrypted` and copied by
the unprivileged service into its private `/run` directory as mode 0600. This
retains the broker's strict owner/permission checks: systemd credentials may be
root-owned and group-readable even when the service can read them. The vault
unit copies its runtime admin credential to a
root-only `/run/vaultwarden-agent-automation` directory so Docker can bind-mount
it across the service's private credential namespace. Compose stops before that
directory is removed. No credential belongs in arguments, environment variables,
source control, logs, reports or AI-visible output.

After recording a private rollback and verifying the systemd units, run as root:

```bash
systemctl daemon-reload
/opt/vaultwarden-agent/venv/bin/python /opt/vaultwarden-agent/bin/agent-automation-setup.py init
systemctl enable vaultwarden-agent-automation.service vaultwarden-agent-broker.service
```

Initialization invites only the generated account in the private vault, creates
an independent account through the owned website's normal HTTPS registration,
stores a type-2 encrypted login in a dedicated folder, publishes its exact URI
and issues scoped credentials. The generated master password is discarded after
normal authentication and key unwrapping; only the encrypted operational key and
scoped tokens persist. Nonsecret item/folder/token IDs are recorded in
`/etc/vaultwarden-agent/automation-state.json`. A failed initialization requires
inspection and rollback of this isolated test state before retrying.

The existing restricted SSH connection always uses the shared broker socket;
no Codex reload or display connection is needed when switching implementations.
Verify actual current-chat login and account-specific success, retained state
from independent connections, and denial of an unapproved site. Use the same
setup script's `revoke` action to revoke both scoped credentials and restart the
broker, then confirm a fresh MCP login fails. Its `rotate` action seals new
credentials, revokes the previous IDs and restarts the broker; confirm login
recovers. Restart both services and verify unattended login once more.

After the headless flow passes, disable the native display unit, uninstall only
task-installed TigerVNC packages, close its task SSH forwarding and remove the
native runtime units/launchers/extension/proxy. Retire the temporary signing
agent. Move task fixtures, staging and obsolete native configuration to Trash
or one private rollback archive; preserve production data, original accounts
and passkeys, the live restricted MCP identity and its known-hosts file. Do not
prune unrelated Docker volumes or remove headless Chromium dependencies.

## Operator prerequisites

- A selected HTTPS website using a same-origin, visible username/password POST
  form. Keep existing account protections; MFA/passkeys/cross-origin SSO are not
  automated by this version.
- A personal vault login in a dedicated allowed folder, with its exact URI
  published through **Agent sites**. An AI token limited to that folder and a
  separate Fill Agent credential/UUID from Admin.
- Verified SSH host identity and temporary administrator access to the existing
  Oracle host. Do not reuse the administrator SSH identity for Codex's MCP.
- A private operator terminal for vault authentication and configuration. Never
  enter passwords, scoped tokens or vault keys in an AI transcript.

## Install and restrict access

Record the source revision, build a wheel from `examples/agent-fill-client`, and
run the existing backup service before changing host packages. Install the wheel
with the `mcp` extra into `/opt/vaultwarden-agent/venv`, then install Chromium
and its runtime dependencies. Keep code, the venv and browser binaries root-owned
and not writable by the broker. Put browsers in
`/opt/vaultwarden-agent/browsers` using `PLAYWRIGHT_BROWSERS_PATH` during install.

Chromium's native sandbox is enabled. On Ubuntu 24.04, allow user namespaces
for the root-owned browser executable with an AppArmor profile, then load it
with `apparmor_parser -r`. Do not disable the global user-namespace restriction
or pass `--no-sandbox`. For this dedicated install, the profile is:

```text
abi <abi/4.0>,
include <tunables/global>
profile vaultwarden-agent-chromium /opt/vaultwarden-agent/browsers/**/chrome-headless-shell flags=(unconfined) {
  userns,
}
```

Use an unprivileged system account `vaultwarden-agent`, no sudo access, locked
password, shell `/bin/sh`, home `/var/lib/vaultwarden-agent`. The home must be
**root-owned 0755** so the broker cannot replace its SSH authorization directory.
Create `private/` below it owned by the broker, mode **0700**. Put runtime caches
and the private config there, not in the root-owned home itself.

Install `tools/agent-mcp-ssh.sh` as root-owned executable
`/opt/vaultwarden-agent/bin/mcp-ssh`. Create a root-owned `.ssh/` directory mode
0755 in the home, and a root-owned `authorized_keys` mode 0644 containing only
the dedicated MCP public key with these options:

```text
restrict,command="/opt/vaultwarden-agent/bin/mcp-ssh" ssh-ed25519 PUBLIC_KEY
```

The public authorization file must be readable by the account but not writable.
Do not give the account an administrator key, sudo permission or any other
unrestricted SSH identity. No global sshd configuration change is necessary.
The forced command rejects nonempty requested commands and starts Python with
an explicit minimal environment. OpenSSH `restrict` disables forwarding, PTYs
and user rc scripts.

## Configure privately

Prepare an operator-approved sites JSON using `sites.example.json`; include the
actual item UUID and independently verified form/success selectors. In the
operator's own authenticated administrator terminal on the trusted host, run:

```bash
sudo -u vaultwarden-agent /opt/vaultwarden-agent/venv/bin/vaultwarden-agent-setup \
  --headless --sites /path/to/approved-sites.json \
  --config /var/lib/vaultwarden-agent/private/config.json
```

The sites file must be readable by the account. Enter the vault origin, account
email and master password, complete the vault's supported two-step challenge,
then enter the scoped credentials and Fill Agent UUID. Setup authenticates and
unwraps the account encryption key locally. `BW_SESSION` is not that key.
Only scoped credentials and the unwrapped key are stored; the master password
and normal user access token are not saved. Setup refuses existing destinations.
For rotation, create a new private config, validate it, then switch it as the
operator. Stop the MCP session and revoke compromised credentials immediately.

Register `/usr/bin/ssh` as Codex's stdio MCP command, with `-T`, the dedicated
identity, `IdentitiesOnly=yes`, `BatchMode=yes`, strict host-key checking and the
verified known-hosts file, followed by the broker user/host. Do not add a remote
shell command. No vault credentials belong in Codex's arguments/environment.
Reload the connection only after the independent SSH/MCP check succeeds.

## Required live acceptance

1. Confirm code, launcher, home and SSH files are not broker-writable; private
   config is owned by the broker and mode 0600. Confirm the account has no sudo
   access and cannot read the production vault directory.
2. The restricted key must reject a shell command and SFTP, deny PTY and TCP
   forwarding, and still allow MCP initialization, tool listing and calls.
3. In the current Codex conversation, list the approved site, log in and check
   retained authenticated state. Confirm a non-approved site is rejected.
4. Revoke the scoped credential and confirm a fresh login fails. Restore access
   only through a newly issued credential and private operator configuration.
5. Inspect diagnostics/audit for the expected fixed states without copying raw
   secrets or page contents into the model. Record versions and sanitized results.

Rollback: restore Codex's previous MCP command, close the remote session and
disable the dedicated SSH authorization as the operator. Vaultwarden's running
service, data, backup and SMTP configuration are independent of this client.

## Native passkey deployment — pending

VNC has been retired on the operator's Mac and the Oracle host. Do not reinstall
it or follow historical remote-desktop enrollment instructions. The previous
runtime is retained only in a private rollback archive; it is not active.

The selected RP is `https://agent-test.bo0lean.com`. Preserve its existing
`agent-test` account, enrolled passkey and dedicated Vaultwarden account. Preserve
the earlier GitHub item and the 1Password original without repeating their copy.

Follow the [native confirmation plan](agent-native-operator-plan.md). The intended
replacement uses one private masked Mac confirmation per new native login and
automates provider setup in the isolated browser. It must keep the official
provider, master-password re-prompt, real WebAuthn assertion and expected-account
checks. No MCP approval tool, stored human master password, VNC, cookie export or
public debugging interface is permitted.

Do not activate or claim this path until the actual provider, cancel/expiry/replay
cases, privacy scan and current-chat owned-site login pass. Install only formal
native dependencies and retain the browser sandbox, normal TLS validation,
loopback-only vault proxy and existing production data. Deployment commands and
rollback instructions will be added with the tested implementation.

## References

- [OpenSSH authorized_keys restrictions](https://man.openbsd.org/sshd#AUTHORIZED_KEYS_FILE_FORMAT)
- [Ubuntu user namespace restrictions](https://documentation.ubuntu.com/release-notes/24.04/#unprivileged-user-namespace-restrictions)
- [Bitwarden CLI session-key generation](https://github.com/bitwarden/clients/blob/main/apps/cli/src/key-management/commands/unlock.command.ts)
- [MCP contract and acceptance](agent-mcp-spec.md)
- [systemd shared private temporary namespace](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html#JoinsNamespaceOf=)
