# Trusted MCP production deployment

The client requires no Vaultwarden server upgrade or database migration.
Use the existing server API and deploy the client under a separate unprivileged
account. The AI host receives only an SSH key restricted to the MCP protocol.
Administrators and the trusted process remain outside this isolation guarantee.

## Default unattended owned-site deployment

The owned test site uses the existing password broker in headless mode. A new,
generated machine identity is separate from the operator's `agent-test` account
and its passkey. No human vault password or personal credential is required.
The native passkey workflow below remains optional; it is not the default and
must not hold up unattended acceptance.

Keep that machine identity in a separate Vaultwarden bound only to loopback,
with public registration disabled and folder ACLs required. Reuse the verified
production image by digest, without mounting production data or changing its
configuration. Its admin token and broker config are encrypted using
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

## Native passkey deployment

Current acceptance uses the independent Oracle RP at
`https://agent-test.bo0lean.com`; see the [owned-site plan](agent-test-site-plan.md)
and [service deployment](../examples/agent-test-site/README.md). Retarget only the
operator-approved site metadata with a private rollback copy. Create a separate
test credential for this RP; preserve the previous GitHub credential. The notes
below describe the original GitHub enrollment and the shared runtime setup.

The native provider uses a dedicated vault account containing only the approved
GitHub item. The user approved creating that account and copying the single
1Password item through native credential exchange, retaining the original.
Do not use the operator's broader vault account. Follow the separate
[activation gates](github-passkey-activation.md) before private enrollment.

Install full Chromium, the pinned extension, `tigervnc-standalone-server`,
`xauth` and `libnss3-tools`. Keep the extension root-owned under the path in
`native.example.json`; verify the archive digest recorded in the native verifier.
Add the same browser-specific AppArmor rule for `**/chrome`, preserving the
global user-namespace restriction and Chromium's native sandbox.

Install the repository's native deployment files as root:

| Source | Destination |
| --- | --- |
| `tools/agent-native-display.sh` | `/opt/vaultwarden-agent/bin/native-display` (0755) |
| `tools/agent-native-broker.sh` | `/opt/vaultwarden-agent/bin/native-broker` (0755) |
| `tools/vaultwarden-agent-display.service` | `/etc/systemd/system/vaultwarden-agent-display.service` |
| `tools/vaultwarden-agent-broker.service` | `/etc/systemd/system/vaultwarden-agent-broker.service` |
| `tools/agent-native-Caddyfile` | `/etc/vaultwarden-agent/Caddyfile` |
| `tools/agent-native-compose.yml` | `/etc/vaultwarden-agent/compose.yml` |

Create `/var/lib/vaultwarden-agent-tls` root-owned 0700. The separate pinned Caddy
container binds HTTPS only to loopback and proxies the existing vault at port
8080. It does not mount the production vault volume. Start it with the separate
compose file, then export **only** `/data/caddy/pki/authorities/local/root.crt`
using `docker exec ... cat` into `/etc/vaultwarden-agent/native-ca.crt` (0644).
Never export its private key or use `docker cp` for tmpfs data. Verify `/alive`
with that CA using normal TLS validation. No system trust-store change is needed.

Copy the approved native profile metadata to
`/var/lib/vaultwarden-agent/private/native.json`, owned by the broker and 0600.
Replace the expected GitHub username and independently confirm its selectors.
The native config contains no credentials. The forced SSH launcher always uses
the shared broker socket; a missing broker fails closed. Switching providers
changes the broker service, without weakening SSH restrictions.

Run `systemd-analyze verify` on the installed units, reload systemd, and start
`vaultwarden-agent-broker.service`. Its private display shares a temporary X
namespace with the browser. The VNC socket directory is broker-owned, operator
group `ubuntu`, mode 0710; the socket is 0660. The X authorization file remains
0600. VNC TCP listeners and clipboard sharing are disabled. `SecurityTypes=None`
is used only inside that permission-protected Unix socket and verified operator
SSH forwarding; never expose it on TCP. The restricted MCP key cannot forward it.

Before enrollment, verify the actual VNC handshake, socket permissions, absence
of VNC TCP listeners, native sandboxing, and the broker's inability to read the
TLS private state or production vault directory. Only then connect the human's
viewer through a temporary administrator SSH tunnel. The operator privately
selects the self-hosted environment `https://localhost:18443`, signs in to the
dedicated account, and enables master-password re-prompt on the selected item.
Do not capture the viewer, provider DOM, master password or native confirmation.

The browser profile, NSS trust, cache and home live under private `/run` paths.
Stopping the broker discards that runtime, so the operator must sign in again.
Core dumps and raw service output are disabled; the browser has a 2 GiB memory
limit and one CPU quota. The VNC service is also bounded. Stopping the display
stops the broker. Keep both services manually started until real acceptance;
there is no unattended vault unlock or bypass of native user verification.

Rollback: stop the broker and display, close the operator tunnel, restore the
previous launcher/configuration, and stop the separate TLS compose service.
Retain its root-only state for rollback. The production vault service and its
data remain independent. Verify health again after activation or rollback.

## References

- [OpenSSH authorized_keys restrictions](https://man.openbsd.org/sshd#AUTHORIZED_KEYS_FILE_FORMAT)
- [Ubuntu user namespace restrictions](https://documentation.ubuntu.com/release-notes/24.04/#unprivileged-user-namespace-restrictions)
- [Bitwarden CLI session-key generation](https://github.com/bitwarden/clients/blob/main/apps/cli/src/key-management/commands/unlock.command.ts)
- [MCP contract and acceptance](agent-mcp-spec.md)
- [TigerVNC Unix sockets and TCP disabling](https://tigervnc.org/doc/Xvnc.html)
- [systemd shared private temporary namespace](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html#JoinsNamespaceOf=)
