# Trusted MCP production deployment

The client requires no Vaultwarden server upgrade or database migration.
Use the existing server API and deploy the client under a separate unprivileged
account. The AI host receives only an SSH key restricted to the MCP protocol.
Administrators and the trusted process remain outside this isolation guarantee.

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

## References

- [OpenSSH authorized_keys restrictions](https://man.openbsd.org/sshd#AUTHORIZED_KEYS_FILE_FORMAT)
- [Bitwarden CLI session-key generation](https://github.com/bitwarden/clients/blob/main/apps/cli/src/key-management/commands/unlock.command.ts)
- [MCP contract and acceptance](agent-mcp-spec.md)
