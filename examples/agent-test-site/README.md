# Owned Agent authentication test site

An independent password and WebAuthn relying party at
https://agent-test.bo0lean.com. Use test credentials only. Production Vaultwarden
data, credentials and TLS private state must never be mounted into this service.

## Local checks

```sh
python3 -m venv .venv
.venv/bin/pip install '.[test]'
.venv/bin/python -m unittest discover -p 'test_*.py'
```

The native CI verifier runs a loopback HTTPS equivalent with a trusted local CA,
the pinned official Bitwarden extension and disposable Vaultwarden credentials.
It verifies actual password MCP login, native passkey registration, signed
authentication, re-prompt cancellation, replay rejection and retained sessions.
TLS validation and the Chromium sandbox stay enabled.

## Oracle release

Build the checked-out immutable release and prepare its independent data directory:

```sh
docker build -t vaultwarden-agent-test:COMMIT examples/agent-test-site
sudo install -d -m 0700 -o 10001 -g 10001 /var/lib/vaultwarden-agent-test
AGENT_TEST_IMAGE=vaultwarden-agent-test:COMMIT AGENT_TEST_TUNNEL_ID=UUID docker compose \
  -f examples/agent-test-site/compose.yml up -d
```

Persist the selected image in the root-owned deployment configuration. The
container has a read-only root, no capabilities, a dedicated internal network,
bounded resources and no host-published port. Its SQLite file contains
test password hashes, public keys and private short-lived sessions; keep backups
private and use only generated accounts. Registration is limited to 64 accounts.

Use the authenticated Mac `cloudflared` CLI to create the dedicated
`vaultwarden-agent-test` tunnel, saving its generated credentials in the private
operations directory. Transfer that file through verified SSH to
`/etc/vaultwarden-agent-test/tunnel.json`, owned by 65532:65532 and mode 0400.
Install `cloudflared.yml` beside it as root-owned 0644. Do not copy the Mac's
account-level origin certificate to Oracle or print credential contents.

The pinned connector joins only this project's private ingress and egress
networks. The app has no internet egress; the connector has only its dedicated
tunnel credential. Production containers and networks remain unchanged. After
the service is healthy, run `cloudflared tunnel route dns UUID agent-test.bo0lean.com`
without the overwrite flag. This publishes only the owned test hostname.

Verify public `/health`, the expected HTTPS origin, password login/logout and
actual server-verified passkey login. Recheck production Vaultwarden health.
Record the immutable image ID and source revision. For rollback, restore the
previous selected image and Compose configuration; retain the database and its
backup. Do not run destructive volume cleanup or recreate the production vault.

The CI verifier accepts `--site-origin https://agent-test.bo0lean.com` for a
public-origin run while retaining a disposable vault. Its private fixture logs
and profile must not be attached to model-visible diagnostics.

## Private operator enrollment

After public HTTPS is verified, create a test account privately in the operator
browser and save only its test credential in the dedicated Vaultwarden account.
Register a new passkey for this RP and enable the item's master-password
re-prompt. Sign out before MCP acceptance. Keep the existing GitHub item intact.
Set the broker's approved origin, selectors and expected test username using
private operator metadata; do not send the password, passkey or session to Codex.
Retire temporary administrator SSH signing access before private credential entry.

The broker approval, browser WebAuthn request and server challenge all allow five
minutes for remote private confirmation. Challenges still expire, are consumed
once, and require the expected origin, RP and native user verification.
