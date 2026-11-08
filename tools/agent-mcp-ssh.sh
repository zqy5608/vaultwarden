#!/bin/sh
# Install root-owned; the restricted SSH key may start MCP, never a shell command.
set -eu

if [ -n "${SSH_ORIGINAL_COMMAND:-}" ]; then
    printf '%s\n' 'This key only supports MCP stdio.' >&2
    exit 1
fi

exec /usr/bin/env -i \
    HOME=/var/lib/vaultwarden-agent \
    XDG_CACHE_HOME=/var/lib/vaultwarden-agent/private/cache \
    PLAYWRIGHT_BROWSERS_PATH=/opt/vaultwarden-agent/browsers \
    PATH=/usr/bin:/bin \
    LANG=C.UTF-8 \
    /opt/vaultwarden-agent/venv/bin/vaultwarden-agent-mcp \
    --config /var/lib/vaultwarden-agent/private/config.json
