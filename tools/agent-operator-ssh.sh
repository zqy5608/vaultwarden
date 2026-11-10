#!/bin/sh
# A distinct restricted key may confirm one pending request, never use model RPC.
set -eu
if [ -n "${SSH_ORIGINAL_COMMAND:-}" ]; then
    printf '%s\n' 'This key only supports private confirmation.' >&2
    exit 1
fi
exec /usr/bin/env -i HOME=/var/lib/vaultwarden-agent PATH=/usr/bin:/bin LANG=C.UTF-8 \
    /opt/vaultwarden-agent/venv/bin/vaultwarden-agent-operator \
    --socket /run/vaultwarden-agent/operator.sock
