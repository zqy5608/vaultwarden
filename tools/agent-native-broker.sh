#!/bin/sh
set -eu
umask 077
base=/run/vaultwarden-agent
/usr/bin/install -d -m 0700 "$HOME/.local/share/pki/nssdb" \
    "$XDG_CONFIG_HOME" "$XDG_CACHE_HOME"
/usr/bin/certutil -N --empty-password -d "sql:$HOME/.local/share/pki/nssdb"
/usr/bin/certutil -A -d "sql:$HOME/.local/share/pki/nssdb" -t C,, \
    -n 'Vaultwarden loopback CA' -i "$CREDENTIALS_DIRECTORY/native-ca"
exec /opt/vaultwarden-agent/venv/bin/vaultwarden-agent-broker \
    --config "$base/broker-config" --socket "$base/broker.sock" \
    --operator-socket "$base/operator.sock"
