#!/bin/sh
set -eu
umask 077
base=/run/vaultwarden-agent
/usr/bin/install -d -m 0700 "$HOME/.local/share/pki/nssdb" \
    "$XDG_CONFIG_HOME" "$XDG_CACHE_HOME"
/usr/bin/certutil -N --empty-password -d "sql:$HOME/.local/share/pki/nssdb"
/usr/bin/certutil -A -d "sql:$HOME/.local/share/pki/nssdb" -t C,, \
    -n 'Vaultwarden loopback CA' -i /etc/vaultwarden-agent/native-ca.crt
exec /opt/vaultwarden-agent/venv/bin/vaultwarden-agent-broker \
    --config /var/lib/vaultwarden-agent/private/native.json \
    --socket "$base/broker.sock"
