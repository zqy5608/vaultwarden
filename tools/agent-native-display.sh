#!/bin/sh
# The VNC socket is accessible only to the operator group over verified SSH.
set -eu
umask 077
authority=/run/vaultwarden-agent-ui/Xauthority
cookie=$(/usr/bin/mcookie)
/usr/bin/xauth -f "$authority" add :99 . "$cookie" >/dev/null 2>&1
unset cookie
exec /usr/bin/Xtigervnc :99 -geometry 1440x1000 -depth 24 \
    -auth "$authority" -nolisten tcp -localhost yes -rfbport -1 \
    -rfbunixpath /run/vaultwarden-agent-ui/view.sock -rfbunixmode 0660 \
    -SecurityTypes None -SendCutText 0 -AcceptCutText 0 \
    -SendPrimary 0 -SetPrimary 0 -AllowOverride '' \
    -desktop 'Vaultwarden private confirmation'
