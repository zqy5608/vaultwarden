#!/bin/sh
# Chromium's provider needs a display; no viewer or desktop transport is exposed.
set -eu
umask 077
authority=/run/vaultwarden-agent-ui/Xauthority
cookie=$(/usr/bin/mcookie)
/usr/bin/xauth -f "$authority" add :99 . "$cookie" >/dev/null 2>&1
unset cookie
exec /usr/bin/Xvfb :99 -screen 0 1440x1000x24 -auth "$authority" -nolisten tcp
