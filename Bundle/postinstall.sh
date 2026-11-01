#!/bin/sh
# Create the account, then let systemd know about the unit. It is NOT started: nothing is joined and nothing
# is switched on yet, and starting it is the owner's choice (systemctl enable --now beacon).
systemd-sysusers /usr/lib/sysusers.d/beacon.conf 2>/dev/null || true
systemctl daemon-reload 2>/dev/null || true
echo "plaiiin Beacon installed. Next: switch fields on in /etc/beacon/beacon.json,"
echo "  join a server:  sudo beacon join '<join string>'"
echo "  start it:       sudo systemctl enable --now beacon"
