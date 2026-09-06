#!/bin/sh
# keepalived notify script — writes the VRRP state to a file so the backend
# HA health endpoint can report MASTER/BACKUP/FAULT for this HAProxy instance.
#
# Called by keepalived as: keepalived_notify.sh <STATE>
# where <STATE> is one of: MASTER, BACKUP, FAULT
set -e

STATE="${1:-UNKNOWN}"
STATE_FILE="/app/data/keepalived.state"

mkdir -p "$(dirname "$STATE_FILE")"
echo "$STATE" > "$STATE_FILE"

# Log to stderr for container logs
echo "[keepalived] VRRP state -> $STATE" >&2

exit 0
