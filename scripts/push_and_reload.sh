#!/usr/bin/env bash
set -euo pipefail

HOST="${1:-root@208.70.218.84}"
REMOTE_DIR="${2:-/root/xdp_staging_20260322_183846}"
RULES_FILE="${3:-configs/rules.conf}"
shift $(( $# >= 3 ? 3 : $# )) || true

if [ "$#" -eq 0 ]; then
  IFACES=(eth0)
else
  IFACES=("$@")
fi

echo "[1/3] Copying updated sources to ${HOST}:${REMOTE_DIR} via SCP"
ssh "$HOST" "mkdir -p '$REMOTE_DIR/src' '$REMOTE_DIR/configs'"
scp src/xdp_ddos_kern.c src/xdp_ddos_user.c src/common.h "${HOST}:${REMOTE_DIR}/src/"
scp Makefile "${HOST}:${REMOTE_DIR}/"
scp "$RULES_FILE" "${HOST}:${REMOTE_DIR}/configs/rules.conf"

echo "[2/3] Rebuilding on remote host"
ssh "$HOST" "cd '$REMOTE_DIR'; make"

echo "[3/3] Detach then reattach XDP in shared mode"
ssh "$HOST" "cd '$REMOTE_DIR'; ./xdp_ddos unload-many ${IFACES[*]} || true; ./xdp_ddos load-many '$RULES_FILE' ${IFACES[*]}"

echo
echo "Live human-readable monitor:"
echo "  ssh $HOST 'cd $REMOTE_DIR; ./xdp_ddos active 2 15'"
