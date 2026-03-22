#!/usr/bin/env bash
set -euo pipefail

IFACE="${1:-eth0}"

sudo ./xdp_ddos load "$IFACE" configs/rules.conf
sudo ./xdp_ddos defaults show
sudo ./xdp_ddos stats
sudo ./xdp_ddos state top 10
sudo ./xdp_ddos policy list

cat <<'EOF'
XDP DDoS filter is active.
Run:
  sudo ./xdp_ddos monitor 2
  sudo ./xdp_ddos log /var/log/xdp_ddos_events.jsonl 250
To unload:
  sudo ./xdp_ddos unload <iface>
EOF
