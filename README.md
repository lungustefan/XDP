THIS IS **NOT** PRODUCTION READY
---

# XDP DDoS Filter (Driver Mode, Adaptive)

This project provides an XDP/eBPF DDoS protection filter with:

- IPv4 and IPv6 source tracking
- Per-IP, subnet, and per-port policy rules (pass, adaptive, or drop)
- Adaptive baseline learning (no fixed static pps/bps limits)
- Heuristic packet inspection for:
  - DNS amplification-like response floods
  - NTP/SSDP/CLDAP/Memcached/Chargen reflection-like UDP floods
  - ACK-only TCP flood signatures
  - TCP RST spam and SYN-heavy flood signatures
  - ICMP flood behavior
  - TCP weird-flag/null-scan style traffic spikes
  - Random UDP spray patterns
  - Port-scan-like destination spread
- Automatic mitigation (temporary auto-block after repeated suspicious windows)
- High-confidence mitigation gates (minimum score and multi-signal confirmation before block)
- Driver-mode XDP attachment (native mode)
- Runtime stats, monitoring, and structured log streaming
- REST API service for dashboard integration
- SQLite-backed persistent control plane state
- Conservative auto-learning loop with trust/suspicion tracking

## Architecture

- `src/xdp_ddos_kern.c`:
  - XDP data path logic
  - Per-source-IP adaptive state tracking with 1-second windows
  - IPv4 and IPv6 parsing
  - L4 signal extraction (TCP/UDP feature counters)
  - Suspicion scoring + auto-mitigation via timed blocks
  - Ring buffer security event emission
- `src/xdp_ddos_user.c`:
  - Load/unload XDP in driver mode
  - Configure adaptive defaults and IP/subnet/port policies
  - Parse optional rule file
  - Read and monitor stats
  - Show top source talkers (pps/bps/signals)
  - Persist mitigation events as JSONL logs
- `src/common.h`: shared map/value definitions
- `api/server.py`: REST API wrapper for automation and UI
  - SQLite DB persistence for defaults/policies/learning state
  - Startup replay to re-apply saved rules automatically
  - Auto-learning/tuning worker for adaptive policy updates

## Requirements

- Linux kernel with XDP support
- Native driver-mode support on your NIC
- `clang`, `gcc`, `make`, `libbpf`, `libelf`, `zlib`
- Root privileges for load/unload and map access

## Build

```bash
make
```

## Quick Start

Load with defaults only:

```bash
sudo ./xdp_ddos load eth0
```

Load with a rules file:

```bash
sudo ./xdp_ddos load eth0 configs/rules.conf
```

Load in shared mode on multiple interfaces (single shared map set):

```bash
sudo ./xdp_ddos load-many configs/rules.conf eth0 enp6s20 enp6s21
```

Detach then reattach on multiple interfaces (for rolling hardening updates):

```bash
sudo ./xdp_ddos reload-many configs/rules.conf eth0 enp6s20 enp6s21
```

`configs/rules.conf` is intentionally defaults-only. Manage IP/subnet/port overrides dynamically via API.

Show one-shot stats:

```bash
sudo ./xdp_ddos stats
```

Monitor stats continuously:

```bash
sudo ./xdp_ddos monitor 2
```

Live human-readable active monitor (shows block deltas and top sources):

```bash
sudo ./xdp_ddos active 2 15
```

Stream detection events to JSONL:

```bash
sudo ./xdp_ddos log /var/log/xdp_ddos_events.jsonl 250
```

Unload:

```bash
sudo ./xdp_ddos unload eth0
```

Unload from multiple interfaces:

```bash
sudo ./xdp_ddos unload-many eth0 enp6s20 enp6s21
```

## CLI Examples

Show global defaults:

```bash
sudo ./xdp_ddos defaults show
```

Set adaptive defaults:

```bash
sudo ./xdp_ddos defaults set 280 140 120 3 1 3 88 70 65 60 700 12 18 45 55 220 3 30 20 12 18 0
```

Machine-readable JSON output (for API integrations):

```bash
sudo ./xdp_ddos --json stats
sudo ./xdp_ddos --json defaults show
sudo ./xdp_ddos --json state top 20
```

Show top active sources:

```bash
sudo ./xdp_ddos state top 30
```

Add subnet rule:

```bash
sudo ./xdp_ddos subnet add 203.0.113.0/24 adaptive 230 110 180
```

Add per-port default profile (UDP/53):

```bash
sudo ./xdp_ddos port add udp 53 adaptive 210 100 180
```

Add an IPv4 drop rule for 10 minutes:

```bash
sudo ./xdp_ddos policy add 198.51.100.10 drop 0 0 0 600
```

Add an IPv6 adaptive override rule:

```bash
sudo ./xdp_ddos policy add 2001:db8::42 adaptive 220 100 180
```

Delete a rule:

```bash
sudo ./xdp_ddos policy del 2001:db8::42
```

List rules:

```bash
sudo ./xdp_ddos policy list
```

## Rules File Format

See `configs/rules.conf`.

Supported directives:

- `default anomaly_mult=<pct> score=<n> block_ttl=<sec> offenses=<n> auto=<0|1> warmup=<n> ack_ratio=<pct> rst_ratio=<pct> syn_ratio=<pct> dns_ratio=<pct> dns_min_bytes=<n> udp_spread=<n> scan_spread=<n> udp_amp_ratio=<pct> icmp_ratio=<pct> block_min_score=<n> block_min_reasons=<n> emergency_cooldown_sec=<sec> service_relax_dns_pct=<pct> service_relax_http_pct=<pct> service_relax_https_pct=<pct> service_relax_ntp_pct=<pct>`
- `ip <IPv4|IPv6> action=<pass|adaptive|drop> anomaly_mult=<pct> score=<n> block_ttl=<sec> ttl=<sec>`
- `subnet <IPv4_CIDR|IPv6_CIDR> action=<pass|adaptive|drop> anomaly_mult=<pct> score=<n> block_ttl=<sec> ttl=<sec>`
- `port <tcp|udp> <port> action=<pass|adaptive|drop> anomaly_mult=<pct> score=<n> block_ttl=<sec> ttl=<sec>`

If no rules file is supplied, built-in defaults are applied automatically.
If no API/CLI overrides are set, the system runs on defaults only.

## REST API

The API server is intended for a web panel/control plane.

Install and run:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r api/requirements.txt
XDP_DDOS_CLI=./xdp_ddos XDP_DDOS_EVENT_LOG=/var/log/xdp_ddos_events.jsonl XDP_DDOS_DB=./xdp_ddos.db XDP_DDOS_AUTO_LEARN=1 python api/server.py
```

Environment options:

- `XDP_DDOS_DB`: SQLite file path (portable state file)
- `XDP_DDOS_AUTO_LEARN`: `1` enable auto-learning, `0` disable
- `XDP_DDOS_AUTO_LEARN_INTERVAL_SEC`: learning loop interval in seconds
- `XDP_DDOS_API_HOST`, `XDP_DDOS_API_PORT`: bind settings

Main endpoints:

- `GET /api/v1/health`
- `GET /api/v1/stats`
- `GET /api/v1/defaults`
- `PUT /api/v1/defaults`
- `GET /api/v1/sources/top?limit=20`
- `POST /api/v1/policies/ip`
- `DELETE /api/v1/policies/ip/<ip>`
- `POST /api/v1/policies/subnet`
- `DELETE /api/v1/policies/subnet/<cidr>`
- `POST /api/v1/policies/port`
- `DELETE /api/v1/policies/port/<proto>/<port>`
- `GET /api/v1/policies?scope=<ip|subnet|port>`
- `POST /api/v1/ip/<ip>/disable` (sets pass rule with ttl)
- `POST /api/v1/ip/<ip>/enable` (removes disable/pass rule)
- `GET /api/v1/learning/state`
- `POST /api/v1/learning/tick`
- `GET /api/v1/attacks/recent?limit=100`
- `GET /api/v1/attacks/summary?limit=1000`
- `GET /api/v1/db/export`
- `POST /api/v1/db/import`
- `POST /api/v1/replay`

## Notes

- Driver mode is enforced. If your NIC does not support native XDP mode, load will fail.
- Existing state is LRU-capped to prevent unbounded memory growth.
- Auto-mitigation is in-kernel, so it reacts at packet path speed.
- This is adaptive anomaly detection with packet-level heuristics, not full stream reassembly IDS.
- No single XDP program can detect literally every attack type; for full coverage combine this with upstream filtering, ACLs, and L7 controls.
- Blocking is intentionally conservative: uncertain patterns are monitored first (`monitor_only`) and only high-confidence multi-signal cases are eligible for block.
- An emergency guardrail path is enabled for extreme in-window floods so severe attacks are dropped immediately instead of waiting for window rollover.
- Emergency hysteresis is enabled through a cooldown period after emergency drops so immediate post-attack traffic is judged with stricter confidence thresholds.
