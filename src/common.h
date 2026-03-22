#ifndef XDP_DDOS_COMMON_H
#define XDP_DDOS_COMMON_H

#include <linux/types.h>

#define XDP_DDOS_MAX_POLICIES 262144
#define XDP_DDOS_MAX_STATES 1048576
#define XDP_DDOS_WINDOW_NS 1000000000ULL

#define XDP_DDOS_DEFAULT_ANOMALY_MULT_PCT 280
#define XDP_DDOS_DEFAULT_SCORE_THRESHOLD 140
#define XDP_DDOS_DEFAULT_BLOCK_TTL_SEC 120
#define XDP_DDOS_DEFAULT_OFFENSES 3
#define XDP_DDOS_DEFAULT_WARMUP_WINDOWS 3
#define XDP_DDOS_DEFAULT_ACK_ONLY_RATIO_PCT 88
#define XDP_DDOS_DEFAULT_RST_RATIO_PCT 70
#define XDP_DDOS_DEFAULT_SYN_RATIO_PCT 65
#define XDP_DDOS_DEFAULT_DNS_RESP_RATIO_PCT 60
#define XDP_DDOS_DEFAULT_DNS_AMP_MIN_BYTES 700
#define XDP_DDOS_DEFAULT_UDP_RANDOM_SPREAD 12
#define XDP_DDOS_DEFAULT_SCAN_SPREAD 18
#define XDP_DDOS_DEFAULT_UDP_AMP_RATIO_PCT 45
#define XDP_DDOS_DEFAULT_ICMP_RATIO_PCT 55
#define XDP_DDOS_DEFAULT_BLOCK_MIN_SCORE 220
#define XDP_DDOS_DEFAULT_BLOCK_MIN_REASONS 3
#define XDP_DDOS_DEFAULT_EMERGENCY_COOLDOWN_SEC 30
#define XDP_DDOS_DEFAULT_SERVICE_RELAX_DNS_PCT 20
#define XDP_DDOS_DEFAULT_SERVICE_RELAX_HTTP_PCT 12
#define XDP_DDOS_DEFAULT_SERVICE_RELAX_HTTPS_PCT 18
#define XDP_DDOS_DEFAULT_SERVICE_RELAX_NTP_PCT 0

#define XDP_DDOS_FAMILY_V4 4
#define XDP_DDOS_FAMILY_V6 6

#define XDP_DDOS_REASON_ANOMALY_RATE   (1u << 0)
#define XDP_DDOS_REASON_DNS_AMP        (1u << 1)
#define XDP_DDOS_REASON_ACK_FLOOD      (1u << 2)
#define XDP_DDOS_REASON_UDP_RANDOM     (1u << 3)
#define XDP_DDOS_REASON_PORT_SCAN      (1u << 4)
#define XDP_DDOS_REASON_RST_FLOOD      (1u << 5)
#define XDP_DDOS_REASON_SYN_FLOOD      (1u << 6)
#define XDP_DDOS_REASON_UDP_AMP        (1u << 7)
#define XDP_DDOS_REASON_ICMP_FLOOD     (1u << 8)
#define XDP_DDOS_REASON_TCP_WEIRD      (1u << 9)
#define XDP_DDOS_REASON_EMERGENCY      (1u << 10)

enum ddos_action {
    DDOS_ACTION_PASS = 0,
    DDOS_ACTION_ADAPTIVE = 1,
    DDOS_ACTION_DROP = 2,
};

enum ddos_stat_idx {
    STAT_PASS = 0,
    STAT_DROP_POLICY = 1,
    STAT_DROP_SUSPICIOUS = 2,
    STAT_DROP_MITIGATED = 3,
    STAT_MITIGATION_SET = 4,
    STAT_PARSE_ERROR = 5,
    STAT_DNS_AMP = 6,
    STAT_ACK_FLOOD = 7,
    STAT_UDP_RANDOM = 8,
    STAT_PORT_SCAN = 9,
    STAT_RST_FLOOD = 10,
    STAT_SYN_FLOOD = 11,
    STAT_UDP_AMP = 12,
    STAT_ICMP_FLOOD = 13,
    STAT_TCP_WEIRD = 14,
    STAT_EVENT_DROP = 15,
    STAT_MONITOR_ONLY = 16,
    STAT_DROP_EMERGENCY = 17,
    STAT_MAX = 18,
};

struct ip_key {
    __u8 family;
    __u8 reserved[3];
    union {
        __be32 v4;
        __u8 v6[16];
    } addr;
};

struct global_cfg {
    __u32 anomaly_mult_pct;
    __u32 score_threshold;
    __u32 block_ttl_sec;
    __u32 offense_threshold;
    __u32 auto_mitigation;
    __u32 warmup_windows;
    __u32 ewma_shift;
    __u32 ack_only_ratio_pct;
    __u32 rst_ratio_pct;
    __u32 syn_ratio_pct;
    __u32 dns_resp_ratio_pct;
    __u32 dns_amp_min_bytes;
    __u32 udp_random_spread_bins;
    __u32 scan_spread_bins;
    __u32 udp_amp_ratio_pct;
    __u32 icmp_ratio_pct;
    __u32 block_min_score;
    __u32 block_min_reasons;
    __u32 emergency_cooldown_sec;
    __u32 service_relax_dns_pct;
    __u32 service_relax_http_pct;
    __u32 service_relax_https_pct;
    __u32 service_relax_ntp_pct;
};

struct lpm_v4_key {
    __u32 prefixlen;
    __be32 addr;
};

struct lpm_v6_key {
    __u32 prefixlen;
    __u8 addr[16];
};

struct port_key {
    __u8 proto;
    __u8 reserved;
    __u16 port;
};

struct ip_policy {
    __u32 action;
    __u32 anomaly_mult_pct;
    __u32 score_threshold;
    __u32 block_ttl_sec;
    __u64 expires_at_ns;
};

struct ip_state {
    __u64 window_start_ns;
    __u64 last_seen_ns;
    __u64 drop_until_ns;

    __u32 pkt_count;
    __u32 byte_count;
    __u32 syn_count;
    __u32 rst_count;
    __u32 icmp_count;
    __u32 ack_only_count;
    __u32 udp_count;
    __u32 udp_high_port_count;
    __u32 dns_resp_like_count;
    __u32 udp_amp_like_count;
    __u32 tcp_weird_count;
    __u32 dst_port_spread;
    __u64 dst_port_bits;
    __u16 last_dport;
    __u16 reserved16;

    __u32 baseline_pps_q8;
    __u32 baseline_bps_q8;
    __u32 baseline_syn_q8;
    __u32 baseline_ack_q8;

    __u32 warmup_seen;
    __u32 offense_count;
    __u32 last_reason_mask;
    __u32 low_score_windows;
    __u64 emergency_cooldown_until_ns;
};

struct ddos_event {
    __u64 ts_ns;
    struct ip_key src;
    __u32 reason_mask;
    __u32 action;
    __u32 score;
    __u32 pkt_count;
    __u32 byte_count;
    __u32 syn_count;
    __u32 ack_only_count;
    __u32 udp_count;
    __u32 udp_spread;
    __u32 block_ttl_sec;
};

#endif
