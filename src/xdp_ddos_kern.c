#include "common.h"

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct ip_key);
    __type(value, struct ip_policy);
    __uint(max_entries, XDP_DDOS_MAX_POLICIES);
} ip_policies SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm_v4_key);
    __type(value, struct ip_policy);
    __uint(max_entries, XDP_DDOS_MAX_POLICIES);
} subnet_policies_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm_v6_key);
    __type(value, struct ip_policy);
    __uint(max_entries, XDP_DDOS_MAX_POLICIES);
} subnet_policies_v6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct port_key);
    __type(value, struct ip_policy);
    __uint(max_entries, 65536);
} port_policies SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct ip_key);
    __type(value, struct ip_state);
    __uint(max_entries, XDP_DDOS_MAX_STATES);
} ip_states SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct global_cfg);
    __uint(max_entries, 1);
} global_config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, STAT_MAX);
} stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

static __always_inline void stat_inc(__u32 idx)
{
    __u64 *value;

    if (idx >= STAT_MAX)
        return;

    value = bpf_map_lookup_elem(&stats, &idx);
    if (value)
        (*value)++;
}

static __always_inline __u32 max_u32(__u32 a, __u32 b)
{
    return a > b ? a : b;
}

static __always_inline __u32 ewma_q8(__u32 prev_q8, __u32 sample, __u32 shift)
{
    __u32 sample_q8 = sample << 8;

    if (!prev_q8)
        return sample_q8;
    if (!shift || shift > 8)
        shift = 3;

    return prev_q8 - (prev_q8 >> shift) + (sample_q8 >> shift);
}

static __always_inline __u32 bit_count64(__u64 v)
{
    __u32 count = 0;
    int i;

#pragma clang loop unroll(full)
    for (i = 0; i < 64; i++) {
        if (v & ((__u64)1 << i))
            count++;
    }

    return count;
}

static __always_inline __u32 bit_count32(__u32 v)
{
    __u32 count = 0;
    int i;

#pragma clang loop unroll(full)
    for (i = 0; i < 32; i++) {
        if (v & ((__u32)1 << i))
            count++;
    }

    return count;
}

static __always_inline __u32 resolve_anomaly_mult(const struct global_cfg *cfg,
                          const struct ip_policy *policy)
{
    __u32 anomaly_mult = cfg->anomaly_mult_pct;

    if (policy && policy->anomaly_mult_pct)
        anomaly_mult = policy->anomaly_mult_pct;
    if (!anomaly_mult)
        anomaly_mult = XDP_DDOS_DEFAULT_ANOMALY_MULT_PCT;
    return anomaly_mult;
}

static __always_inline __u32 resolve_service_relax_pct(const struct global_cfg *cfg,
                            __u16 dport)
{
    if (dport == 53)
        return cfg->service_relax_dns_pct;
    if (dport == 80)
        return cfg->service_relax_http_pct;
    if (dport == 443)
        return cfg->service_relax_https_pct;
    if (dport == 123)
        return cfg->service_relax_ntp_pct;
    return 0;
}

static __always_inline void emit_event(const struct ip_key *key,
                       __u32 reason_mask,
                       __u32 action,
                       __u32 score,
                       const struct ip_state *state,
                       __u32 block_ttl_sec)
{
    struct ddos_event *evt;

    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) {
        stat_inc(STAT_EVENT_DROP);
        return;
    }

    evt->ts_ns = bpf_ktime_get_ns();
    evt->src = *key;
    evt->reason_mask = reason_mask;
    evt->action = action;
    evt->score = score;
    evt->pkt_count = state->pkt_count;
    evt->byte_count = state->byte_count;
    evt->syn_count = state->syn_count;
    evt->ack_only_count = state->ack_only_count;
    evt->udp_count = state->udp_count;
    evt->udp_spread = state->dst_port_spread;
    evt->block_ttl_sec = block_ttl_sec;

    bpf_ringbuf_submit(evt, 0);
}

static __always_inline void update_baselines(struct ip_state *state,
                         const struct global_cfg *cfg)
{
    state->baseline_pps_q8 = ewma_q8(state->baseline_pps_q8, state->pkt_count,
                     cfg->ewma_shift);
    state->baseline_bps_q8 = ewma_q8(state->baseline_bps_q8, state->byte_count,
                     cfg->ewma_shift);
    state->baseline_syn_q8 = ewma_q8(state->baseline_syn_q8, state->syn_count,
                     cfg->ewma_shift);
    state->baseline_ack_q8 = ewma_q8(state->baseline_ack_q8, state->ack_only_count,
                     cfg->ewma_shift);
}

static __always_inline void reset_window_state(struct ip_state *state, __u64 now)
{
    state->window_start_ns = now;
    state->pkt_count = 0;
    state->byte_count = 0;
    state->syn_count = 0;
    state->rst_count = 0;
    state->icmp_count = 0;
    state->ack_only_count = 0;
    state->udp_count = 0;
    state->udp_high_port_count = 0;
    state->dns_resp_like_count = 0;
    state->udp_amp_like_count = 0;
    state->tcp_weird_count = 0;
    state->dst_port_spread = 0;
    state->dst_port_bits = 0;
    state->last_dport = 0;
}

static __always_inline __u8 is_udp_amp_source_port(__u16 sport)
{
    switch (sport) {
    case 19:    /* chargen */
    case 53:    /* dns */
    case 123:   /* ntp */
    case 389:   /* cldap */
    case 1900:  /* ssdp */
    case 3702:  /* ws-discovery */
    case 11211: /* memcached */
        return 1;
    default:
        return 0;
    }
}

static __always_inline int eval_completed_window(struct ip_state *state,
                         const struct ip_key *key,
                         const struct global_cfg *cfg,
                         const struct ip_policy *policy,
                         __u16 service_dport,
                         __u64 now)
{
    __u32 anomaly_mult = resolve_anomaly_mult(cfg, policy);
    __u32 score_threshold = cfg->score_threshold;
    __u32 block_ttl_sec = cfg->block_ttl_sec;
    __u32 baseline_pps;
    __u32 baseline_bps;
    __u32 pps_threshold;
    __u32 bps_threshold;
    __u32 score = 0;
    __u32 reason_mask = 0;
    __u32 ack_ratio = 0;
    __u32 rst_ratio = 0;
    __u32 syn_ratio = 0;
    __u32 icmp_ratio = 0;
    __u32 dns_ratio = 0;
    __u32 udp_amp_ratio = 0;
    __u32 udp_high_ratio = 0;
    __u32 reason_count;
    __u32 block_min_score = cfg->block_min_score;
    __u32 block_min_reasons = cfg->block_min_reasons;
    __u32 service_relax_pct = resolve_service_relax_pct(cfg, service_dport);

    if (!state->pkt_count)
        return 0;

    if (policy) {
        if (policy->score_threshold)
            score_threshold = policy->score_threshold;
        if (policy->block_ttl_sec)
            block_ttl_sec = policy->block_ttl_sec;
    }

    if (!score_threshold)
        score_threshold = XDP_DDOS_DEFAULT_SCORE_THRESHOLD;
    if (!block_min_score)
        block_min_score = XDP_DDOS_DEFAULT_BLOCK_MIN_SCORE;
    if (!block_min_reasons)
        block_min_reasons = XDP_DDOS_DEFAULT_BLOCK_MIN_REASONS;

    if (state->warmup_seen < cfg->warmup_windows) {
        update_baselines(state, cfg);
        state->warmup_seen++;
        return 0;
    }

    baseline_pps = state->baseline_pps_q8 >> 8;
    baseline_bps = state->baseline_bps_q8 >> 8;
    pps_threshold = max_u32((baseline_pps * anomaly_mult) / 100, baseline_pps + 20);
    bps_threshold = max_u32((baseline_bps * anomaly_mult) / 100, baseline_bps + 8192);

    if (service_relax_pct) {
        pps_threshold = (pps_threshold * (100 + service_relax_pct)) / 100;
        bps_threshold = (bps_threshold * (100 + service_relax_pct)) / 100;
        score_threshold = (score_threshold * (100 + (service_relax_pct / 2))) / 100;
    }

    if (state->emergency_cooldown_until_ns > now) {
        score_threshold += 25;
        block_min_score += 25;
        block_min_reasons += 1;
    }

    if (state->pkt_count > pps_threshold) {
        __u32 excess_pct = ((state->pkt_count - pps_threshold) * 100) /
                   max_u32(pps_threshold, 1);
        score += 15 + (excess_pct / 3);
        reason_mask |= XDP_DDOS_REASON_ANOMALY_RATE;
    }

    if (state->byte_count > bps_threshold) {
        __u32 excess_pct = ((state->byte_count - bps_threshold) * 100) /
                   max_u32(bps_threshold, 1);
        score += 15 + (excess_pct / 4);
        reason_mask |= XDP_DDOS_REASON_ANOMALY_RATE;
    }

    if (state->pkt_count > 25)
        ack_ratio = (state->ack_only_count * 100) / state->pkt_count;

    if (state->pkt_count > 25)
        rst_ratio = (state->rst_count * 100) / state->pkt_count;

    if (state->pkt_count > 25)
        syn_ratio = (state->syn_count * 100) / state->pkt_count;

    if (state->pkt_count > 25)
        icmp_ratio = (state->icmp_count * 100) / state->pkt_count;

    if (state->ack_only_count > 20 && ack_ratio >= cfg->ack_only_ratio_pct &&
        state->syn_count < (state->pkt_count / 20 + 1)) {
        score += 65;
        reason_mask |= XDP_DDOS_REASON_ACK_FLOOD;
        stat_inc(STAT_ACK_FLOOD);
    }

    if (state->rst_count > 16 && rst_ratio >= cfg->rst_ratio_pct) {
        score += 70;
        reason_mask |= XDP_DDOS_REASON_RST_FLOOD;
        stat_inc(STAT_RST_FLOOD);
    }

    if (state->syn_count > 18 && syn_ratio >= cfg->syn_ratio_pct) {
        score += 60;
        reason_mask |= XDP_DDOS_REASON_SYN_FLOOD;
        stat_inc(STAT_SYN_FLOOD);
    }

    if (state->icmp_count > 20 && icmp_ratio >= cfg->icmp_ratio_pct) {
        score += 55;
        reason_mask |= XDP_DDOS_REASON_ICMP_FLOOD;
        stat_inc(STAT_ICMP_FLOOD);
    }

    if (state->tcp_weird_count > 6) {
        score += 50;
        reason_mask |= XDP_DDOS_REASON_TCP_WEIRD;
        stat_inc(STAT_TCP_WEIRD);
    }

    if (state->udp_count > 20) {
        dns_ratio = (state->dns_resp_like_count * 100) / state->udp_count;
        udp_amp_ratio = (state->udp_amp_like_count * 100) / state->udp_count;
        udp_high_ratio = (state->udp_high_port_count * 100) / state->udp_count;
    }

    if (state->dns_resp_like_count > 8 && dns_ratio >= cfg->dns_resp_ratio_pct) {
        score += 70;
        reason_mask |= XDP_DDOS_REASON_DNS_AMP;
        stat_inc(STAT_DNS_AMP);
    }

    if (state->udp_amp_like_count > 10 &&
        udp_amp_ratio >= cfg->udp_amp_ratio_pct) {
        score += 75;
        reason_mask |= XDP_DDOS_REASON_UDP_AMP;
        stat_inc(STAT_UDP_AMP);
    }

    if (state->udp_count > 32 &&
        state->dst_port_spread >= cfg->udp_random_spread_bins &&
        udp_high_ratio >= 70) {
        score += 60;
        reason_mask |= XDP_DDOS_REASON_UDP_RANDOM;
        stat_inc(STAT_UDP_RANDOM);
    }

    if (state->pkt_count > 28 &&
        state->dst_port_spread >= cfg->scan_spread_bins &&
        state->syn_count > 4) {
        score += 70;
        reason_mask |= XDP_DDOS_REASON_PORT_SCAN;
        stat_inc(STAT_PORT_SCAN);
    }

    update_baselines(state, cfg);

    if (reason_mask)
        state->last_reason_mask = reason_mask;

    if (score >= score_threshold) {
        reason_count = bit_count32(reason_mask);
        emit_event(key, reason_mask, DDOS_ACTION_ADAPTIVE, score, state, block_ttl_sec);

        if (score < block_min_score || reason_count < block_min_reasons) {
            stat_inc(STAT_MONITOR_ONLY);
            if (state->offense_count > 0)
                state->offense_count--;
            return 0;
        }

        state->offense_count++;
        state->low_score_windows = 0;

        if (cfg->auto_mitigation && cfg->offense_threshold &&
            state->offense_count >= cfg->offense_threshold) {
            state->drop_until_ns = now + ((__u64)block_ttl_sec * 1000000000ULL);
            state->offense_count = 0;
            stat_inc(STAT_MITIGATION_SET);
            emit_event(key, reason_mask, DDOS_ACTION_DROP, score, state,
                   block_ttl_sec);
            return 1;
        }

        stat_inc(STAT_DROP_SUSPICIOUS);
    } else {
        state->low_score_windows++;
        if (state->offense_count > 0 && state->low_score_windows >= 2)
            state->offense_count--;
    }

    return 0;
}

static __always_inline int emergency_guard(struct ip_state *state,
                       const struct ip_key *key,
                       const struct global_cfg *cfg,
                       const struct ip_policy *policy,
                       __u64 now)
{
    __u32 anomaly_mult = resolve_anomaly_mult(cfg, policy);
    __u32 baseline_pps = state->baseline_pps_q8 >> 8;
    __u32 baseline_bps = state->baseline_bps_q8 >> 8;
    __u32 pps_floor = 200000;
    __u32 bps_floor = 300000000;
    __u32 guard_pps = max_u32(max_u32(baseline_pps, 2000) * (anomaly_mult / 100 + 9),
                  pps_floor);
    __u32 guard_bps = max_u32(max_u32(baseline_bps, 4000000) * (anomaly_mult / 100 + 9),
                  bps_floor);
    __u32 reason_mask = 0;
    __u32 short_ttl = cfg->block_ttl_sec / 6;
    __u32 cooldown_sec = cfg->emergency_cooldown_sec;

    if (short_ttl < 15)
        short_ttl = 15;
    if (!cooldown_sec)
        cooldown_sec = XDP_DDOS_DEFAULT_EMERGENCY_COOLDOWN_SEC;

    if (state->pkt_count >= guard_pps || state->byte_count >= guard_bps)
        reason_mask |= XDP_DDOS_REASON_ANOMALY_RATE;

    if (state->pkt_count > 20000 && state->syn_count > (state->pkt_count * 92) / 100)
        reason_mask |= XDP_DDOS_REASON_SYN_FLOOD;

    if (state->pkt_count > 20000 && state->rst_count > (state->pkt_count * 92) / 100)
        reason_mask |= XDP_DDOS_REASON_RST_FLOOD;

    if (state->udp_count > 25000 && state->udp_amp_like_count > (state->udp_count * 70) / 100)
        reason_mask |= XDP_DDOS_REASON_UDP_AMP;

    if (!reason_mask)
        return 0;

    reason_mask |= XDP_DDOS_REASON_EMERGENCY;
    state->drop_until_ns = now + ((__u64)short_ttl * 1000000000ULL);
    state->emergency_cooldown_until_ns = now + ((__u64)cooldown_sec * 1000000000ULL);
    state->offense_count = 0;
    state->low_score_windows = 0;
    emit_event(key, reason_mask, DDOS_ACTION_DROP, cfg->block_min_score + 200,
           state, short_ttl);
    stat_inc(STAT_DROP_EMERGENCY);
    return 1;
}

static __always_inline void apply_policy_override(struct ip_policy *effective,
                          const struct ip_policy *candidate)
{
    if (!candidate)
        return;
    *effective = *candidate;
}

static __always_inline void resolve_policies(const struct ip_key *key,
                         __u8 ip_proto,
                         __u16 dport,
                         __u64 now,
                         struct ip_policy *effective)
{
    struct ip_policy *p;

    *effective = (struct ip_policy){
        .action = DDOS_ACTION_ADAPTIVE,
    };

    if (dport) {
        struct port_key pk = {
            .proto = ip_proto,
            .port = bpf_htons(dport),
        };

        p = bpf_map_lookup_elem(&port_policies, &pk);
        if (p) {
            if (p->expires_at_ns && p->expires_at_ns < now) {
                bpf_map_delete_elem(&port_policies, &pk);
            } else {
                apply_policy_override(effective, p);
            }
        }
    }

    if (key->family == XDP_DDOS_FAMILY_V4) {
        struct lpm_v4_key k4 = {
            .prefixlen = 32,
            .addr = key->addr.v4,
        };

        p = bpf_map_lookup_elem(&subnet_policies_v4, &k4);
        if (p) {
            if (p->expires_at_ns && p->expires_at_ns < now) {
                bpf_map_delete_elem(&subnet_policies_v4, &k4);
            } else {
                apply_policy_override(effective, p);
            }
        }
    } else if (key->family == XDP_DDOS_FAMILY_V6) {
        struct lpm_v6_key k6 = {
            .prefixlen = 128,
        };

        __builtin_memcpy(k6.addr, key->addr.v6, 16);
        p = bpf_map_lookup_elem(&subnet_policies_v6, &k6);
        if (p) {
            if (p->expires_at_ns && p->expires_at_ns < now) {
                bpf_map_delete_elem(&subnet_policies_v6, &k6);
            } else {
                apply_policy_override(effective, p);
            }
        }
    }

    p = bpf_map_lookup_elem(&ip_policies, key);
    if (p) {
        if (p->expires_at_ns && p->expires_at_ns < now) {
            bpf_map_delete_elem(&ip_policies, key);
        } else {
            apply_policy_override(effective, p);
        }
    }
}

static __always_inline int parse_l4_dport(__u8 ip_proto,
                       void *l4,
                       void *data_end,
                       __u8 l4_parsable,
                       __u16 *dport)
{
    if (!l4_parsable)
        return -1;

    if (ip_proto == IPPROTO_TCP) {
        struct tcphdr *tcph = l4;
        if ((void *)(tcph + 1) > data_end)
            return -1;
        *dport = bpf_ntohs(tcph->dest);
        return 0;
    }

    if (ip_proto == IPPROTO_UDP) {
        struct udphdr *udph = l4;
        if ((void *)(udph + 1) > data_end)
            return -1;
        *dport = bpf_ntohs(udph->dest);
        return 0;
    }

    return -1;
}

static __always_inline int parse_tcp(void *l4, void *data_end,
                     __u8 *is_syn,
                     __u8 *is_rst,
                     __u8 *is_ack_only,
                     __u8 *is_weird,
                     __u16 *dport)
{
    struct tcphdr *tcph = l4;
    __u32 hdr_len;
    __u32 payload_len;
    __u8 syn;
    __u8 ack;
    __u8 fin;
    __u8 rst;

    if ((void *)(tcph + 1) > data_end)
        return -1;

    hdr_len = tcph->doff * 4;
    if (hdr_len < sizeof(*tcph) || (void *)tcph + hdr_len > data_end)
        return -1;

    *dport = bpf_ntohs(tcph->dest);
    syn = tcph->syn;
    ack = tcph->ack;
    fin = tcph->fin;
    rst = tcph->rst;
    payload_len = (__u32)((long)data_end - ((long)tcph + hdr_len));

    *is_syn = syn && !ack;
    *is_rst = rst;
    *is_ack_only = ack && !syn && !fin && !rst && payload_len <= 16;
    *is_weird = (syn && fin) || (syn && rst) || (!syn && !ack && !fin && !rst &&
               !tcph->psh && !tcph->urg);
    return 0;
}

static __always_inline int parse_udp(void *l4, void *data_end,
                     __u16 *sport,
                     __u16 *dport,
                     __u16 *len)
{
    struct udphdr *udph = l4;

    if ((void *)(udph + 1) > data_end)
        return -1;

    *sport = bpf_ntohs(udph->source);
    *dport = bpf_ntohs(udph->dest);
    *len = bpf_ntohs(udph->len);
    return 0;
}

static __always_inline void set_key_v4(struct ip_key *key, __be32 saddr)
{
    __builtin_memset(key, 0, sizeof(*key));
    key->family = XDP_DDOS_FAMILY_V4;
    key->addr.v4 = saddr;
}

static __always_inline void set_key_v6(struct ip_key *key, const __u8 *saddr)
{
    __builtin_memset(key, 0, sizeof(*key));
    key->family = XDP_DDOS_FAMILY_V6;
    __builtin_memcpy(key->addr.v6, saddr, 16);
}

SEC("xdp")
int xdp_ddos_filter(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    struct global_cfg *cfg;
    struct ip_state *state;
    struct ip_state zero = {};
    struct ip_policy effective_policy;
    struct ip_key key;
    __u64 now = bpf_ktime_get_ns();
    __u32 cfg_key = 0;
    __u16 eth_proto;
    void *l3;
    void *l4;
    __u8 ip_proto;
    __u32 pkt_len;
    __u16 dport = 0;
    __u16 sport = 0;
    __u16 udp_len = 0;
    __u8 is_syn = 0;
    __u8 is_rst = 0;
    __u8 is_ack_only = 0;
    __u8 is_weird = 0;
    __u32 spread_bin;
    __u64 spread_mask;
    __u32 action = DDOS_ACTION_ADAPTIVE;
    __u8 l4_parsable = 1;

    if ((void *)(eth + 1) > data_end)
        return XDP_ABORTED;

    eth_proto = bpf_ntohs(eth->h_proto);
    l3 = (void *)(eth + 1);

    if (eth_proto == ETH_P_IP) {
        struct iphdr *iph = l3;

        if ((void *)(iph + 1) > data_end)
            goto parse_error;
        if (iph->ihl < 5)
            goto parse_error;
        if ((void *)iph + (iph->ihl * 4) > data_end)
            goto parse_error;

        if (bpf_ntohs(iph->frag_off) & 0x1FFF)
            l4_parsable = 0;

        set_key_v4(&key, iph->saddr);
        ip_proto = iph->protocol;
        l4 = (void *)iph + (iph->ihl * 4);
    } else if (eth_proto == ETH_P_IPV6) {
        struct ipv6hdr *ip6h = l3;

        if ((void *)(ip6h + 1) > data_end)
            goto parse_error;

        set_key_v6(&key, ip6h->saddr.s6_addr);
        ip_proto = ip6h->nexthdr;
        l4 = (void *)(ip6h + 1);
    } else {
        stat_inc(STAT_PASS);
        return XDP_PASS;
    }

    cfg = bpf_map_lookup_elem(&global_config, &cfg_key);
    if (!cfg)
        return XDP_PASS;

    if (parse_l4_dport(ip_proto, l4, data_end, l4_parsable, &dport) < 0)
        dport = 0;

    resolve_policies(&key, ip_proto, dport, now, &effective_policy);
    action = effective_policy.action;

    if (action == DDOS_ACTION_DROP) {
        stat_inc(STAT_DROP_POLICY);
        return XDP_DROP;
    }
    if (action == DDOS_ACTION_PASS) {
        stat_inc(STAT_PASS);
        return XDP_PASS;
    }

    state = bpf_map_lookup_elem(&ip_states, &key);
    if (!state) {
        bpf_map_update_elem(&ip_states, &key, &zero, BPF_NOEXIST);
        state = bpf_map_lookup_elem(&ip_states, &key);
        if (!state)
            return XDP_PASS;
        state->window_start_ns = now;
    }

    if (state->drop_until_ns > now) {
        stat_inc(STAT_DROP_MITIGATED);
        return XDP_DROP;
    }

    if ((now - state->window_start_ns) > XDP_DDOS_WINDOW_NS) {
        if (eval_completed_window(state, &key, cfg, &effective_policy,
                      state->last_dport, now)) {
            stat_inc(STAT_DROP_MITIGATED);
            reset_window_state(state, now);
            return XDP_DROP;
        }

        reset_window_state(state, now);
    }

    pkt_len = (__u32)((long)data_end - (long)data);
    state->pkt_count++;
    state->byte_count += pkt_len;
    state->last_seen_ns = now;

    if (ip_proto == IPPROTO_TCP && l4_parsable) {
        if (parse_tcp(l4, data_end, &is_syn, &is_rst, &is_ack_only, &is_weird,
                  &dport) == 0) {
            state->last_dport = dport;
            if (is_syn)
                state->syn_count++;
            if (is_rst)
                state->rst_count++;
            if (is_ack_only)
                state->ack_only_count++;
            if (is_weird)
                state->tcp_weird_count++;

            spread_bin = dport & 63;
            spread_mask = (__u64)1 << spread_bin;
            if (!(state->dst_port_bits & spread_mask)) {
                state->dst_port_bits |= spread_mask;
                state->dst_port_spread = bit_count64(state->dst_port_bits);
            }
        }
    } else if (ip_proto == IPPROTO_UDP && l4_parsable) {
        if (parse_udp(l4, data_end, &sport, &dport, &udp_len) == 0) {
            state->last_dport = dport;
            state->udp_count++;
            if (dport >= 1024)
                state->udp_high_port_count++;

            if (sport == 53 && pkt_len >= cfg->dns_amp_min_bytes && udp_len >= 300)
                state->dns_resp_like_count++;

            if (is_udp_amp_source_port(sport) && udp_len >= 180)
                state->udp_amp_like_count++;

            spread_bin = dport & 63;
            spread_mask = (__u64)1 << spread_bin;
            if (!(state->dst_port_bits & spread_mask)) {
                state->dst_port_bits |= spread_mask;
                state->dst_port_spread = bit_count64(state->dst_port_bits);
            }
        }
    } else if (ip_proto == IPPROTO_ICMP || ip_proto == IPPROTO_ICMPV6) {
        state->icmp_count++;
    }

    if (state->warmup_seen >= cfg->warmup_windows &&
        emergency_guard(state, &key, cfg, &effective_policy, now))
        return XDP_DROP;

    stat_inc(STAT_PASS);
    return XDP_PASS;

parse_error:
    stat_inc(STAT_PARSE_ERROR);
    return XDP_DROP;
}
