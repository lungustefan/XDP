#include "common.h"

#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_link.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/if.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define PIN_BASE "/sys/fs/bpf/xdp_ddos"
#define OBJ_FILE "src/xdp_ddos_kern.o"

static volatile bool keep_running = true;
static bool g_json_output = false;

static void on_sigint(int signo)
{
    (void)signo;
    keep_running = false;
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage:\n"
        "  %s [--json] <command> ...\n"
        "  %s load <iface> [rules.conf]\n"
        "  %s unload <iface>\n"
        "  %s stats\n"
        "  %s monitor [interval_sec]\n"
        "  %s log <output.jsonl> [poll_ms]\n"
        "  %s state top [n]\n"
        "  %s defaults show\n"
        "  %s defaults set <anomaly_mult_pct> <score_threshold> <block_ttl_sec> <offenses> <auto_mitigation> <warmup_windows> <ack_ratio_pct> <rst_ratio_pct> <syn_ratio_pct> <dns_ratio_pct> <dns_min_bytes> <udp_spread_bins> <scan_spread_bins> <udp_amp_ratio_pct> <icmp_ratio_pct> <block_min_score> <block_min_reasons> [emergency_cooldown_sec] [service_relax_dns_pct] [service_relax_http_pct] [service_relax_https_pct] [service_relax_ntp_pct]\n"
        "  %s policy add <ip(v4|v6)> <action(pass|adaptive|drop)> [anomaly_mult_pct] [score_threshold] [block_ttl_sec] [ttl_sec]\n"
        "  %s policy del <ip(v4|v6)>\n"
        "  %s policy list\n"
        "  %s subnet add <cidr(v4|v6)> <action(pass|adaptive|drop)> [anomaly_mult_pct] [score_threshold] [block_ttl_sec] [ttl_sec]\n"
        "  %s subnet del <cidr(v4|v6)>\n"
        "  %s subnet list\n"
        "  %s port add <proto(tcp|udp)> <port> <action(pass|adaptive|drop)> [anomaly_mult_pct] [score_threshold] [block_ttl_sec] [ttl_sec]\n"
        "  %s port del <proto(tcp|udp)> <port>\n"
        "  %s port list\n",
        prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog,
        prog, prog, prog, prog, prog, prog, prog);
}

static int parse_action(const char *s)
{
    if (!strcmp(s, "pass"))
        return DDOS_ACTION_PASS;
    if (!strcmp(s, "adaptive"))
        return DDOS_ACTION_ADAPTIVE;
    if (!strcmp(s, "drop"))
        return DDOS_ACTION_DROP;
    return -1;
}

static const char *action_to_str(__u32 action)
{
    switch (action) {
    case DDOS_ACTION_PASS:
        return "pass";
    case DDOS_ACTION_ADAPTIVE:
        return "adaptive";
    case DDOS_ACTION_DROP:
        return "drop";
    default:
        return "unknown";
    }
}

static int parse_proto(const char *s)
{
    if (!strcmp(s, "tcp"))
        return IPPROTO_TCP;
    if (!strcmp(s, "udp"))
        return IPPROTO_UDP;
    return -1;
}

static int bump_memlock(void)
{
    struct rlimit rlim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    return setrlimit(RLIMIT_MEMLOCK, &rlim);
}

static int ensure_pin_base(void)
{
    if (mkdir(PIN_BASE, 0700) < 0 && errno != EEXIST) {
        fprintf(stderr, "failed to create %s: %s\n", PIN_BASE, strerror(errno));
        return -1;
    }

    return 0;
}

static int open_pinned_map(const char *name)
{
    char path[256];

    snprintf(path, sizeof(path), "%s/%s", PIN_BASE, name);
    return bpf_obj_get(path);
}

static int parse_ip_any(const char *s, struct ip_key *key)
{
    __be32 v4;

    memset(key, 0, sizeof(*key));
    if (inet_pton(AF_INET, s, &v4) == 1) {
        key->family = XDP_DDOS_FAMILY_V4;
        key->addr.v4 = v4;
        return 0;
    }

    if (inet_pton(AF_INET6, s, key->addr.v6) == 1) {
        key->family = XDP_DDOS_FAMILY_V6;
        return 0;
    }

    return -1;
}

static int parse_cidr_v4(const char *s, struct lpm_v4_key *k)
{
    char buf[64];
    char *slash;
    int prefix;

    if (strlen(s) >= sizeof(buf))
        return -1;

    strcpy(buf, s);
    slash = strchr(buf, '/');
    if (!slash)
        return -1;
    *slash = '\0';
    prefix = atoi(slash + 1);
    if (prefix < 0 || prefix > 32)
        return -1;
    if (inet_pton(AF_INET, buf, &k->addr) != 1)
        return -1;
    k->prefixlen = (__u32)prefix;
    return 0;
}

static int parse_cidr_v6(const char *s, struct lpm_v6_key *k)
{
    char buf[96];
    char *slash;
    int prefix;

    if (strlen(s) >= sizeof(buf))
        return -1;

    strcpy(buf, s);
    slash = strchr(buf, '/');
    if (!slash)
        return -1;
    *slash = '\0';
    prefix = atoi(slash + 1);
    if (prefix < 0 || prefix > 128)
        return -1;
    if (inet_pton(AF_INET6, buf, k->addr) != 1)
        return -1;
    k->prefixlen = (__u32)prefix;
    return 0;
}

static const char *ip_key_to_str(const struct ip_key *key, char *buf, size_t len)
{
    if (key->family == XDP_DDOS_FAMILY_V4)
        return inet_ntop(AF_INET, &key->addr.v4, buf, len);
    if (key->family == XDP_DDOS_FAMILY_V6)
        return inet_ntop(AF_INET6, key->addr.v6, buf, len);
    snprintf(buf, len, "<unknown>");
    return buf;
}

static int set_defaults(const struct global_cfg *cfg)
{
    int fd = open_pinned_map("global_config");
    __u32 key = 0;

    if (fd < 0) {
        fprintf(stderr, "failed to open global_config: %s\n", strerror(errno));
        return -1;
    }

    if (bpf_map_update_elem(fd, &key, cfg, BPF_ANY) < 0) {
        fprintf(stderr, "failed to set defaults: %s\n", strerror(errno));
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}

static int show_defaults(void)
{
    int fd = open_pinned_map("global_config");
    struct global_cfg cfg;
    __u32 key = 0;

    if (fd < 0) {
        fprintf(stderr, "failed to open global_config: %s\n", strerror(errno));
        return -1;
    }

    if (bpf_map_lookup_elem(fd, &key, &cfg) < 0) {
        fprintf(stderr, "failed to read defaults: %s\n", strerror(errno));
        close(fd);
        return -1;
    }

    close(fd);

    if (g_json_output) {
        printf("{\"anomaly_mult\":%u,\"score_threshold\":%u,\"block_ttl\":%u,\"offenses\":%u,\"auto\":%u,\"warmup\":%u,\"ack_ratio\":%u,\"rst_ratio\":%u,\"syn_ratio\":%u,\"dns_ratio\":%u,\"dns_min_bytes\":%u,\"udp_spread\":%u,\"scan_spread\":%u,\"udp_amp_ratio\":%u,\"icmp_ratio\":%u,\"block_min_score\":%u,\"block_min_reasons\":%u,\"emergency_cooldown_sec\":%u,\"service_relax_dns_pct\":%u,\"service_relax_http_pct\":%u,\"service_relax_https_pct\":%u,\"service_relax_ntp_pct\":%u}\n",
            cfg.anomaly_mult_pct,
            cfg.score_threshold,
            cfg.block_ttl_sec,
            cfg.offense_threshold,
            cfg.auto_mitigation,
            cfg.warmup_windows,
            cfg.ack_only_ratio_pct,
            cfg.rst_ratio_pct,
            cfg.syn_ratio_pct,
            cfg.dns_resp_ratio_pct,
            cfg.dns_amp_min_bytes,
            cfg.udp_random_spread_bins,
            cfg.scan_spread_bins,
            cfg.udp_amp_ratio_pct,
            cfg.icmp_ratio_pct,
            cfg.block_min_score,
            cfg.block_min_reasons,
            cfg.emergency_cooldown_sec,
            cfg.service_relax_dns_pct,
            cfg.service_relax_http_pct,
            cfg.service_relax_https_pct,
            cfg.service_relax_ntp_pct);
    } else {
        printf("defaults: anomaly_mult=%u score_threshold=%u block_ttl=%u offenses=%u auto=%u warmup=%u ack_ratio=%u rst_ratio=%u syn_ratio=%u dns_ratio=%u dns_min_bytes=%u udp_spread=%u scan_spread=%u udp_amp_ratio=%u icmp_ratio=%u block_min_score=%u block_min_reasons=%u emergency_cooldown_sec=%u service_relax_dns_pct=%u service_relax_http_pct=%u service_relax_https_pct=%u service_relax_ntp_pct=%u\n",
            cfg.anomaly_mult_pct,
            cfg.score_threshold,
            cfg.block_ttl_sec,
            cfg.offense_threshold,
            cfg.auto_mitigation,
            cfg.warmup_windows,
            cfg.ack_only_ratio_pct,
            cfg.rst_ratio_pct,
            cfg.syn_ratio_pct,
            cfg.dns_resp_ratio_pct,
            cfg.dns_amp_min_bytes,
            cfg.udp_random_spread_bins,
            cfg.scan_spread_bins,
            cfg.udp_amp_ratio_pct,
            cfg.icmp_ratio_pct,
            cfg.block_min_score,
            cfg.block_min_reasons,
            cfg.emergency_cooldown_sec,
            cfg.service_relax_dns_pct,
            cfg.service_relax_http_pct,
            cfg.service_relax_https_pct,
            cfg.service_relax_ntp_pct);
    }

    return 0;
}

static int apply_policy(const struct ip_key *key, const struct ip_policy *p)
{
    int fd = open_pinned_map("ip_policies");

    if (fd < 0) {
        fprintf(stderr, "failed to open ip_policies: %s\n", strerror(errno));
        return -1;
    }

    if (bpf_map_update_elem(fd, key, p, BPF_ANY) < 0) {
        fprintf(stderr, "failed to update policy: %s\n", strerror(errno));
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}

static int apply_subnet_policy(const char *cidr, const struct ip_policy *p)
{
    struct lpm_v4_key k4;
    struct lpm_v6_key k6;
    int fd;

    if (strchr(cidr, ':')) {
        if (parse_cidr_v6(cidr, &k6) < 0)
            return -1;
        fd = open_pinned_map("subnet_policies_v6");
        if (fd < 0)
            return -1;
        if (bpf_map_update_elem(fd, &k6, p, BPF_ANY) < 0) {
            close(fd);
            return -1;
        }
        close(fd);
        return 0;
    }

    if (parse_cidr_v4(cidr, &k4) < 0)
        return -1;
    fd = open_pinned_map("subnet_policies_v4");
    if (fd < 0)
        return -1;
    if (bpf_map_update_elem(fd, &k4, p, BPF_ANY) < 0) {
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

static int delete_subnet_policy(const char *cidr)
{
    struct lpm_v4_key k4;
    struct lpm_v6_key k6;
    int fd;

    if (strchr(cidr, ':')) {
        if (parse_cidr_v6(cidr, &k6) < 0)
            return -1;
        fd = open_pinned_map("subnet_policies_v6");
        if (fd < 0)
            return -1;
        if (bpf_map_delete_elem(fd, &k6) < 0) {
            close(fd);
            return -1;
        }
        close(fd);
        return 0;
    }

    if (parse_cidr_v4(cidr, &k4) < 0)
        return -1;
    fd = open_pinned_map("subnet_policies_v4");
    if (fd < 0)
        return -1;
    if (bpf_map_delete_elem(fd, &k4) < 0) {
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

static int apply_port_policy(int proto, __u16 port, const struct ip_policy *p)
{
    struct port_key key = {
        .proto = (__u8)proto,
        .port = htons(port),
    };
    int fd = open_pinned_map("port_policies");

    if (fd < 0)
        return -1;
    if (bpf_map_update_elem(fd, &key, p, BPF_ANY) < 0) {
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

static int delete_port_policy(int proto, __u16 port)
{
    struct port_key key = {
        .proto = (__u8)proto,
        .port = htons(port),
    };
    int fd = open_pinned_map("port_policies");

    if (fd < 0)
        return -1;
    if (bpf_map_delete_elem(fd, &key) < 0) {
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

struct top_state {
    struct ip_key key;
    struct ip_state state;
};

static void maybe_insert_top(struct top_state *top, int *used, int cap,
                 const struct ip_key *key,
                 const struct ip_state *state)
{
    int i;
    int pos = -1;

    for (i = 0; i < *used; i++) {
        if (state->pkt_count > top[i].state.pkt_count ||
            (state->pkt_count == top[i].state.pkt_count &&
             state->byte_count > top[i].state.byte_count)) {
            pos = i;
            break;
        }
    }

    if (pos < 0 && *used < cap)
        pos = *used;

    if (pos < 0)
        return;

    if (*used < cap)
        (*used)++;

    for (i = *used - 1; i > pos; i--)
        top[i] = top[i - 1];

    top[pos].key = *key;
    top[pos].state = *state;
}

static int print_top_states(int n)
{
    int fd = open_pinned_map("ip_states");
    struct ip_key key;
    struct ip_key next;
    struct ip_state st;
    struct top_state top[128];
    int used = 0;
    int i;
    char ipbuf[INET6_ADDRSTRLEN];

    if (n <= 0)
        n = 20;
    if (n > 128)
        n = 128;

    if (fd < 0) {
        fprintf(stderr, "failed to open ip_states: %s\n", strerror(errno));
        return -1;
    }

    if (bpf_map_get_next_key(fd, NULL, &next) == 0) {
        do {
            if (bpf_map_lookup_elem(fd, &next, &st) == 0)
                maybe_insert_top(top, &used, n, &next, &st);
            key = next;
        } while (bpf_map_get_next_key(fd, &key, &next) == 0);
    }

    close(fd);

    if (g_json_output)
        printf("{\"items\":[");
    else
        printf("top_sources:\n");

    for (i = 0; i < used; i++) {
        bool blocked;

        ip_key_to_str(&top[i].key, ipbuf, sizeof(ipbuf));
        blocked = top[i].state.drop_until_ns > (__u64)time(NULL) * 1000000000ULL;
        if (g_json_output) {
            if (i)
                printf(",");
            printf("{\"ip\":\"%s\",\"pps\":%u,\"bps\":%u,\"syn\":%u,\"rst\":%u,\"ack_only\":%u,\"udp\":%u,\"icmp\":%u,\"offenses\":%u,\"blocked\":%s}",
                ipbuf,
                top[i].state.pkt_count,
                top[i].state.byte_count,
                top[i].state.syn_count,
                top[i].state.rst_count,
                top[i].state.ack_only_count,
                top[i].state.udp_count,
                top[i].state.icmp_count,
                top[i].state.offense_count,
                blocked ? "true" : "false");
        } else {
            printf("  %s pps=%u bps=%u syn=%u rst=%u ack_only=%u udp=%u icmp=%u offenses=%u blocked=%s\n",
                ipbuf,
                top[i].state.pkt_count,
                top[i].state.byte_count,
                top[i].state.syn_count,
                top[i].state.rst_count,
                top[i].state.ack_only_count,
                top[i].state.udp_count,
                top[i].state.icmp_count,
                top[i].state.offense_count,
                blocked ? "yes" : "no");
        }
    }

    if (g_json_output)
        printf("]}\n");

    return 0;
}

static int delete_policy(const struct ip_key *key)
{
    int fd = open_pinned_map("ip_policies");

    if (fd < 0) {
        fprintf(stderr, "failed to open ip_policies: %s\n", strerror(errno));
        return -1;
    }

    if (bpf_map_delete_elem(fd, key) < 0) {
        fprintf(stderr, "failed to delete policy: %s\n", strerror(errno));
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}

static int list_policies(void)
{
    int fd = open_pinned_map("ip_policies");
    struct ip_key key;
    struct ip_key next_key;
    struct ip_policy p;
    char ipbuf[INET6_ADDRSTRLEN];
    time_t now = time(NULL);

    if (fd < 0) {
        fprintf(stderr, "failed to open ip_policies: %s\n", strerror(errno));
        return -1;
    }

    if (g_json_output)
        printf("{\"items\":[");
    else
        printf("IP policies:\n");

    if (bpf_map_get_next_key(fd, NULL, &next_key) == 0) {
        int emitted = 0;
        do {
            if (bpf_map_lookup_elem(fd, &next_key, &p) == 0) {
                __u64 now_ns = (__u64)now * 1000000000ULL;
                long long ttl_left = -1;

                ip_key_to_str(&next_key, ipbuf, sizeof(ipbuf));
                if (p.expires_at_ns) {
                    if (p.expires_at_ns > now_ns)
                        ttl_left = (long long)((p.expires_at_ns - now_ns) / 1000000000ULL);
                    else
                        ttl_left = 0;
                }

                if (g_json_output) {
                    if (emitted++)
                        printf(",");
                    printf("{\"scope\":\"ip\",\"target\":\"%s\",\"action\":\"%s\",\"anomaly_mult_pct\":%u,\"score_threshold\":%u,\"block_ttl_sec\":%u,\"ttl_sec\":%lld}",
                        ipbuf,
                        action_to_str(p.action),
                        p.anomaly_mult_pct,
                        p.score_threshold,
                        p.block_ttl_sec,
                        ttl_left);
                } else {
                    printf("  %s action=%s anomaly_mult=%u score=%u block_ttl=%u",
                        ipbuf,
                        action_to_str(p.action),
                        p.anomaly_mult_pct,
                        p.score_threshold,
                        p.block_ttl_sec);
                    if (p.expires_at_ns) {
                        if (ttl_left > 0)
                            printf(" ttl=%lld", ttl_left);
                        else
                            printf(" ttl=expired");
                    }
                    printf("\n");
                }
            }
            key = next_key;
        } while (bpf_map_get_next_key(fd, &key, &next_key) == 0);
    }

    if (g_json_output)
        printf("]}\n");

    close(fd);
    return 0;
}

static int list_subnets_v4(void)
{
    int fd = open_pinned_map("subnet_policies_v4");
    struct lpm_v4_key key;
    struct lpm_v4_key next;
    struct ip_policy p;
    char ipbuf[INET_ADDRSTRLEN];

    if (fd < 0)
        return -1;

    while (bpf_map_get_next_key(fd, NULL, &next) == 0) {
        do {
            if (bpf_map_lookup_elem(fd, &next, &p) == 0) {
                inet_ntop(AF_INET, &next.addr, ipbuf, sizeof(ipbuf));
                printf("  %s/%u action=%s anomaly_mult=%u score=%u block_ttl=%u\n",
                    ipbuf, next.prefixlen, action_to_str(p.action),
                    p.anomaly_mult_pct, p.score_threshold, p.block_ttl_sec);
            }
            key = next;
        } while (bpf_map_get_next_key(fd, &key, &next) == 0);
        break;
    }

    close(fd);
    return 0;
}

static int list_subnets_v6(void)
{
    int fd = open_pinned_map("subnet_policies_v6");
    struct lpm_v6_key key;
    struct lpm_v6_key next;
    struct ip_policy p;
    char ipbuf[INET6_ADDRSTRLEN];

    if (fd < 0)
        return -1;

    while (bpf_map_get_next_key(fd, NULL, &next) == 0) {
        do {
            if (bpf_map_lookup_elem(fd, &next, &p) == 0) {
                inet_ntop(AF_INET6, next.addr, ipbuf, sizeof(ipbuf));
                printf("  %s/%u action=%s anomaly_mult=%u score=%u block_ttl=%u\n",
                    ipbuf, next.prefixlen, action_to_str(p.action),
                    p.anomaly_mult_pct, p.score_threshold, p.block_ttl_sec);
            }
            key = next;
        } while (bpf_map_get_next_key(fd, &key, &next) == 0);
        break;
    }

    close(fd);
    return 0;
}

static int list_subnets(void)
{
    printf("Subnet policies:\n");
    list_subnets_v4();
    list_subnets_v6();
    return 0;
}

static int list_ports(void)
{
    int fd = open_pinned_map("port_policies");
    struct port_key key;
    struct port_key next;
    struct ip_policy p;

    if (fd < 0)
        return -1;

    printf("Port policies:\n");
    while (bpf_map_get_next_key(fd, NULL, &next) == 0) {
        do {
            if (bpf_map_lookup_elem(fd, &next, &p) == 0) {
                printf("  %s/%u action=%s anomaly_mult=%u score=%u block_ttl=%u\n",
                    next.proto == IPPROTO_TCP ? "tcp" :
                    (next.proto == IPPROTO_UDP ? "udp" : "other"),
                    (unsigned)ntohs(next.port),
                    action_to_str(p.action),
                    p.anomaly_mult_pct,
                    p.score_threshold,
                    p.block_ttl_sec);
            }
            key = next;
        } while (bpf_map_get_next_key(fd, &key, &next) == 0);
        break;
    }

    close(fd);
    return 0;
}

static int print_stats_once(void)
{
    int fd = open_pinned_map("stats");
    int ncpu = libbpf_num_possible_cpus();
    __u64 values[STAT_MAX][256];
    __u64 total[STAT_MAX] = {};
    __u32 key;
    int cpu;

    if (ncpu <= 0 || ncpu > 256) {
        fprintf(stderr, "unexpected cpu count: %d\n", ncpu);
        return -1;
    }

    if (fd < 0) {
        fprintf(stderr, "failed to open stats: %s\n", strerror(errno));
        return -1;
    }

    for (key = 0; key < STAT_MAX; key++) {
        if (bpf_map_lookup_elem(fd, &key, values[key]) < 0)
            continue;

        for (cpu = 0; cpu < ncpu; cpu++)
            total[key] += values[key][cpu];
    }

    close(fd);

    if (g_json_output) {
        printf("{\"pass\":%llu,\"drop_policy\":%llu,\"drop_suspicious\":%llu,\"drop_mitigated\":%llu,\"mitigation_set\":%llu,\"parse_error\":%llu,\"dns_amp\":%llu,\"ack_flood\":%llu,\"udp_random\":%llu,\"port_scan\":%llu,\"rst_flood\":%llu,\"syn_flood\":%llu,\"udp_amp\":%llu,\"icmp_flood\":%llu,\"tcp_weird\":%llu,\"event_drop\":%llu,\"monitor_only\":%llu,\"drop_emergency\":%llu}\n",
            (unsigned long long)total[STAT_PASS],
            (unsigned long long)total[STAT_DROP_POLICY],
            (unsigned long long)total[STAT_DROP_SUSPICIOUS],
            (unsigned long long)total[STAT_DROP_MITIGATED],
            (unsigned long long)total[STAT_MITIGATION_SET],
            (unsigned long long)total[STAT_PARSE_ERROR],
            (unsigned long long)total[STAT_DNS_AMP],
            (unsigned long long)total[STAT_ACK_FLOOD],
            (unsigned long long)total[STAT_UDP_RANDOM],
            (unsigned long long)total[STAT_PORT_SCAN],
            (unsigned long long)total[STAT_RST_FLOOD],
            (unsigned long long)total[STAT_SYN_FLOOD],
            (unsigned long long)total[STAT_UDP_AMP],
            (unsigned long long)total[STAT_ICMP_FLOOD],
            (unsigned long long)total[STAT_TCP_WEIRD],
            (unsigned long long)total[STAT_EVENT_DROP],
            (unsigned long long)total[STAT_MONITOR_ONLY],
            (unsigned long long)total[STAT_DROP_EMERGENCY]);
    } else {
        printf("stats: pass=%llu drop_policy=%llu drop_suspicious=%llu drop_mitigated=%llu mitigation_set=%llu parse_error=%llu dns_amp=%llu ack_flood=%llu udp_random=%llu port_scan=%llu rst_flood=%llu syn_flood=%llu udp_amp=%llu icmp_flood=%llu tcp_weird=%llu event_drop=%llu monitor_only=%llu drop_emergency=%llu\n",
            (unsigned long long)total[STAT_PASS],
            (unsigned long long)total[STAT_DROP_POLICY],
            (unsigned long long)total[STAT_DROP_SUSPICIOUS],
            (unsigned long long)total[STAT_DROP_MITIGATED],
            (unsigned long long)total[STAT_MITIGATION_SET],
            (unsigned long long)total[STAT_PARSE_ERROR],
            (unsigned long long)total[STAT_DNS_AMP],
            (unsigned long long)total[STAT_ACK_FLOOD],
            (unsigned long long)total[STAT_UDP_RANDOM],
            (unsigned long long)total[STAT_PORT_SCAN],
            (unsigned long long)total[STAT_RST_FLOOD],
            (unsigned long long)total[STAT_SYN_FLOOD],
            (unsigned long long)total[STAT_UDP_AMP],
            (unsigned long long)total[STAT_ICMP_FLOOD],
            (unsigned long long)total[STAT_TCP_WEIRD],
            (unsigned long long)total[STAT_EVENT_DROP],
            (unsigned long long)total[STAT_MONITOR_ONLY],
            (unsigned long long)total[STAT_DROP_EMERGENCY]);
    }

    return 0;
}

static int monitor_loop(int interval)
{
    if (interval <= 0)
        interval = 2;

    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);

    while (keep_running) {
        if (print_stats_once() < 0)
            return -1;
        sleep(interval);
    }

    return 0;
}

static int parse_kv_u32(const char *token, const char *name, __u32 *dst)
{
    size_t n = strlen(name);

    if (strncmp(token, name, n) || token[n] != '=')
        return -1;

    *dst = (__u32)strtoul(token + n + 1, NULL, 10);
    return 0;
}

static const char *reason_to_str(__u32 reason_mask, char *buf, size_t len)
{
    size_t off = 0;

    buf[0] = '\0';
    if (reason_mask & XDP_DDOS_REASON_ANOMALY_RATE)
        off += snprintf(buf + off, len - off, "%sanomaly", off ? "|" : "");
    if (reason_mask & XDP_DDOS_REASON_DNS_AMP)
        off += snprintf(buf + off, len - off, "%sdns_amp", off ? "|" : "");
    if (reason_mask & XDP_DDOS_REASON_ACK_FLOOD)
        off += snprintf(buf + off, len - off, "%sack_flood", off ? "|" : "");
    if (reason_mask & XDP_DDOS_REASON_UDP_RANDOM)
        off += snprintf(buf + off, len - off, "%sudp_random", off ? "|" : "");
    if (reason_mask & XDP_DDOS_REASON_PORT_SCAN)
        off += snprintf(buf + off, len - off, "%sport_scan", off ? "|" : "");
    if (reason_mask & XDP_DDOS_REASON_RST_FLOOD)
        off += snprintf(buf + off, len - off, "%srst_flood", off ? "|" : "");
    if (reason_mask & XDP_DDOS_REASON_SYN_FLOOD)
        off += snprintf(buf + off, len - off, "%ssyn_flood", off ? "|" : "");
    if (reason_mask & XDP_DDOS_REASON_UDP_AMP)
        off += snprintf(buf + off, len - off, "%sudp_amp", off ? "|" : "");
    if (reason_mask & XDP_DDOS_REASON_ICMP_FLOOD)
        off += snprintf(buf + off, len - off, "%sicmp_flood", off ? "|" : "");
    if (reason_mask & XDP_DDOS_REASON_TCP_WEIRD)
        off += snprintf(buf + off, len - off, "%stcp_weird", off ? "|" : "");
    if (reason_mask & XDP_DDOS_REASON_EMERGENCY)
        off += snprintf(buf + off, len - off, "%semergency", off ? "|" : "");
    if (!off)
        snprintf(buf, len, "none");
    return buf;
}

struct log_ctx {
    FILE *fp;
};

static int on_event(void *ctx, void *data, size_t data_sz)
{
    struct log_ctx *lctx = ctx;
    const struct ddos_event *e = data;
    char ipbuf[INET6_ADDRSTRLEN];
    char reason[128];

    (void)data_sz;
    ip_key_to_str(&e->src, ipbuf, sizeof(ipbuf));
    reason_to_str(e->reason_mask, reason, sizeof(reason));

    fprintf(lctx->fp,
        "{\"ts_ns\":%llu,\"src\":\"%s\",\"action\":\"%s\",\"reason\":\"%s\",\"score\":%u,\"pps\":%u,\"bytes\":%u,\"syn\":%u,\"ack_only\":%u,\"udp\":%u,\"udp_spread\":%u,\"block_ttl\":%u}\n",
        (unsigned long long)e->ts_ns,
        ipbuf,
        action_to_str(e->action),
        reason,
        e->score,
        e->pkt_count,
        e->byte_count,
        e->syn_count,
        e->ack_only_count,
        e->udp_count,
        e->udp_spread,
        e->block_ttl_sec);
    fflush(lctx->fp);

    printf("event src=%s action=%s reason=%s score=%u\n",
        ipbuf, action_to_str(e->action), reason, e->score);
    return 0;
}

static int log_loop(const char *path, int poll_ms)
{
    int events_fd;
    struct ring_buffer *rb;
    struct log_ctx lctx = {};

    if (poll_ms <= 0)
        poll_ms = 250;

    events_fd = open_pinned_map("events");
    if (events_fd < 0) {
        fprintf(stderr, "failed to open events map: %s\n", strerror(errno));
        return -1;
    }

    lctx.fp = fopen(path, "a");
    if (!lctx.fp) {
        fprintf(stderr, "failed to open log file %s: %s\n", path, strerror(errno));
        close(events_fd);
        return -1;
    }

    rb = ring_buffer__new(events_fd, on_event, &lctx, NULL);
    if (!rb) {
        fprintf(stderr, "failed to create ring buffer\n");
        fclose(lctx.fp);
        close(events_fd);
        return -1;
    }

    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);

    while (keep_running) {
        int rc = ring_buffer__poll(rb, poll_ms);
        if (rc < 0 && rc != -EINTR) {
            fprintf(stderr, "ring buffer poll error: %d\n", rc);
            break;
        }
    }

    ring_buffer__free(rb);
    fclose(lctx.fp);
    close(events_fd);
    return 0;
}

static int apply_rules_file(const char *path)
{
    FILE *f = fopen(path, "r");
    char line[512];
    int line_no = 0;

    if (!f) {
        fprintf(stderr, "failed to open rules file %s: %s\n", path, strerror(errno));
        return -1;
    }

    while (fgets(line, sizeof(line), f)) {
        char *tok;
        char *ctx = NULL;

        line_no++;
        tok = strtok_r(line, " \t\r\n", &ctx);
        if (!tok || tok[0] == '#')
            continue;

        if (!strcmp(tok, "default")) {
            struct global_cfg cfg = {
                .anomaly_mult_pct = XDP_DDOS_DEFAULT_ANOMALY_MULT_PCT,
                .score_threshold = XDP_DDOS_DEFAULT_SCORE_THRESHOLD,
                .block_ttl_sec = XDP_DDOS_DEFAULT_BLOCK_TTL_SEC,
                .offense_threshold = XDP_DDOS_DEFAULT_OFFENSES,
                .auto_mitigation = 1,
                .warmup_windows = XDP_DDOS_DEFAULT_WARMUP_WINDOWS,
                .ewma_shift = 3,
                .ack_only_ratio_pct = XDP_DDOS_DEFAULT_ACK_ONLY_RATIO_PCT,
                .rst_ratio_pct = XDP_DDOS_DEFAULT_RST_RATIO_PCT,
                .syn_ratio_pct = XDP_DDOS_DEFAULT_SYN_RATIO_PCT,
                .dns_resp_ratio_pct = XDP_DDOS_DEFAULT_DNS_RESP_RATIO_PCT,
                .dns_amp_min_bytes = XDP_DDOS_DEFAULT_DNS_AMP_MIN_BYTES,
                .udp_random_spread_bins = XDP_DDOS_DEFAULT_UDP_RANDOM_SPREAD,
                .scan_spread_bins = XDP_DDOS_DEFAULT_SCAN_SPREAD,
                .udp_amp_ratio_pct = XDP_DDOS_DEFAULT_UDP_AMP_RATIO_PCT,
                .icmp_ratio_pct = XDP_DDOS_DEFAULT_ICMP_RATIO_PCT,
                .block_min_score = XDP_DDOS_DEFAULT_BLOCK_MIN_SCORE,
                .block_min_reasons = XDP_DDOS_DEFAULT_BLOCK_MIN_REASONS,
                .emergency_cooldown_sec = XDP_DDOS_DEFAULT_EMERGENCY_COOLDOWN_SEC,
                .service_relax_dns_pct = XDP_DDOS_DEFAULT_SERVICE_RELAX_DNS_PCT,
                .service_relax_http_pct = XDP_DDOS_DEFAULT_SERVICE_RELAX_HTTP_PCT,
                .service_relax_https_pct = XDP_DDOS_DEFAULT_SERVICE_RELAX_HTTPS_PCT,
                .service_relax_ntp_pct = XDP_DDOS_DEFAULT_SERVICE_RELAX_NTP_PCT,
            };

            while ((tok = strtok_r(NULL, " \t\r\n", &ctx))) {
                if (!parse_kv_u32(tok, "anomaly_mult", &cfg.anomaly_mult_pct))
                    continue;
                if (!parse_kv_u32(tok, "score", &cfg.score_threshold))
                    continue;
                if (!parse_kv_u32(tok, "block_ttl", &cfg.block_ttl_sec))
                    continue;
                if (!parse_kv_u32(tok, "offenses", &cfg.offense_threshold))
                    continue;
                if (!parse_kv_u32(tok, "auto", &cfg.auto_mitigation))
                    continue;
                if (!parse_kv_u32(tok, "warmup", &cfg.warmup_windows))
                    continue;
                if (!parse_kv_u32(tok, "ack_ratio", &cfg.ack_only_ratio_pct))
                    continue;
                if (!parse_kv_u32(tok, "rst_ratio", &cfg.rst_ratio_pct))
                    continue;
                if (!parse_kv_u32(tok, "syn_ratio", &cfg.syn_ratio_pct))
                    continue;
                if (!parse_kv_u32(tok, "dns_ratio", &cfg.dns_resp_ratio_pct))
                    continue;
                if (!parse_kv_u32(tok, "dns_min_bytes", &cfg.dns_amp_min_bytes))
                    continue;
                if (!parse_kv_u32(tok, "udp_spread", &cfg.udp_random_spread_bins))
                    continue;
                if (!parse_kv_u32(tok, "scan_spread", &cfg.scan_spread_bins))
                    continue;
                if (!parse_kv_u32(tok, "udp_amp_ratio", &cfg.udp_amp_ratio_pct))
                    continue;
                if (!parse_kv_u32(tok, "icmp_ratio", &cfg.icmp_ratio_pct))
                    continue;
                if (!parse_kv_u32(tok, "block_min_score", &cfg.block_min_score))
                    continue;
                if (!parse_kv_u32(tok, "block_min_reasons", &cfg.block_min_reasons))
                    continue;
                if (!parse_kv_u32(tok, "emergency_cooldown_sec", &cfg.emergency_cooldown_sec))
                    continue;
                if (!parse_kv_u32(tok, "service_relax_dns_pct", &cfg.service_relax_dns_pct))
                    continue;
                if (!parse_kv_u32(tok, "service_relax_http_pct", &cfg.service_relax_http_pct))
                    continue;
                if (!parse_kv_u32(tok, "service_relax_https_pct", &cfg.service_relax_https_pct))
                    continue;
                if (!parse_kv_u32(tok, "service_relax_ntp_pct", &cfg.service_relax_ntp_pct))
                    continue;
                fprintf(stderr, "unknown token at %s:%d -> %s\n", path, line_no, tok);
            }

            if (set_defaults(&cfg) < 0) {
                fclose(f);
                return -1;
            }
            continue;
        }

        if (!strcmp(tok, "ip")) {
            char *ip_s = strtok_r(NULL, " \t\r\n", &ctx);
            struct ip_key key;
            struct ip_policy p = {
                .action = DDOS_ACTION_ADAPTIVE,
                .anomaly_mult_pct = 0,
                .score_threshold = 0,
                .block_ttl_sec = 0,
                .expires_at_ns = 0,
            };
            __u32 ttl = 0;

            if (!ip_s || parse_ip_any(ip_s, &key) < 0) {
                fprintf(stderr, "invalid ip at %s:%d\n", path, line_no);
                fclose(f);
                return -1;
            }

            while ((tok = strtok_r(NULL, " \t\r\n", &ctx))) {
                if (!strncmp(tok, "action=", 7)) {
                    p.action = parse_action(tok + 7);
                    if ((__s32)p.action < 0) {
                        fprintf(stderr, "invalid action at %s:%d\n", path, line_no);
                        fclose(f);
                        return -1;
                    }
                    continue;
                }
                if (!parse_kv_u32(tok, "anomaly_mult", &p.anomaly_mult_pct))
                    continue;
                if (!parse_kv_u32(tok, "score", &p.score_threshold))
                    continue;
                if (!parse_kv_u32(tok, "block_ttl", &p.block_ttl_sec))
                    continue;
                if (!parse_kv_u32(tok, "ttl", &ttl))
                    continue;
                fprintf(stderr, "unknown token at %s:%d -> %s\n", path, line_no, tok);
            }

            if (ttl)
                p.expires_at_ns = ((__u64)time(NULL) + ttl) * 1000000000ULL;

            if (apply_policy(&key, &p) < 0) {
                fclose(f);
                return -1;
            }
            continue;
        }

        if (!strcmp(tok, "subnet")) {
            char *cidr = strtok_r(NULL, " \t\r\n", &ctx);
            struct ip_policy p = {
                .action = DDOS_ACTION_ADAPTIVE,
                .anomaly_mult_pct = 0,
                .score_threshold = 0,
                .block_ttl_sec = 0,
                .expires_at_ns = 0,
            };
            __u32 ttl = 0;

            if (!cidr) {
                fprintf(stderr, "invalid subnet at %s:%d\n", path, line_no);
                fclose(f);
                return -1;
            }

            while ((tok = strtok_r(NULL, " \t\r\n", &ctx))) {
                if (!strncmp(tok, "action=", 7)) {
                    p.action = parse_action(tok + 7);
                    if ((__s32)p.action < 0) {
                        fprintf(stderr, "invalid action at %s:%d\n", path, line_no);
                        fclose(f);
                        return -1;
                    }
                    continue;
                }
                if (!parse_kv_u32(tok, "anomaly_mult", &p.anomaly_mult_pct))
                    continue;
                if (!parse_kv_u32(tok, "score", &p.score_threshold))
                    continue;
                if (!parse_kv_u32(tok, "block_ttl", &p.block_ttl_sec))
                    continue;
                if (!parse_kv_u32(tok, "ttl", &ttl))
                    continue;
                fprintf(stderr, "unknown token at %s:%d -> %s\n", path, line_no, tok);
            }

            if (ttl)
                p.expires_at_ns = ((__u64)time(NULL) + ttl) * 1000000000ULL;

            if (apply_subnet_policy(cidr, &p) < 0) {
                fprintf(stderr, "failed subnet policy at %s:%d\n", path, line_no);
                fclose(f);
                return -1;
            }
            continue;
        }

        if (!strcmp(tok, "port")) {
            char *proto_s = strtok_r(NULL, " \t\r\n", &ctx);
            char *port_s = strtok_r(NULL, " \t\r\n", &ctx);
            struct ip_policy p = {
                .action = DDOS_ACTION_ADAPTIVE,
                .anomaly_mult_pct = 0,
                .score_threshold = 0,
                .block_ttl_sec = 0,
                .expires_at_ns = 0,
            };
            int proto;
            __u16 port;
            __u32 ttl = 0;

            if (!proto_s || !port_s) {
                fprintf(stderr, "invalid port rule at %s:%d\n", path, line_no);
                fclose(f);
                return -1;
            }

            proto = parse_proto(proto_s);
            port = (__u16)strtoul(port_s, NULL, 10);
            if (proto < 0 || !port) {
                fprintf(stderr, "invalid proto/port at %s:%d\n", path, line_no);
                fclose(f);
                return -1;
            }

            while ((tok = strtok_r(NULL, " \t\r\n", &ctx))) {
                if (!strncmp(tok, "action=", 7)) {
                    p.action = parse_action(tok + 7);
                    if ((__s32)p.action < 0) {
                        fprintf(stderr, "invalid action at %s:%d\n", path, line_no);
                        fclose(f);
                        return -1;
                    }
                    continue;
                }
                if (!parse_kv_u32(tok, "anomaly_mult", &p.anomaly_mult_pct))
                    continue;
                if (!parse_kv_u32(tok, "score", &p.score_threshold))
                    continue;
                if (!parse_kv_u32(tok, "block_ttl", &p.block_ttl_sec))
                    continue;
                if (!parse_kv_u32(tok, "ttl", &ttl))
                    continue;
                fprintf(stderr, "unknown token at %s:%d -> %s\n", path, line_no, tok);
            }

            if (ttl)
                p.expires_at_ns = ((__u64)time(NULL) + ttl) * 1000000000ULL;

            if (apply_port_policy(proto, port, &p) < 0) {
                fprintf(stderr, "failed port policy at %s:%d\n", path, line_no);
                fclose(f);
                return -1;
            }
            continue;
        }

        fprintf(stderr, "unknown directive at %s:%d -> %s\n", path, line_no, tok);
    }

    fclose(f);
    return 0;
}

static int do_load(const char *ifname, const char *rules_file)
{
    struct bpf_object *obj = NULL;
    struct bpf_program *prog;
    struct global_cfg cfg = {
        .anomaly_mult_pct = XDP_DDOS_DEFAULT_ANOMALY_MULT_PCT,
        .score_threshold = XDP_DDOS_DEFAULT_SCORE_THRESHOLD,
        .block_ttl_sec = XDP_DDOS_DEFAULT_BLOCK_TTL_SEC,
        .offense_threshold = XDP_DDOS_DEFAULT_OFFENSES,
        .auto_mitigation = 1,
        .warmup_windows = XDP_DDOS_DEFAULT_WARMUP_WINDOWS,
        .ewma_shift = 3,
        .ack_only_ratio_pct = XDP_DDOS_DEFAULT_ACK_ONLY_RATIO_PCT,
        .rst_ratio_pct = XDP_DDOS_DEFAULT_RST_RATIO_PCT,
        .syn_ratio_pct = XDP_DDOS_DEFAULT_SYN_RATIO_PCT,
        .dns_resp_ratio_pct = XDP_DDOS_DEFAULT_DNS_RESP_RATIO_PCT,
        .dns_amp_min_bytes = XDP_DDOS_DEFAULT_DNS_AMP_MIN_BYTES,
        .udp_random_spread_bins = XDP_DDOS_DEFAULT_UDP_RANDOM_SPREAD,
        .scan_spread_bins = XDP_DDOS_DEFAULT_SCAN_SPREAD,
        .udp_amp_ratio_pct = XDP_DDOS_DEFAULT_UDP_AMP_RATIO_PCT,
        .icmp_ratio_pct = XDP_DDOS_DEFAULT_ICMP_RATIO_PCT,
        .block_min_score = XDP_DDOS_DEFAULT_BLOCK_MIN_SCORE,
        .block_min_reasons = XDP_DDOS_DEFAULT_BLOCK_MIN_REASONS,
        .emergency_cooldown_sec = XDP_DDOS_DEFAULT_EMERGENCY_COOLDOWN_SEC,
        .service_relax_dns_pct = XDP_DDOS_DEFAULT_SERVICE_RELAX_DNS_PCT,
        .service_relax_http_pct = XDP_DDOS_DEFAULT_SERVICE_RELAX_HTTP_PCT,
        .service_relax_https_pct = XDP_DDOS_DEFAULT_SERVICE_RELAX_HTTPS_PCT,
        .service_relax_ntp_pct = XDP_DDOS_DEFAULT_SERVICE_RELAX_NTP_PCT,
    };
    int ifindex;
    int prog_fd;

    ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        fprintf(stderr, "invalid interface: %s\n", ifname);
        return -1;
    }

    obj = bpf_object__open_file(OBJ_FILE, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "failed opening %s\n", OBJ_FILE);
        return -1;
    }

    if (bpf_object__load(obj) < 0) {
        fprintf(stderr, "failed loading BPF object\n");
        bpf_object__close(obj);
        return -1;
    }

    prog = bpf_object__find_program_by_name(obj, "xdp_ddos_filter");
    if (!prog)
        prog = bpf_object__next_program(obj, NULL);

    if (!prog) {
        fprintf(stderr, "failed finding XDP program\n");
        bpf_object__close(obj);
        return -1;
    }

    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        fprintf(stderr, "failed getting program fd\n");
        bpf_object__close(obj);
        return -1;
    }

    if (bpf_set_link_xdp_fd(ifindex, prog_fd, XDP_FLAGS_DRV_MODE) < 0) {
        fprintf(stderr, "failed attaching XDP in driver mode to %s (interface may not support native mode)\n", ifname);
        bpf_object__close(obj);
        return -1;
    }

    if (ensure_pin_base() < 0) {
        bpf_set_link_xdp_fd(ifindex, -1, XDP_FLAGS_DRV_MODE);
        bpf_object__close(obj);
        return -1;
    }

    if (bpf_object__pin_maps(obj, PIN_BASE) < 0) {
        fprintf(stderr, "failed pinning maps to %s\n", PIN_BASE);
        bpf_set_link_xdp_fd(ifindex, -1, XDP_FLAGS_DRV_MODE);
        bpf_object__close(obj);
        return -1;
    }

    if (set_defaults(&cfg) < 0) {
        bpf_set_link_xdp_fd(ifindex, -1, XDP_FLAGS_DRV_MODE);
        bpf_object__close(obj);
        return -1;
    }

    if (rules_file && apply_rules_file(rules_file) < 0) {
        bpf_set_link_xdp_fd(ifindex, -1, XDP_FLAGS_DRV_MODE);
        bpf_object__close(obj);
        return -1;
    }

    printf("xdp_ddos loaded on %s in driver mode\n", ifname);
    bpf_object__close(obj);
    return 0;
}

static int do_unload(const char *ifname)
{
    int ifindex = if_nametoindex(ifname);

    if (!ifindex) {
        fprintf(stderr, "invalid interface: %s\n", ifname);
        return -1;
    }

    if (bpf_set_link_xdp_fd(ifindex, -1, XDP_FLAGS_DRV_MODE) < 0) {
        fprintf(stderr, "failed detaching XDP from %s\n", ifname);
        return -1;
    }

    printf("xdp_ddos unloaded from %s\n", ifname);
    return 0;
}

int main(int argc, char **argv)
{
    const char *cmd;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(NULL);

    if (bump_memlock())
        fprintf(stderr, "warning: unable to raise memlock limit\n");

    if (argc >= 2 && !strcmp(argv[1], "--json")) {
        g_json_output = true;
        argc--;
        argv++;
    }

    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    cmd = argv[1];

    if (!strcmp(cmd, "load")) {
        if (argc < 3 || argc > 4) {
            usage(argv[0]);
            return 1;
        }
        return do_load(argv[2], argc == 4 ? argv[3] : NULL) ? 1 : 0;
    }

    if (!strcmp(cmd, "unload")) {
        if (argc != 3) {
            usage(argv[0]);
            return 1;
        }
        return do_unload(argv[2]) ? 1 : 0;
    }

    if (!strcmp(cmd, "stats"))
        return print_stats_once() ? 1 : 0;

    if (!strcmp(cmd, "monitor")) {
        int interval = 2;
        if (argc > 2)
            interval = atoi(argv[2]);
        return monitor_loop(interval) ? 1 : 0;
    }

    if (!strcmp(cmd, "log")) {
        int poll_ms = 250;
        if (argc < 3 || argc > 4) {
            usage(argv[0]);
            return 1;
        }
        if (argc == 4)
            poll_ms = atoi(argv[3]);
        return log_loop(argv[2], poll_ms) ? 1 : 0;
    }

    if (!strcmp(cmd, "state")) {
        if (argc >= 3 && !strcmp(argv[2], "top")) {
            int n = 20;
            if (argc >= 4)
                n = atoi(argv[3]);
            return print_top_states(n) ? 1 : 0;
        }
        usage(argv[0]);
        return 1;
    }

    if (!strcmp(cmd, "defaults")) {
        if (argc == 3 && !strcmp(argv[2], "show"))
            return show_defaults() ? 1 : 0;

        if ((argc == 20 || argc == 25) && !strcmp(argv[2], "set")) {
            struct global_cfg cfg = {
                .anomaly_mult_pct = (__u32)strtoul(argv[3], NULL, 10),
                .score_threshold = (__u32)strtoul(argv[4], NULL, 10),
                .block_ttl_sec = (__u32)strtoul(argv[5], NULL, 10),
                .offense_threshold = (__u32)strtoul(argv[6], NULL, 10),
                .auto_mitigation = (__u32)strtoul(argv[7], NULL, 10),
                .warmup_windows = (__u32)strtoul(argv[8], NULL, 10),
                .ewma_shift = 3,
                .ack_only_ratio_pct = (__u32)strtoul(argv[9], NULL, 10),
                .rst_ratio_pct = (__u32)strtoul(argv[10], NULL, 10),
                .syn_ratio_pct = (__u32)strtoul(argv[11], NULL, 10),
                .dns_resp_ratio_pct = (__u32)strtoul(argv[12], NULL, 10),
                .dns_amp_min_bytes = (__u32)strtoul(argv[13], NULL, 10),
                .udp_random_spread_bins = (__u32)strtoul(argv[14], NULL, 10),
                .scan_spread_bins = (__u32)strtoul(argv[15], NULL, 10),
                .udp_amp_ratio_pct = (__u32)strtoul(argv[16], NULL, 10),
                .icmp_ratio_pct = (__u32)strtoul(argv[17], NULL, 10),
                .block_min_score = (__u32)strtoul(argv[18], NULL, 10),
                .block_min_reasons = (__u32)strtoul(argv[19], NULL, 10),
                .emergency_cooldown_sec = XDP_DDOS_DEFAULT_EMERGENCY_COOLDOWN_SEC,
                .service_relax_dns_pct = XDP_DDOS_DEFAULT_SERVICE_RELAX_DNS_PCT,
                .service_relax_http_pct = XDP_DDOS_DEFAULT_SERVICE_RELAX_HTTP_PCT,
                .service_relax_https_pct = XDP_DDOS_DEFAULT_SERVICE_RELAX_HTTPS_PCT,
                .service_relax_ntp_pct = XDP_DDOS_DEFAULT_SERVICE_RELAX_NTP_PCT,
            };

            if (argc == 25) {
                cfg.emergency_cooldown_sec = (__u32)strtoul(argv[20], NULL, 10);
                cfg.service_relax_dns_pct = (__u32)strtoul(argv[21], NULL, 10);
                cfg.service_relax_http_pct = (__u32)strtoul(argv[22], NULL, 10);
                cfg.service_relax_https_pct = (__u32)strtoul(argv[23], NULL, 10);
                cfg.service_relax_ntp_pct = (__u32)strtoul(argv[24], NULL, 10);
            }

            return set_defaults(&cfg) ? 1 : 0;
        }

        usage(argv[0]);
        return 1;
    }

    if (!strcmp(cmd, "policy")) {
        if (argc >= 5 && !strcmp(argv[2], "add")) {
            struct ip_key key;
            struct ip_policy p = {
                .action = DDOS_ACTION_ADAPTIVE,
                .anomaly_mult_pct = 0,
                .score_threshold = 0,
                .block_ttl_sec = 0,
                .expires_at_ns = 0,
            };

            if (parse_ip_any(argv[3], &key) < 0) {
                fprintf(stderr, "invalid ip %s\n", argv[3]);
                return 1;
            }

            p.action = parse_action(argv[4]);
            if ((__s32)p.action < 0) {
                fprintf(stderr, "invalid action %s\n", argv[4]);
                return 1;
            }

            if (argc > 5)
                p.anomaly_mult_pct = (__u32)strtoul(argv[5], NULL, 10);
            if (argc > 6)
                p.score_threshold = (__u32)strtoul(argv[6], NULL, 10);
            if (argc > 7)
                p.block_ttl_sec = (__u32)strtoul(argv[7], NULL, 10);
            if (argc > 8) {
                __u32 ttl = (__u32)strtoul(argv[8], NULL, 10);
                p.expires_at_ns = ((__u64)time(NULL) + ttl) * 1000000000ULL;
            }

            return apply_policy(&key, &p) ? 1 : 0;
        }

        if (argc == 4 && !strcmp(argv[2], "del")) {
            struct ip_key key;
            if (parse_ip_any(argv[3], &key) < 0) {
                fprintf(stderr, "invalid ip %s\n", argv[3]);
                return 1;
            }
            return delete_policy(&key) ? 1 : 0;
        }

        if (argc == 3 && !strcmp(argv[2], "list"))
            return list_policies() ? 1 : 0;

        usage(argv[0]);
        return 1;
    }

    if (!strcmp(cmd, "subnet")) {
        if (argc >= 5 && !strcmp(argv[2], "add")) {
            struct ip_policy p = {
                .action = DDOS_ACTION_ADAPTIVE,
            };

            p.action = parse_action(argv[4]);
            if ((__s32)p.action < 0) {
                fprintf(stderr, "invalid action %s\n", argv[4]);
                return 1;
            }

            if (argc > 5)
                p.anomaly_mult_pct = (__u32)strtoul(argv[5], NULL, 10);
            if (argc > 6)
                p.score_threshold = (__u32)strtoul(argv[6], NULL, 10);
            if (argc > 7)
                p.block_ttl_sec = (__u32)strtoul(argv[7], NULL, 10);
            if (argc > 8) {
                __u32 ttl = (__u32)strtoul(argv[8], NULL, 10);
                p.expires_at_ns = ((__u64)time(NULL) + ttl) * 1000000000ULL;
            }

            return apply_subnet_policy(argv[3], &p) ? 1 : 0;
        }

        if (argc == 4 && !strcmp(argv[2], "del"))
            return delete_subnet_policy(argv[3]) ? 1 : 0;

        if (argc == 3 && !strcmp(argv[2], "list"))
            return list_subnets() ? 1 : 0;

        usage(argv[0]);
        return 1;
    }

    if (!strcmp(cmd, "port")) {
        if (argc >= 6 && !strcmp(argv[2], "add")) {
            int proto = parse_proto(argv[3]);
            __u16 port = (__u16)strtoul(argv[4], NULL, 10);
            struct ip_policy p = {
                .action = DDOS_ACTION_ADAPTIVE,
            };

            if (proto < 0 || !port) {
                fprintf(stderr, "invalid proto/port\n");
                return 1;
            }

            p.action = parse_action(argv[5]);
            if ((__s32)p.action < 0) {
                fprintf(stderr, "invalid action %s\n", argv[5]);
                return 1;
            }

            if (argc > 6)
                p.anomaly_mult_pct = (__u32)strtoul(argv[6], NULL, 10);
            if (argc > 7)
                p.score_threshold = (__u32)strtoul(argv[7], NULL, 10);
            if (argc > 8)
                p.block_ttl_sec = (__u32)strtoul(argv[8], NULL, 10);
            if (argc > 9) {
                __u32 ttl = (__u32)strtoul(argv[9], NULL, 10);
                p.expires_at_ns = ((__u64)time(NULL) + ttl) * 1000000000ULL;
            }

            return apply_port_policy(proto, port, &p) ? 1 : 0;
        }

        if (argc == 5 && !strcmp(argv[2], "del")) {
            int proto = parse_proto(argv[3]);
            __u16 port = (__u16)strtoul(argv[4], NULL, 10);
            if (proto < 0 || !port)
                return 1;
            return delete_port_policy(proto, port) ? 1 : 0;
        }

        if (argc == 3 && !strcmp(argv[2], "list"))
            return list_ports() ? 1 : 0;

        usage(argv[0]);
        return 1;
    }

    usage(argv[0]);
    return 1;
}
