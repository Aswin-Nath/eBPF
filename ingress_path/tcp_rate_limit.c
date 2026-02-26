#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86
#endif

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

#define RATE_LIMIT_MAX_REQUESTS 10
#define TIME_WINDOW_SECONDS 300

struct ip_stats {
    __u64 first_request_time;
    __u64 last_request_time;
    __u32 request_count;
    __u32 blocked_count;
};

struct ip_event {
    __u32 dst_ip;
    __u32 request_count;
    __u32 blocked_count;
    __u64 timestamp;
    __u8 is_blocked;
};

/* Ring buffer for events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

/* Per-destination-IP rate limit stats */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);
    __type(value, struct ip_stats);
} ip_stats_map SEC(".maps");

/* Request counter */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} request_counter SEC(".maps");

static __always_inline void update_ip_stats(__u32 dst_ip, __u8 is_blocked)
{
    struct ip_stats *stats = bpf_map_lookup_elem(&ip_stats_map, &dst_ip);
    struct ip_stats new_stats = {};
    __u64 now = bpf_ktime_get_ns();
    
    if (stats) {
        new_stats = *stats;
    } else {
        new_stats.first_request_time = now;
    }
    
    new_stats.last_request_time = now;
    new_stats.request_count++;
    if (is_blocked) {
        new_stats.blocked_count++;
    }
    
    bpf_map_update_elem(&ip_stats_map, &dst_ip, &new_stats, BPF_ANY);
    
    struct ip_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->dst_ip = dst_ip;
        e->request_count = new_stats.request_count;
        e->blocked_count = new_stats.blocked_count;
        e->timestamp = now;
        e->is_blocked = is_blocked;
        bpf_ringbuf_submit(e, 0);
    }
    
    __u32 zero = 0;
    __u64 *counter = bpf_map_lookup_elem(&request_counter, &zero);
    if (counter) {
        __sync_fetch_and_add(counter, 1);
    }
}

static __always_inline __u8 check_rate_limit(__u32 dst_ip)
{
    struct ip_stats *stats = bpf_map_lookup_elem(&ip_stats_map, &dst_ip);
    if (!stats) {
        return 0;
    }
    
    __u64 now = bpf_ktime_get_ns();
    __u64 elapsed_sec = (now - stats->first_request_time) / 1000000000;
    
    if (elapsed_sec > TIME_WINDOW_SECONDS) {
        struct ip_stats reset = {};
        reset.first_request_time = now;
        reset.last_request_time = now;
        reset.request_count = 0;
        reset.blocked_count = 0;
        bpf_map_update_elem(&ip_stats_map, &dst_ip, &reset, BPF_ANY);
        return 0;
    }
    
    if (stats->request_count >= RATE_LIMIT_MAX_REQUESTS) {
        return 1;
    }
    
    return 0;
}

/* Kprobe: tcp_v4_connect to track TCP connections */
SEC("kprobe/tcp_connect")
int trace_tcp_v4_connect(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)ctx->di;
    
    if (!sk)
        return 0;
    
    /* Extract destination IP */
    __u32 dst_ip = 0;
    bpf_probe_read_kernel(&dst_ip, sizeof(dst_ip), &sk->__sk_common.skc_daddr);
    
    if (dst_ip == 0)
        return 0;
    
    /* Check rate limit for destination IP */
    __u8 is_blocked = check_rate_limit(dst_ip);
    update_ip_stats(dst_ip, is_blocked);
    
    bpf_printk("TCP_V4_CONNECT: dst_ip=%pI4 blocked=%u", &dst_ip, is_blocked);
    
    return 0;
}

