#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include "tcp.skel.h"

static volatile sig_atomic_t exiting = 0;

struct tcp_info1 {
    __u32 pid;
    __u32 tid;
    __s32 state;
    __s32 type;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    char comm[16];
};


static void handle_signal(int sig)
{
    exiting = 1;
}


static int handle_event(void *ctx, void *data, size_t len)
{
    struct tcp_info1 *e = data;

    struct in_addr saddr = { .s_addr = e->saddr };
    struct in_addr daddr = { .s_addr = e->daddr };

    printf("PID=%u COMM=%s TYPE=%d STATE=%d "
           "%s:%u -> %s:%u\n",
           e->pid,
           e->comm,
           e->type,
           e->state,
           inet_ntoa(saddr),
           e->sport,
           inet_ntoa(daddr),
           e->dport);

    return 0;
}

int main(void)
{
    struct tcp_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    skel = tcp_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open/load skeleton\n");
        return 1;
    }

    err = tcp_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach skeleton\n");
        goto cleanup;
    }

    rb = ring_buffer__new(
        bpf_map__fd(skel->maps.events),
        handle_event,
        NULL,
        NULL
    );

    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("TCP tracer running... Press Ctrl+C to exit.\n");

    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR)
            break;
    }

cleanup:
    ring_buffer__free(rb);
    tcp_bpf__destroy(skel);
    return 0;
}
