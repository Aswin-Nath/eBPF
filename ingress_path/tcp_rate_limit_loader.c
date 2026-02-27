#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/resource.h>
#include <arpa/inet.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

struct ip_event {
    __u32 dst_ip;
    __u32 request_count;
    __u32 blocked_count;
    __u64 timestamp;
    __u8 is_blocked;
    __u64 seconds_until_unban;
};

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct ip_event *e = data;
    
    char ip_str[INET_ADDRSTRLEN];
    struct in_addr addr;
    addr.s_addr = e->dst_ip;
    inet_ntop(AF_INET, &addr, ip_str, INET_ADDRSTRLEN);
    
    const char *status = e->is_blocked ? "🚫 BLOCKED" : "✅ ALLOWED";
    
    if (e->is_blocked && e->seconds_until_unban > 0) {
        printf("[%s] Dest IP: %-15s | Requests: %5u | Blocked: %5u | Unban in: %llu sec\n",
               status, ip_str, e->request_count, e->blocked_count, e->seconds_until_unban);
    } else {
        printf("[%s] Dest IP: %-15s | Requests: %5u | Blocked: %5u\n",
               status, ip_str, e->request_count, e->blocked_count);
    }
    return 0;
}

int main(int argc, char **argv)
{
    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;
    struct bpf_link *link = NULL;
    int ringbuf_fd = -1;
    struct ring_buffer *rb = NULL;
    int err = 0;
    
    
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <bpf_object_file>\n", argv[0]);
        return 1;
    }
    
    obj = bpf_object__open_file(argv[1], NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "[-] Failed to open BPF object file: %s\n", argv[1]);
        return 1;
    }
    
    printf("[*] Loading BPF object from: %s\n", argv[1]);
    
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "[-] Failed to load BPF object: %d\n", err);
        goto cleanup;
    }
    
    printf("[+] BPF object loaded successfully\n\n");
    prog = bpf_object__find_program_by_name(obj, "trace_tcp_v4_connect");
    if (!prog) {
        fprintf(stderr, "Program not found\n");
        goto cleanup;
    }

    link = bpf_program__attach(prog);
    if (!link) {
        fprintf(stderr, "Attach failed\n");
        goto cleanup;
    }
    
    ringbuf_fd = bpf_object__find_map_fd_by_name(obj, "events");
    if (ringbuf_fd < 0) {
        fprintf(stderr, "[-] Failed to find events ring buffer\n");
        err = -1;
        goto cleanup;
    }
    
    rb = ring_buffer__new(ringbuf_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "[-] Failed to create ring buffer reader\n");
        err = -1;
        goto cleanup;
    }
    
    
    printf("\n╔════════════════════════════════════════════════════════════╗\n");
    printf("║     TCP Destination IP Rate Limiter Statistics Monitor    ║\n");
    printf("╚════════════════════════════════════════════════════════════╝\n\n");
    
    
    while (true) {
        err = ring_buffer__poll(rb, 100);
        if (err < 0 && err != -EINTR) {
            printf("[-] Error polling ring buffer: %d\n", err);
            break;
        }
        
    }
    

cleanup:
    if (rb)
        ring_buffer__free(rb);
    if (obj)
        bpf_object__close(obj);
    
    return err ? 1 : 0;
}
