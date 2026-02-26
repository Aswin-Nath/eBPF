#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <sys/resource.h>
#include <arpa/inet.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}

struct ip_event {
    __u32 dst_ip;
    __u32 request_count;
    __u32 blocked_count;
    __u64 timestamp;
    __u8 is_blocked;
};

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct ip_event *e = data;
    
    char ip_str[INET_ADDRSTRLEN];
    struct in_addr addr;
    addr.s_addr = e->dst_ip;
    inet_ntop(AF_INET, &addr, ip_str, INET_ADDRSTRLEN);
    
    const char *status = e->is_blocked ? "🚫 BLOCKED" : "✅ ALLOWED";
    
    printf("[%s] Dest IP: %-15s | Requests: %5u | Blocked: %5u\n",
           status, ip_str, e->request_count, e->blocked_count);
    return 0;
}

int main(int argc, char **argv)
{
    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;
    struct bpf_link *link = NULL;
    int ringbuf_fd = -1;
    struct ring_buffer *rb = NULL;
    int request_counter_fd = -1;
    int err = 0;
    
    libbpf_set_print(libbpf_print_fn);
    
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
    
    bpf_object__for_each_program(prog, obj) {
        const char *prog_name = bpf_program__name(prog);
        const char *section = bpf_program__section_name(prog);
        
        if (strncmp(section, "kprobe/", 7) == 0) {
            link = bpf_program__attach(prog);
            if (!link) {
                fprintf(stderr, "[-] Failed to attach %s\n", prog_name);
            } else {
                printf("[+] Attached kprobe: %s\n", prog_name);
            }
        }
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
    
    request_counter_fd = bpf_object__find_map_fd_by_name(obj, "request_counter");
    
    printf("\n╔════════════════════════════════════════════════════════════╗\n");
    printf("║     TCP Destination IP Rate Limiter Statistics Monitor    ║\n");
    printf("╚════════════════════════════════════════════════════════════╝\n\n");
    printf("[*] Monitoring TCP connections per destination IP...\n");
    printf("[*] Rate Limit: 10 connections per 5 minutes per IP\n");
    printf("[*] Press Ctrl+C to exit\n\n");
    
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    int last_count = 0;
    time_t last_display = time(NULL);
    
    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err < 0 && err != -EINTR) {
            printf("[-] Error polling ring buffer: %d\n", err);
            break;
        }
        
        time_t now = time(NULL);
        if (now - last_display >= 2) {
            if (request_counter_fd >= 0) {
                __u32 key = 0;
                __u64 counter = 0;
                if (bpf_map_lookup_elem(request_counter_fd, &key, &counter) == 0) {
                    int new_count = (int)counter;
                    if (new_count != last_count) {
                        printf("\n📊 Total TCP connections tracked: %d\n\n", new_count);
                        last_count = new_count;
                    }
                }
            }
            last_display = now;
        }
    }
    
    printf("\n[*] Detaching programs and cleaning up...\n");

cleanup:
    if (rb)
        ring_buffer__free(rb);
    if (obj)
        bpf_object__close(obj);
    
    return err ? 1 : 0;
}
