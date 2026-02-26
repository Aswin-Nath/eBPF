#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <net/if.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "xdp.skel.h"

static volatile sig_atomic_t exiting = 0;

void handle_signal(int sig)
{
    exiting = 1;
}

int main(int argc, char **argv)
{
    struct xdp_bpf *skel;
    int ifindex;
    int err;

    // if (argc < 2) {
    //     printf("Usage: %s <interface>\n", argv[0]);
    //     return 1;
    // }

    /* Convert interface name to index */

    /* Open + Load */
    skel = xdp_bpf__open_and_load();
    if (!skel) {
        printf("Failed to open/load BPF skeleton\n");
        return 1;
    }
    struct bpf_link *link;

    /* Attach XDP manually to chosen interface */
    link = bpf_program__attach_xdp(skel->progs.drop_packets, 0);
    if (!link) {
        printf("Failed to attach XDP program\n");
        goto cleanup;
    }

    printf("XDP program attached to %s\n", argv[1]);

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    while (!exiting) {
        sleep(1);
    }

cleanup:
    xdp_bpf__destroy(skel);
    printf("Detached and exiting...\n");
    return err < 0;
}
