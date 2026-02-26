#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86
#endif

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL"; 

SEC("xdp")
int drop_packets(struct xdp_md *ctx){
//     char comm[16];
//     bpf_get_current_comm(&comm,sizeof(comm));

// bpf_printk("data: %llu data_end: %llu\n command_name:%s",
//            (unsigned long long)ctx->data,
//            (unsigned long long)ctx->data_end,
//             comm);
    return XDP_DROP;
}
// load_xdp
// load_tc
// 