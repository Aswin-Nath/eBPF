#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86
#endif

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>


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


char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type,BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries,1<<15);
} events SEC(".maps");


struct {
    __uint(type,BPF_MAP_TYPE_HASH);
    __uint(max_entries,1<<10);
    __type(key,__u64);
    __type(value,__u32);
} sk_to_pid SEC(".maps");


SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect,struct sock *sk){
    __u64 tgid = bpf_get_current_pid_tgid();
    __u32 pid = tgid >> 32;
    __u32 tid  = (__u32)tgid;

    struct tcp_info1 *event;
    char comm[16];
    bpf_get_current_comm(&comm,sizeof(comm));
    if(comm[0]!='c' || comm[1]!='u' || comm[2]!='r' || comm[3]!='l'){
        return 0;
    }
    event = bpf_ringbuf_reserve(&events,sizeof(*event),0);
    if(!event){
        return 0;
    }
    __builtin_memset(event,0,sizeof(*event));      
    event->pid = pid;
    event->tid = tid;
    event->type = 0;
    bpf_get_current_comm(&event->comm,sizeof(event->comm));
    if(pid){
        __u64 sk_key = (__u64)sk;   
        bpf_map_update_elem(&sk_to_pid,&sk_key,&pid,BPF_ANY);
    }
    bpf_ringbuf_submit(event,0);
    return 0;
}


SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(tcp_v6_connect,struct sock *sk){
    __u64 tgid = bpf_get_current_pid_tgid();
    __u32 pid = tgid >> 32;
    __u32 tid = (__u32)tgid;
    struct tcp_info1 *event;
    char comm[16];
    bpf_get_current_comm(&comm,sizeof(comm));
    if(comm[0]!='c' || comm[1]!='u' || comm[2]!='r' || comm[3]!='l'){
        return 0;
    }
    event = bpf_ringbuf_reserve(&events,sizeof(*event),0);
    if(!event){
        return 0;
    }
    __builtin_memset(event,0,sizeof(*event));
    event->pid = pid;
    event->tid = tid;
    event->type = 1;
    bpf_get_current_comm(&event->comm,sizeof(event->comm));
    if(pid){
        __u64 sk_key = (__u64)sk;   
        bpf_map_update_elem(&sk_to_pid,&sk_key,&pid,BPF_ANY);
    }
    bpf_ringbuf_submit(event,0);
    return 0;
}

SEC("kprobe/tcp_set_state")
int BPF_KPROBE(tcp_set_state,struct sock *sk,int state){
    struct tcp_info1 *event;
    char comm[16];
    bpf_get_current_comm(&comm,sizeof(comm));
    if(comm[0]!='c' || comm[1]!='u' || comm[2]!='r' || comm[3]!='l'){
        return 0;
    }
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;
    __u64 sk_key = (__u64)sk;

    __builtin_memset(event, 0, sizeof(*event));

    __u32 *pid = bpf_map_lookup_elem(&sk_to_pid, &sk_key);

    __u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);

    event->saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    event->daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    event->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    event->dport = __builtin_bswap16(dport);

    event->state = state;
    event->type  = 2;

    if (pid)
        event->pid = *pid;

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    bpf_ringbuf_submit(event, 0);
    return 0;
}