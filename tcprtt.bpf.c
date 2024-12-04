#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

// for the definition of the type shared between user and kernel
#include "tcprtt.h"

#include "bpf_tracing_net.h"
    
char LICENSE[] SEC("license") = "Dual BSD/GPL";

// TODO: define ring buffer
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("fentry/tcp_rcv_established")
int BPF_PROG(tcp_rcv, struct sock *sk /*, optional */)
{
    // handler ipv4 only
    if (sk->__sk_common.skc_family != AF_INET)
        return 0;
    
    // TODO: complete kernel program
    /* reserve sample from BPF ringbuf */
    pid_t pid;
    struct event *e;
    // unsigned int saddr;
    // unsigned int daddr;
    // unsigned short sport;
    // unsigned short dport;
    // unsigned int rtt;
    // int pid;
    // char comm[16];
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

    pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->rtt = (BPF_CORE_READ(tcp_sk(sk), srtt_us) >> 3);
    e->saddr = sk->__sk_common.skc_rcv_saddr;
    e->daddr = sk->__sk_common.skc_daddr;
    e->sport = sk->__sk_common.skc_num;
    e->dport = sk->__sk_common.skc_dport;

	/* successfully submit it to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);
    return 0;
}