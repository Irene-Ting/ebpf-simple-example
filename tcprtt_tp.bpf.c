#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "tcprtt.h"

#include "bpf_tracing_net.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// TODO: define ring buffer
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");
// TODO: define hash map
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, unsigned int);
	__type(value, u64);
} exec_start SEC(".maps");

SEC("tracepoint/sock/inet_sock_set_state")
int handle_set_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
    // handle ipv4 only
    if (ctx->family != AF_INET)
        return 0;
    
    // TODO: complete kernel program
    /* reserve sample from BPF ringbuf */
    struct event *e;
    unsigned int saddr;

    bpf_core_read(&saddr, sizeof(saddr), ctx->skaddr);
    u64 *prev, ts;

    if ((ctx->oldstate == TCP_SYN_SENT || ctx->oldstate == TCP_SYN_RECV) \
            && ctx->newstate == TCP_ESTABLISHED) {
        e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
        if (!e)
            return 0;

        prev = bpf_map_lookup_elem(&exec_start, &saddr);

        if (prev) {
            u64 duration = bpf_ktime_get_ns() - *prev;
            e->rtt = duration / 1000;

            bpf_get_current_comm(&e->comm, sizeof(e->comm));
            bpf_core_read(&e->saddr, sizeof(e->saddr), ctx->saddr);
            bpf_core_read(&e->daddr, sizeof(e->daddr), ctx->daddr);
            e->sport = ctx->sport;
            e->dport = ctx->dport;
        }
        /* successfully submit it to user-space for post-processing */
        bpf_ringbuf_submit(e, 0);
    } 
    
    if (ctx->newstate == TCP_CLOSE) {
       bpf_map_delete_elem(&exec_start, &saddr);
    } else {
        ts = bpf_ktime_get_ns();
        bpf_map_update_elem(&exec_start, &saddr, &ts, BPF_ANY);
    }
    return 0;
}