#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

BPF_HASH(currsock, u32, struct sock *);

BPF_PERF_OUTPUT(kprobe_tcp_v4_connect_events); //Create a definition perf event output for tcpv4 _connect events to send data to userspace
BPF_PERF_OUTPUT(kretprobe_tcp_v4_connect_events); //Create a definition perf event output for tcpv4_connect events to send data to userspace

int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk)
{
	u32 pid = bpf_get_current_pid_tgid();

	// stash the sock ptr for lookup on return
	currsock.update(&pid, &sk);
    //kprobe_tcp_v4_connect_events.perf.submit()
	return 0;
};

int kretprobe__tcp_v4_connect(struct pt_regs *ctx)
{
	int ret = PT_REGS_RC(ctx);
	u32 pid = bpf_get_current_pid_tgid();

	struct sock **skpp;
	skpp = currsock.lookup(&pid);
	if (skpp == 0) {
		return 0;	// missed entry
	}

	if (ret != 0) {
		// failed to send SYNC packet, may not have populated
		// socket __sk_common.{skc_rcv_saddr, ...}
		currsock.delete(&pid);
		return 0;
	}

	// pull in details
	struct sock *skp = *skpp;
	u32 saddr = skp->__sk_common.skc_rcv_saddr;
	u32 daddr = skp->__sk_common.skc_daddr;
	u16 dport = skp->__sk_common.skc_dport;

	// output
	bpf_trace_printk("trace_tcp4connect %x %x %d\n", saddr, daddr, ntohs(dport));

    //kretprobe_tcp_v4_connect_events.perf_submit.()

	currsock.delete(&pid);

	return 0;
}
