#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>


struct process_information {
  pid_t pid;
  char name[64];
  __u8 is_ipv6;
  __u32 dst[4];
  __u32 src[4];
  __u8 proto;
  __u8 type;
  __u8 code;
  __u16 dport;
  __u16 sport;
};


BPF_QUEUE(flowi_map, struct process_information, 128);


int kprobe_security_sk_classify_flow(struct pt_regs *ctx, struct sock *sk, struct flowi *fl) {
  pid_t pid;

  // Set the memory to 0
  struct process_information info;
  __builtin_memset(&info, 0, sizeof(struct process_information));

  // Get the process PID and name
  pid = bpf_get_current_pid_tgid() >> 32;
  info.pid = pid;
  bpf_get_current_comm(info.name, sizeof(info.name));

  // Get the protocol and the IP version
  bpf_probe_read(&info.proto, sizeof(u8), &fl->u.__fl_common.flowic_proto);
  info.is_ipv6 = sk->sk_family == AF_INET6;

  // Get packet information
  if (sk->sk_family == AF_INET) {
    bpf_probe_read(&info.dst, sizeof(u32), &fl->u.ip4.daddr);
    bpf_probe_read(&info.src, sizeof(u32), &fl->u.ip4.saddr);

    bpf_probe_read(&info.type, sizeof(u16), &fl->u.ip4.uli.icmpt.type);
    bpf_probe_read(&info.code, sizeof(u16), &fl->u.ip4.uli.icmpt.code);
    bpf_probe_read(&info.dport, sizeof(u16), &fl->u.ip4.uli.ports.dport);
    bpf_probe_read(&info.sport, sizeof(u16), &fl->u.ip4.uli.ports.sport);

  } else if (sk->sk_family == AF_INET6) {
    bpf_probe_read(&info.dst, sizeof(u32) * 4, &fl->u.ip6.daddr.in6_u.u6_addr32);
    bpf_probe_read(&info.src, sizeof(u32) * 4, &fl->u.ip6.saddr.in6_u.u6_addr32);

    bpf_probe_read(&info.type, sizeof(u16), &fl->u.ip6.uli.icmpt.type);
    bpf_probe_read(&info.code, sizeof(u16), &fl->u.ip6.uli.icmpt.code);
    bpf_probe_read(&info.dport, sizeof(u16), &fl->u.ip6.uli.ports.dport);
    bpf_probe_read(&info.sport, sizeof(u16), &fl->u.ip6.uli.ports.sport);
  } else {
    return 0;
  }

  flowi_map.push(&info, 0);

  return 0;
}
