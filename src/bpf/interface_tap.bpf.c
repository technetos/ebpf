#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800

struct {
  __uint(type, BPF_MAP_TYPE_XSKMAP);
  __uint(max_entries, 1 << 24); // 16 MB buffer
  __type(key, int);
  __type(value, __u32);
} perf_map SEC(".maps");


SEC("raw_tracepoint")
int read_from_interface(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  struct ethhdr *eth = data;

  if ((void *)(eth + sizeof(struct ethhdr)) > data_end) {
    return XDP_PASS;
  }

  if (!bpf_ntohs(eth->h_proto) == ETH_P_IP) {
    return XDP_PASS;
  }

  struct iphdr *ip = (struct iphdr *)(eth + sizeof(struct ethhdr));

  if ((void *)(ip + sizeof(struct iphdr)) > data_end) {
    return XDP_PASS;
  }

  if (!ip->protocol == IPPROTO_UDP) {
    return XDP_PASS;
  }
  
  struct udphdr *udp = (struct udphdr *)(ip + sizeof(struct iphdr));

  if ((void *)(udp + sizeof(struct udphdr)) > data_end) {
    return XDP_PASS;
  }

  unsigned int payload_len = bpf_ntohs(udp->len) - sizeof(struct udphdr);
  unsigned char *payload = (unsigned char *)udp + sizeof(struct udphdr);

  if ((void *)payload + payload_len > data_end) {
    bpf_printk("udp_header_bytes too far past end of data");
    return XDP_PASS;
  }

  bpf_xdp_output(ctx, &perf_map, BPF_F_CURRENT_CPU, payload, payload_len);

  bpf_printk("Captured UDP header (%d bytes)", payload_len);

  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
