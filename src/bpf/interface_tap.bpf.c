#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 4096);
} ringbuf SEC(".maps");

SEC("xdp")
int read_from_interface(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  struct ethhdr *eth = data;
  struct iphdr *iph = data + sizeof(*eth);
  struct udphdr *udp = data + sizeof(*eth) + sizeof(*iph);

  if (data + sizeof(*eth) + sizeof(*iph) + sizeof(*udp) > data_end) {
    bpf_printk("Bounds check failed, pointer past data_end");
    return XDP_PASS;
  }

  if (eth->h_proto != bpf_htons(ETH_P_IP)) {
    return XDP_PASS;
  }

  if (iph->protocol == IPPROTO_UDP) {
    // Length of the UDP payload
    unsigned int payload_size = bpf_ntohs(udp->len) - sizeof(*udp);
    // Start of the UDP payload
    unsigned char *payload = (unsigned char *)udp + sizeof(*udp);

    bpf_ringbuf_output(&ringbuf, &payload, payload_size, 0);
  }

  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
