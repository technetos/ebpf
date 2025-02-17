#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 4096);
} ringbuf SEC(".maps");

const unsigned int SIZE = 512;

SEC("xdp")
int read_from_interface(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  struct ethhdr *eth = data;
  struct iphdr *iph = data + sizeof(*eth);
  struct udphdr *udp = data + sizeof(*eth) + sizeof(*iph);

  unsigned int offset = sizeof(*eth) + sizeof(*iph) + sizeof(*udp);

  if (data + offset > data_end) {
    bpf_printk("Bounds check failed, pointer past data_end");
    return XDP_PASS;
  }

  if (eth->h_proto != bpf_htons(ETH_P_IP)) {
    return XDP_PASS;
  }

  if (iph->protocol != IPPROTO_UDP) {
    return XDP_PASS;
  }

  // Length of the UDP payload
  unsigned int payload_len = bpf_ntohs(udp->len) - sizeof(*udp);

  if (data + offset + payload_len > data_end) {
    return XDP_PASS;
  }

  unsigned char *payload = bpf_ringbuf_reserve(&ringbuf, SIZE, 0);

  if (!payload) {
    return XDP_PASS;
  }

  unsigned int i = 0;
  for (i = 0; i < payload_len && data + offset + i < data_end; i++) {
    void *payload_data = data + offset + i;
    if (payload_data) {
      payload[i] = *(unsigned char *)payload_data;
    }
  }

  bpf_ringbuf_submit(payload, BPF_RB_FORCE_WAKEUP);

  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
