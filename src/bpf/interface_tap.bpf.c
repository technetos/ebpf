#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800

struct hdr_cursor {
  void *pos;
};

int parse_eth_hdr(struct hdr_cursor *cursor, void *data_end, struct ethhdr **ethhdr);
int parse_ip_hdr(struct hdr_cursor *cursor, void *data_end, struct iphdr **iphdr);
int parse_udp_hdr(struct hdr_cursor *cursor, void *data_end, struct udphdr **udphdr);

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 4096);
} ringbuf SEC(".maps");


SEC("xdp")
int read_from_interface(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  if ((data + 1) > data_end) {
    return XDP_PASS;
  }

  struct hdr_cursor cursor;

  cursor.pos = data;

  struct ethhdr *eth;
  int eth_ret = parse_eth_hdr(&cursor, data_end, &eth);
  if (eth_ret != 0) {
    return XDP_PASS;
  }

  struct iphdr *ip;
  int ip_ret = parse_ip_hdr(&cursor, data_end, &ip);
  if (ip_ret != 0) {
    return XDP_PASS;
  }

  struct udphdr *udp;
  int udp_payload_len = parse_udp_hdr(&cursor, data_end, &udp);
  if (udp_payload_len < 0) {
    return XDP_PASS;
  }

  struct event *e = bpf_ringbuf_reserve(&ringbuf, sizeof(udp_payload_len), 0);
  if (!e) {
    return XDP_PASS;
  }

  bpf_printk("Got udp payload, sending to userspace");

  bpf_ringbuf_submit(udp + (sizeof(struct udphdr) - udp_payload_len), 0);

  bpf_printk("Captured UDP header (%d bytes)", sizeof(*udp));

  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

int parse_eth_hdr(struct hdr_cursor *cursor, void *data_end, struct ethhdr **ethhdr) {
  struct ethhdr *eth = cursor->pos;
  
  int header_size = sizeof(*eth);

  if ((cursor->pos + header_size) > data_end) {
    return -1;
  }

  cursor->pos += header_size;
  
  *ethhdr = eth;
  __be16 h_proto = eth->h_proto;

  if (h_proto != bpf_htons(ETH_P_IP)) {
    return -1;
  }

  return 0;
}

int parse_ip_hdr(struct hdr_cursor *cursor, void *data_end, struct iphdr **iphdr) {
  struct iphdr *iph = cursor->pos;

  if ((iph + 1) > data_end) {
    return -1;
  }

  if (iph->version != 4) {
    return -1;
  }

  if (iph->protocol != IPPROTO_UDP) {
    return -1;
  }

  // A byte is eight bits, so a 32-bit word is four bytes. The value of the IHL
  // field must be multiplied times four to get the length of the header in
  // bytes. For example, you will almost always see the value of that field is
  // 5, meaning that the header length is 20 bytes (5 * 4 bytes = 20 bytes).
  int header_size = iph->ihl * 4;

  if (header_size < sizeof(*iph)) {
    return -1;
  }

  if (cursor->pos += header_size > data_end) {
    return -1;
  }

  cursor->pos += header_size;

  *iphdr = iph;

  return 0;
}

int parse_udp_hdr(struct hdr_cursor *cursor, void *data_end, struct udphdr **udphdr) {
  struct udphdr *udp_hdr = cursor->pos;

  if ((udp_hdr + 1) > data_end) {
    return -1;
  }

  cursor->pos = udp_hdr + 1;

  *udphdr = udp_hdr;

  int len = bpf_ntohs(udp_hdr->len) - sizeof(struct udphdr);

  if (len < 0) {
    return -1;
  }

  return len;
}
