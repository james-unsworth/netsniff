#include "netsniff/decode_l4.h"

static const size_t NS_TCP_HEADER_MIN_LEN = 20;
static const size_t NS_UDP_HEADER_LEN = 8;

uint16_t ns_read_be16(const uint8_t *p) {
  return (uint16_t)((p[0] << 8) | p[1]);
}

int ns_decode_l4_ports(const struct pcap_pkthdr *hdr, const uint8_t *data,
                       size_t l4_offset, ns_ip_proto_t proto,
                       packet_info *out) {
  if (!hdr || !data || !out)
    return -1;

  out->src_port = 0;
  out->dst_port = 0;

  if (proto == NS_IPPROTO_TCP) {
    if (hdr->caplen < l4_offset + NS_TCP_HEADER_MIN_LEN)
      return -1;
    out->src_port = ns_read_be16(data + l4_offset);
    out->dst_port = ns_read_be16(data + l4_offset + 2);
    return 0;
  }

  if (proto == NS_IPPROTO_UDP) {
    if (hdr->caplen < l4_offset + NS_UDP_HEADER_LEN)
      return -1;
    out->src_port = ns_read_be16(data + l4_offset);
    out->dst_port = ns_read_be16(data + l4_offset + 2);
    return 0;
  }

  // non-TCP/UDP: ports stay 0
  return 0;
}
