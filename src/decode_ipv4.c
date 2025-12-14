#include "netsniff/decode.h"
#include "netsniff/decode_l4.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pcap/pcap.h>
#include <stdint.h>
#include <string.h>

static const size_t NS_IPV4_MIN_HEADER_LEN = 20;
static const uint8_t NS_IPV4_VERSION = 4;
static const size_t NS_IPV4_PROTO_OFFSET = 9;
static const size_t NS_IPV4_SRC_OFFSET = 12;
static const size_t NS_IPV4_DST_OFFSET = 16;
static const size_t NS_IPV4_ADDR_LEN = 4;
static const uint8_t NS_IPV4_VER_SHIFT = 4;
static const uint8_t NS_IPV4_IHL_MASK = 0x0F;

int ns_decode_ipv4(const struct pcap_pkthdr *hdr, const uint8_t *data,
                   size_t offset, packet_info *out) {
  if (!hdr || !data || !out)
    return -1;

  // minimum IPv4 header = 20 bytes
  if (hdr->caplen < offset + NS_IPV4_MIN_HEADER_LEN)
    return -1;

  const uint8_t *ip = data + offset;

  uint8_t version = (uint8_t)(ip[0] >> NS_IPV4_VER_SHIFT);
  uint8_t ihl = (uint8_t)(ip[0] & NS_IPV4_IHL_MASK);

  if (version != NS_IPV4_VERSION)
    return -1;

  size_t ip_header_len = (size_t)ihl * 4;
  if (ip_header_len < NS_IPV4_MIN_HEADER_LEN)
    return -1;
  if (hdr->caplen < offset + ip_header_len)
    return -1;

  out->proto = (ns_ip_proto_t)ip[NS_IPV4_PROTO_OFFSET];

  struct in_addr src, dst;
  memcpy(&src, ip + NS_IPV4_SRC_OFFSET, NS_IPV4_ADDR_LEN);
  memcpy(&dst, ip + NS_IPV4_DST_OFFSET, NS_IPV4_ADDR_LEN);

  if (!inet_ntop(AF_INET, &src, out->src_ip, sizeof out->src_ip))
    return -1;
  if (!inet_ntop(AF_INET, &dst, out->dst_ip, sizeof out->dst_ip))
    return -1;

  size_t l4_offset = offset + ip_header_len;
  if (ns_decode_l4_ports(hdr, data, l4_offset, out->proto, out) != 0)
    return -1;
  return 0;
}
