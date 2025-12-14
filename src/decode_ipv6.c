#include "netsniff/decode.h"
#include "netsniff/decode_l4.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>

static const size_t NS_IPV6_HEADER_LEN = 40;
static const uint8_t NS_IPV6_VERSION = 6;
static const size_t NS_IPV6_NEXT_HEADER_OFFSET = 6;
static const size_t NS_IPV6_SRC_OFFSET = 8;
static const size_t NS_IPV6_DST_OFFSET = 24;
static const size_t NS_IPV6_ADDR_LEN = 16;
static const uint8_t NS_IPV6_VER_SHIFT = 4;

int ns_decode_ipv6(const struct pcap_pkthdr *hdr, const uint8_t *data,
                   size_t offset, packet_info *out) {

  if (!out)
    return -1;

  if (hdr->caplen < offset + NS_IPV6_HEADER_LEN)
    return -1;

  const uint8_t *ip6 = data + offset;

  uint8_t version = (uint8_t)(ip6[0] >> NS_IPV6_VER_SHIFT);
  if (version != NS_IPV6_VERSION)
    return -1;

  out->proto = (ns_ip_proto_t)ip6[NS_IPV6_NEXT_HEADER_OFFSET];

  struct in6_addr src, dst;
  memcpy(&src, ip6 + NS_IPV6_SRC_OFFSET, NS_IPV6_ADDR_LEN);
  memcpy(&dst, ip6 + NS_IPV6_DST_OFFSET, NS_IPV6_ADDR_LEN);

  if (!inet_ntop(AF_INET6, &src, out->src_ip, sizeof out->src_ip))
    return -1;
  if (!inet_ntop(AF_INET6, &dst, out->dst_ip, sizeof out->dst_ip))
    return -1;

  size_t l4_offset = offset + NS_IPV6_HEADER_LEN;
  if (ns_decode_l4_ports(hdr, data, l4_offset, out->proto, out) != 0)
    return -1;

  return 0;
}
