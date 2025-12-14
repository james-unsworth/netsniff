#ifndef NETSNIFF_DECODE_H
#define NETSNIFF_DECODE_H

#include <pcap/pcap.h>
#include <stdint.h>

typedef enum {
  NS_IPPROTO_ICMP = 1,
  NS_IPPROTO_TCP = 6,
  NS_IPPROTO_UDP = 17,
  NS_IPPROTO_ICMPV6 = 58,
  NS_IPPROTO_ARP = 254,
  NS_IPPROTO_UNKNOWN = 0
} ns_ip_proto_t;

typedef struct {
  char src_ip[46];
  char dst_ip[46];
  ns_ip_proto_t proto;
  uint16_t src_port;
  uint16_t dst_port;
} packet_info;

int ns_decode_ethernet(const struct pcap_pkthdr *hdr, const uint8_t *data,
                       packet_info *out);

int ns_decode_ipv4(const struct pcap_pkthdr *hdr, const uint8_t *data,
                   size_t offset, packet_info *out);

int ns_decode_ipv6(const struct pcap_pkthdr *hdr, const uint8_t *data,
                   size_t offset, packet_info *out);

#endif
