#include "netsniff/decode.h"
#include "netsniff/decode_l4.h"
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>


/* Ethernet */
static const size_t NS_ETH_HEADER_LEN = 14;
static const size_t NS_ETH_ADDR_LEN = 6;
static const size_t NS_ETH_TYPE_OFFSET = NS_ETH_ADDR_LEN * 2;
static const size_t NS_VLAN_TAG_LEN = 4;

static const uint16_t NS_ETHERTYPE_IPV4 = 0x0800;
static const uint16_t NS_ETHERTYPE_ARP  = 0x0806;
static const uint16_t NS_ETHERTYPE_IPV6 = 0x86DD;
static const uint16_t NS_ETHERTYPE_VLAN = 0x8100;

/* ARP (Ethernet / IPv4) */
static const size_t NS_ARP_LEN = 28;

static const size_t NS_ARP_HTYPE_OFF = 0;
static const size_t NS_ARP_PTYPE_OFF = 2;
static const size_t NS_ARP_HLEN_OFF  = 4;
static const size_t NS_ARP_PLEN_OFF  = 5;

static const size_t NS_ARP_SPA_OFF = 14;
static const size_t NS_ARP_TPA_OFF   = 24;

static const uint16_t NS_ARP_HTYPE_ETH = 1;
static const uint8_t  NS_ARP_HLEN_ETH  = 6;
static const uint8_t  NS_ARP_PLEN_IPV4 = 4;


int ns_decode_ethernet(const struct pcap_pkthdr *hdr, const uint8_t *data,
                       packet_info *out) {
  if (!hdr || !data || !out)
    return -1;

  memset(out, 0, sizeof *out);

  if (hdr->caplen < NS_ETH_HEADER_LEN)
    return -1;

  uint16_t ethertype = ns_read_be16(data + NS_ETH_TYPE_OFFSET);
  size_t offset = NS_ETH_HEADER_LEN;

  if (ethertype == NS_ETHERTYPE_VLAN) {
    if (hdr->caplen < NS_ETH_HEADER_LEN + NS_VLAN_TAG_LEN)
      return -1;

    offset += NS_VLAN_TAG_LEN;
    ethertype = ns_read_be16(data + (offset - 2));
  }

  if (ethertype == NS_ETHERTYPE_IPV4) {
    return ns_decode_ipv4(hdr, data, offset, out);
  }

  if (ethertype == NS_ETHERTYPE_IPV6) {
    return ns_decode_ipv6(hdr, data, offset, out);
  }

  if (ethertype == NS_ETHERTYPE_ARP) {
    if (hdr->caplen < offset + NS_ARP_LEN)
      return -1;

    const uint8_t *arp = data + offset;

    uint16_t htype = ns_read_be16(arp + NS_ARP_HTYPE_OFF);
    uint16_t ptype = ns_read_be16(arp + NS_ARP_PTYPE_OFF);
    uint8_t hlen   = arp[NS_ARP_HLEN_OFF];
    uint8_t plen   = arp[NS_ARP_PLEN_OFF];

    if (htype != NS_ARP_HTYPE_ETH || ptype != NS_ETHERTYPE_IPV4 ||
        hlen != NS_ARP_HLEN_ETH || plen != NS_ARP_PLEN_IPV4) {
      return -1;
    }

    struct in_addr spa, tpa;
    memcpy(&spa, arp + NS_ARP_SPA_OFF, 4);
    memcpy(&tpa, arp + NS_ARP_TPA_OFF, 4);

    if (!inet_ntop(AF_INET, &spa, out->src_ip, sizeof out->src_ip))
      return -1;
    if (!inet_ntop(AF_INET, &tpa, out->dst_ip, sizeof out->dst_ip))
      return -1;

    out->proto = NS_IPPROTO_ARP;   
    out->src_port = 0;
    out->dst_port = 0;

    return 0;
  }
  snprintf(out->src_ip, sizeof out->src_ip, "?");
  snprintf(out->dst_ip, sizeof out->dst_ip, "?");
  out->proto = NS_IPPROTO_UNKNOWN;
  return 0;
}
