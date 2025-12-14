#ifndef NETSNIFF_DECODE_L4_H
#define NETSNIFF_DECODE_L4_H

#include "netsniff/decode.h"
#include <pcap/pcap.h>
#include <stddef.h>
#include <stdint.h>

uint16_t ns_read_be16(const uint8_t *p);
int ns_decode_l4_ports(const struct pcap_pkthdr *hdr, const uint8_t *data,
                       size_t l4_offset, ns_ip_proto_t proto, packet_info *out);

#endif
