#ifndef NETSNIFF_UTIL_H
#define NETSNIFF_UTIL_H

#include "netsniff/decode.h"

const char *ns_proto_name(ns_ip_proto_t p);
void ns_print_packet(const packet_info *info);

#endif
