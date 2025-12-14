#include "netsniff/util.h"
#include <stdio.h>
#include <string.h>

const char *ns_proto_name(ns_ip_proto_t p) {

  switch (p) {
  case NS_IPPROTO_TCP:
    return "TCP";
  case NS_IPPROTO_UDP:
    return "UDP";
  case NS_IPPROTO_ICMP:
    return "ICMP";
  case NS_IPPROTO_ICMPV6:
    return "ICMPv6";
  case NS_IPPROTO_ARP:
    return "ARP";
  case NS_IPPROTO_UNKNOWN:
    return "NON-IP";
  default:
    return "OTHER";
  }
}

static int ns_is_ipv6(const char *ip) { return ip && strchr(ip, ':') != NULL; }

static void ns_print_endpoint(const char *ip, uint16_t port, int with_port) {
  if (!ip)
    return;

  if (with_port) {
    if (ns_is_ipv6(ip))
      printf("[%s]:%u", ip, port);
    else
      printf("%s:%u", ip, port);
  } else {
    printf("%s", ip);
  }
}

static const char *ns_service_name(ns_ip_proto_t proto, uint16_t port) {
  if (proto == NS_IPPROTO_TCP || proto == NS_IPPROTO_UDP) {
    switch (port) {
    case 53:
      return "dns";
    case 80:
      return "http";
    case 123:
      return "ntp";
    case 443:
      return "https";
    case 1900:
      return "ssdp";
    case 5228:
      return "google/xmpp";
    default:
      return NULL;
    }
  }
  return NULL;
}

void ns_print_packet(const packet_info *info) {
  if (!info)
    return;

  int has_ports =
      (info->proto == NS_IPPROTO_TCP || info->proto == NS_IPPROTO_UDP);

  ns_print_endpoint(info->src_ip, info->src_port, has_ports);
  printf(" -> ");
  ns_print_endpoint(info->dst_ip, info->dst_port, has_ports);
  printf(" %s", ns_proto_name(info->proto));

  const char *svc = NULL;
  if (has_ports)
    svc = ns_service_name(info->proto, info->dst_port);
  if (svc)
    printf(" (%s)", svc);
  printf("\n");
}
