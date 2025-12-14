#ifndef NETSNIFF_CLI_H
#define NETSNIFF_CLI_H

#include "netsniff/decode.h"
#include <stdbool.h>

typedef struct {
  const char *iface;
  const char *filter;
  int count;        // -1 = unlimited
  bool stats;
  int interval_sec; // default 1
  bool list_ifaces;
  bool once;        // Capture and decode a single packet, then exit (semantic alias for --count 1).
  const char *pcap_file; // Read packets from a pcap file instead of a live interface
} ns_config;

int ns_parse_args(int argc, char **argv, ns_config *out);
void ns_print_help(const char *prog);

#endif
