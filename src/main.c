#include "netsniff/capture.h"
#include "netsniff/cli.h"
#include "netsniff/ifaces.h"
#include <stdio.h>

int main(int argc, char **argv) {
  ns_config cfg;
  char iface_buf[128];

  int rc = ns_parse_args(argc, argv, &cfg);

  if (rc == 1) {
    ns_print_help(argv[0]);
    return 1;
  }

  if (rc != 0) {
    fprintf(stderr, "Try %s --help\n", argv[0]);
    return 2;
  }

  if (cfg.list_ifaces) {
    return ns_list_ifaces();
  }

  if (cfg.pcap_file) {
    printf("Reading pcap file: %s\n", cfg.pcap_file);
    return ns_capture_loop(&cfg);
  }

  if (!cfg.iface) {
    if (ns_pick_default_iface(iface_buf, sizeof iface_buf) != 0) {
      fprintf(stderr, "No suitable interfaces found.\n");
      return 1;
    }
    cfg.iface = iface_buf;
    printf("Using default interface: %s\n", cfg.iface);
  } else {
    printf("Using interface: %s\n", cfg.iface);
  }
  return ns_capture_loop(&cfg);
}
