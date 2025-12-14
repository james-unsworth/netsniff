#include "netsniff/cli.h"
#include "netsniff/decode.h"
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void ns_print_help(const char *prog) {
  printf("netsniff — simple packet capture tool\n\n"
         "Usage:\n"
         "  %s [options]\n\n"
         "Options:\n"
         "  -h, --help            Show this help and exit\n"
         "  --list-ifaces         List available capture interfaces and exit\n"
         "  -i, --iface <name>     Capture on interface <name>\n"
         "  --count <n>            Stop after capturing <n> packets (default: "
         "unlimited)\n"
         "  --stats               Print periodic stats instead of per-packet output\n"
         "  --interval <sec>       Stats reporting interval in seconds (default: 1). Implies --stats\n"
         "  --once                Capture and decode a single packet, then exit (equivalent to --count 1)\n"
         "  -r, --read <file>      Read packets from a pcap file instead of live capture\n"
         "  -f, --filter <expr>    Apply a BPF capture filter\n\n"


         "Notes:\n"
         "  This tool uses libpcap and requires capture permissions.\n",
         prog);
}

int ns_parse_args(int argc, char **argv, ns_config *out) {
  if (!out) return 2;

  out->iface = NULL;
  out->filter = NULL;
  out->count = -1;
  out->stats = false;
  out->interval_sec = 1;
  out->list_ifaces = false;
  out->once = false;
  out->pcap_file = NULL;

  for (int i = 1; i < argc; i++) {
    if (!strcmp(argv[i], "--"))
      break;

    if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
      return 1;
    }

    if (!strcmp(argv[i], "--list-ifaces")) {
      out->list_ifaces = true;
      return 0;
    }

    if (!strcmp(argv[i], "-i") || !strcmp(argv[i], "--iface")) {
      if (i + 1 >= argc || argv[i + 1][0] == '-') {
        fprintf(stderr, "Missing value for %s\n", argv[i]);
        return 2;
      }
      out->iface = argv[i + 1];
      i++;
      continue;
    }

    if (!strcmp(argv[i], "-r") || !strcmp(argv[i], "--read")) {
      if (i + 1 >= argc || argv[i + 1][0] == '-') {
        fprintf(stderr, "Missing value for %s\n", argv[i]);
        return 2;
      }
      out->pcap_file = argv[i + 1];
      i++;
      continue;
    }

    if (!strcmp(argv[i], "-f") || !strcmp(argv[i], "--filter")) {
      if (i + 1 >= argc || argv[i + 1][0] == '-') {
        fprintf(stderr, "Missing value for %s\n", argv[i]);
          return 2;
      }
      out->filter = argv[i + 1];
      i++;
      continue;
    }

    if (!strcmp(argv[i], "--count")) {
      if (i + 1 >= argc || argv[i + 1][0] == '-') {
        fprintf(stderr, "Missing value for --count\n");
        return 2;
      }

      errno = 0;
      char *end = NULL;
      long v = strtol(argv[i + 1], &end, 10);

      if (errno != 0 || end == argv[i + 1] || *end != '\0') {
        fprintf(stderr, "Invalid integer for --count: %s\n", argv[i + 1]);
        return 2;
      }

      if (v <= 0 || v > INT_MAX) {
        fprintf(stderr, "--count must be in range 1..%d\n", INT_MAX);
        return 2;
      }

      out->count = (int)v;
      i++;
      continue;
    }

    if (!strcmp(argv[i], "--interval")) {
      if (i + 1 >= argc || argv[i + 1][0] == '-') {
        fprintf(stderr, "Missing value for --interval\n");
        return 2;
    }

      errno = 0;
      char *end = NULL;
      long v = strtol(argv[i + 1], &end, 10);

      if (errno != 0 || end == argv[i + 1] || *end != '\0') {
        fprintf(stderr, "Invalid integer for --interval: %s\n", argv[i + 1]);
        return 2;
      }

      if (v < 1 || v > INT_MAX) {
        fprintf(stderr, "--interval must be in range 1..%d\n", INT_MAX);
        return 2;
      }

      out->interval_sec = (int)v;
      out->stats = true;
      i++;
      continue;
    }

    if (!strcmp(argv[i], "--stats")) {
      out->stats = true;
      continue;
    }

     if (!strcmp(argv[i], "--once")) {
      out->once = true;
      continue;
    }

    if (argv[i][0] == '-') {
      fprintf(stderr, "Unknown option: %s\n", argv[i]);
      return 2;
    }

  }
  
  if (out->pcap_file && out->iface) {
    fprintf(stderr, "--read cannot be used with --iface\n");
    return 2;
  }

  if (out->filter && out->filter[0] == '\0') {
    fprintf(stderr, "--filter must not be empty\n");
    return 2;
  }

  if (out->once) {
      out->stats = false;
      out->count = 1;
  }

  return 0;
}
