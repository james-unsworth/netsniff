#include "netsniff/capture.h"
#include "netsniff/cli.h"
#include "netsniff/decode.h"
#include "netsniff/util.h"
#include <pcap/pcap.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define NS_SNAPLEN 65535        // capture full packets
#define NS_PROMISC 1            // enable promiscuous mode
#define NS_READ_TIMEOUT_MS 1000 // read timeout in milliseconds

typedef struct {
  unsigned long total, tcp, udp, icmp, icmpv6, other;
  unsigned long port_53, port_80, port_443, port_other;
  unsigned long bytes;
  unsigned long capbytes;
} ns_stats;

/**
 * @brief Update rolling statistics counters from a decoded packet.
 *
 * Increments protocol counters and (for TCP/UDP) destination-port buckets.
 * Assumes @p info represents a successfully decoded packet.
 *
 * @param[in,out] s     Statistics accumulator.
 * @param[in]     info  Decoded packet metadata.
 */
static void ns_stats_update(ns_stats *s, const packet_info *info) {
  if (!s || !info)
    return;

  s->total++;

  switch (info->proto) {
  case NS_IPPROTO_TCP:
    s->tcp++;
    break;
  case NS_IPPROTO_UDP:
    s->udp++;
    break;
  case NS_IPPROTO_ICMP:
    s->icmp++;
    break;
  case NS_IPPROTO_ICMPV6:
    s->icmpv6++;
    break;
  default:
    s->other++;
    break;
  }

  if (info->proto == NS_IPPROTO_TCP || info->proto == NS_IPPROTO_UDP) {
    switch (info->dst_port) {
    case 53:
      s->port_53++;
      break;
    case 80:
      s->port_80++;
      break;
    case 443:
      s->port_443++;
      break;
    default:
      s->port_other++;
      break;
    }
  }
}

/**
 * @brief Print the current statistics snapshot and reset counters.
 *
 * Intended to be called periodically. Uses @p interval_sec to compute a
 * packets-per-second rate and then clears all counters in @p s.
 *
 * @param[in,out] s             Statistics accumulator.
 * @param[in]     interval_sec  Reporting interval in seconds (must be > 0).
 */
static void ns_stats_print_reset(ns_stats *s, int interval_sec) {
  if (!s || interval_sec <= 0)
    return;

  unsigned long pps = s->total / (unsigned long)interval_sec;

  printf("rate=%lu packets/s total=%lu tcp=%lu udp=%lu icmp=%lu icmpv6=%lu "
         "other=%lu | dst 53=%lu 80=%lu 443=%lu other=%lu\n",
         pps, s->total, s->tcp, s->udp, s->icmp, s->icmpv6, s->other,
         s->port_53, s->port_80, s->port_443, s->port_other);

  memset(s, 0, sizeof *s);
}

/**
 * @brief Capture packets on an interface and report decoded output.
 *
 * Opens a live libpcap capture on cfg->iface and processes packets in a loop.
 * Successfully decoded packets update statistics and are either printed
 * individually or aggregated into periodic stats output.
 *
 * The loop terminates when the requested packet count is reached (cfg->count >=
 * 0), libpcap signals EOF, or a libpcap error occurs.
 *
 * When cfg->stats is enabled, statistics are printed and reset every
 * max(cfg->interval_sec, 1) seconds.
 *
 * @param[in] cfg Capture configuration (must not be NULL; cfg->iface must not
 * be NULL).
 * @return 0 on normal termination; non-zero on error.
 */
int ns_capture_loop(ns_config *cfg) {
  if (!cfg || (!cfg->iface && !cfg->pcap_file)) {
    fprintf(stderr, "ns_capture_loop: must provide iface or pcap_file\n");
    return 1;
  }
  const int interval_sec = (cfg->interval_sec <= 0) ? 1 : cfg->interval_sec;

  ns_stats st = {0};
  char errbuf[PCAP_ERRBUF_SIZE];

 
  pcap_t *handle = NULL;

  if (cfg->pcap_file) {
    handle = pcap_open_offline(cfg->pcap_file, errbuf);
    if (!handle) {
      fprintf(stderr, "pcap_open_offline failed on %s: %s\n", cfg->pcap_file, errbuf);
      return 1;
    }
  } else {
    handle = pcap_open_live(cfg->iface, NS_SNAPLEN, NS_PROMISC,
                          NS_READ_TIMEOUT_MS, errbuf);
    if (!handle) {
      fprintf(stderr, "pcap_open_live failed on %s: %s\n", cfg->iface, errbuf);
      return 1;
    }
  }

  int dlt = pcap_datalink(handle);
  if (dlt != DLT_EN10MB) {
    fprintf(stderr, "Unsupported datalink: %s (%d). Only Ethernet (DLT_EN10MB) is supported.\n",
          pcap_datalink_val_to_name(dlt), dlt);
    pcap_close(handle);
    return 1;
  }


  if (cfg->filter && cfg->filter[0] != '\0') {
    struct bpf_program prog = {0};

    bpf_u_int32 netmask = PCAP_NETMASK_UNKNOWN;
    if (!cfg->pcap_file && cfg->iface) {
      bpf_u_int32 net = 0;
      if (pcap_lookupnet(cfg->iface, &net, &netmask, errbuf) != 0) {
        netmask = PCAP_NETMASK_UNKNOWN;
      }
    }

    if (pcap_compile(handle, &prog, cfg->filter, 1, PCAP_NETMASK_UNKNOWN) != 0) {
      fprintf(stderr, "pcap_compile failed: %s\n", pcap_geterr(handle));
      pcap_close(handle);
      return 1;
    }

    if (pcap_setfilter(handle, &prog) != 0) {
      fprintf(stderr, "pcap_setfilter failed: %s\n", pcap_geterr(handle));
      pcap_freecode(&prog);
      pcap_close(handle);
      return 1;
    }

    pcap_freecode(&prog);
  }

  int exit_code = 0;
  int decoded = 0;
  time_t last = time(NULL);

  while (cfg->count < 0 || decoded < cfg->count) {
    struct pcap_pkthdr *hdr = NULL;
    const u_char *data = NULL;

    int rc = pcap_next_ex(handle, &hdr, &data);

    if (rc == 1) {
      packet_info info;
      if (ns_decode_ethernet(hdr, data, &info) == 0) {
        decoded++;

        ns_stats_update(&st, &info);

        if (!cfg->stats) {
          ns_print_packet(&info);
        }
      }
    } else if (rc == -1) {
      fprintf(stderr, "pcap_next_ex error: %s\n", pcap_geterr(handle));
      exit_code = 1;
      break;
    } else if (rc == -2) {
      exit_code = 0;
      break;
    } else if (rc == 0) {
      // timeout; nothing to decode
    }

    time_t now = time(NULL);
    if (cfg->stats && now - last >= interval_sec) {
      ns_stats_print_reset(&st, interval_sec);
      last = now;
    }
  }
  
  if (!cfg->pcap_file && cfg->stats && st.total > 0) {
    ns_stats_print_reset(&st, interval_sec);
  }

  pcap_close(handle);
  return exit_code;
}
