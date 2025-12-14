#include <pcap/pcap.h>
#include <stdio.h>
#include <string.h>

/**
 * @brief List available capture interfaces.
 *
 * Uses libpcap to enumerate all capture devices visible to the process and
 * prints them to stdout for user inspection/selection.
 *
 * @return 0 on success; non-zero on failure.
 */
int ns_list_ifaces(void) {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *alldevs = NULL;

  if (pcap_findalldevs(&alldevs, errbuf) != 0) {
    fprintf(stderr, "pcap_findalldevs failed: %s\n", errbuf);
    return 1;
  }

  int idx = 0;
  for (pcap_if_t *d = alldevs; d != NULL; d = d->next) {
    idx++;
    const char *name = d->name ? d->name : "(no-name)";
    const char *desc = d->description ? d->description : "";
    if (desc[0] != '\0') {
      printf("%2d) %s — %s\n", idx, name, desc);
    } else {
      printf("%2d) %s\n", idx, name);
    }
  }

  if (idx == 0) {
    puts("No interfaces found.");
  }

  pcap_freealldevs(alldevs);
  return 0;
}

/**
 * @brief Determine whether an interface name should be avoided as a default.
 *
 * Heuristic filter for “non-user-facing” or typically unsuitable interfaces
 * (e.g., tunnels, peer-to-peer Wi-Fi, bridge devices).
 *
 * @param name Interface name (may be NULL).
 * @return Non-zero if the interface should be avoided; 0 otherwise.
 */
static int ns_is_bad_default_iface_name(const char *name) {
  if (!name)
    return 1;
  return !strncmp(name, "utun", 4) || !strncmp(name, "awdl", 4) ||
         !strncmp(name, "llw", 3) || !strncmp(name, "bridge", 6);
}

/**
 * @brief Check whether an interface is a conventional BSD "en*" device.
 *
 * On BSD-derived systems (including macOS), interfaces named "enX" typically
 * correspond to physical Ethernet/Wi-Fi devices.
 *
 * @param name Interface name (may be NULL).
 * @return Non-zero if the name begins with "en"; 0 otherwise.
 */
static int ns_is_en_iface(const char *name) {
  return name && !strncmp(name, "en", 2);
}

/**
 * @brief Choose a default capture interface.
 *
 * Preference order:
 *  1) "en0" if present and not loopback
 *  2) Any "en*" device that is not loopback and not filtered out
 *  3) Any non-loopback device that is not filtered out
 *  4) Any device with a name (last resort)
 *
 * On success, writes the selected interface name into @p out.
 *
 * @param[out] out      Destination buffer for the chosen interface name.
 * @param      out_len  Size of @p out in bytes.
 * @return 0 on success; non-zero if no suitable interface is found or on error.
 */
int ns_pick_default_iface(char *out, size_t out_len) {
  if (!out || out_len == 0)
    return 1;
  out[0] = '\0';

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *alldevs = NULL;

  if (pcap_findalldevs(&alldevs, errbuf) != 0) {
    fprintf(stderr, "pcap_findalldevs failed: %s\n", errbuf);
    return 1;
  }

  const char *chosen = NULL;

  // prefer en0 if present
  for (pcap_if_t *d = alldevs; d != NULL; d = d->next) {
    if (d->name && !strcmp(d->name, "en0") && !(d->flags & PCAP_IF_LOOPBACK)) {
      chosen = d->name;
      break;
    }
  }

  // prefer any en*, non-loopback & not bad default
  if (!chosen) {
    for (pcap_if_t *d = alldevs; d != NULL; d = d->next) {
      if (d->name && ns_is_en_iface(d->name) &&
          !(d->flags & PCAP_IF_LOOPBACK) &&
          !ns_is_bad_default_iface_name(d->name)) {
        chosen = d->name;
        break;
      }
    }
  }

  // any non-loopback & not bad default
  if (!chosen) {
    for (pcap_if_t *d = alldevs; d != NULL; d = d->next) {
      if (d->name && !(d->flags & PCAP_IF_LOOPBACK) &&
          !ns_is_bad_default_iface_name(d->name)) {
        chosen = d->name;
        break;
      }
    }
  }

  // last resort -- any iface with a name
  if (!chosen) {
    for (pcap_if_t *d = alldevs; d != NULL; d = d->next) {
      if (d->name) {
        chosen = d->name;
        break;
      }
    }
  }

  if (!chosen) {
    pcap_freealldevs(alldevs);
    fprintf(stderr, "No interfaces found.\n");
    return 1;
  }

  snprintf(out, out_len, "%s", chosen);
  pcap_freealldevs(alldevs);
  return 0;
}
