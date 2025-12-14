#ifndef NETSNIFF_IFACES_H
#define NETSNIFF_IFACES_H

int ns_list_ifaces(void);
int ns_pick_default_iface(char *out, size_t out_len);

#endif
