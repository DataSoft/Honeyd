/*
 * Copyright (c) 2003 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 *
 * <LICENSEHERE>
 */

#ifndef _INTERFACE_
#define _INTERFACE_

struct interface {
	TAILQ_ENTRY(interface) next;

	struct intf_entry if_ent;
	int if_addrbits;
	struct event if_recvev;
	pcap_t *if_pcap;
	eth_t *if_eth;
	int if_dloff;

	char if_filter[1024];
};

/* disables event methods that do not work with bpf */
void interface_prevent_init(void);

void interface_initialize(pcap_handler);
void interface_init(char *, int, char **);
struct interface *interface_get(int);
struct interface *interface_find(char *);
struct interface *interface_find_addr(struct addr *);
struct interface *interface_find_responsible(struct addr *);

int interface_count(void);

void interface_close(struct interface *);
void interface_close_all(void);

void interface_test(void);

#endif /* _INTERFACE_ */
