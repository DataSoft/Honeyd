/*
 * Copyright (c) 2003 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef _INTERFACE_
#define _INTERFACE_

#define MAX_INTERFACE_ALIASES 4

struct interface {
	TAILQ_ENTRY(interface) next;

	struct intf_entry if_ent;
	struct addr aliases[MAX_INTERFACE_ALIASES];

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
