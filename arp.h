/*
 * Copyright (c) 2003, 2004 Niels Provos <provos@citi.umich.edu>
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

#ifndef _ARP_
#define _ARP_

#define ARP_REQUEST_SUCESS -1

struct arp_req {
	SPLAY_ENTRY(arp_req)	next_pa;
	SPLAY_ENTRY(arp_req)	next_ha;
	
	struct interface	*inter;

	int			cnt;

	struct event		*active;
	struct event		*discover;

	/* The address that we want to know about */
	struct addr		pa;
	struct addr		ha;

	/* The address that is requesting the information */
	struct addr		src_pa;
	struct addr		src_ha;

	void *arg;
	void (*cb)(struct arp_req *, int, void *, int);
	
	int flags;
	struct template	       *owner;	/* template this req refers to */
};

#define ARP_INTERNAL	0x01	/* an internal address, created by us */
#define ARP_EXTERNAL	0x02	/* an address discovered by us */

void arp_init(void);
void arp_recv_cb(u_char *, const struct pcap_pkthdr *, const u_char *);

struct arp_req *arp_new(struct interface *,
    struct addr *src_pa, struct addr *src_ha,
    struct addr *pa, struct addr *ha);
void arp_free(struct arp_req *);

void arp_request(struct interface *,
    struct addr *src_pa, struct addr *src_ha,
    struct addr *dst, void (*)(struct arp_req *, int, void *, int), void *);
struct arp_req *arp_find(struct addr *);

/* Set if we need to listen to arp traffic */
extern int need_arp;

#endif /* _ARP_ */
