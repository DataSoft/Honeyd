/*
 * Copyright (c) 2012 DataSoft Corporation
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


#ifndef NPD_H_
#define NPD_H_

struct ndp_req {
	SPLAY_ENTRY(ndp_req)	next_pa;
	SPLAY_ENTRY(ndp_req)	next_ha;

	struct interface	*inter;

	// TODO: Document this
	int			cnt;

	struct event		active;
	struct event		discover;

	/* The address that we want to know about */
	struct addr		pa;
	struct addr		ha;

	/* The address that is requesting the information */
	struct addr		src_pa;
	struct addr		src_ha;

	void *arg;
	void (*cb)(struct ndp_req *, int, void *, int);

	int flags;
	struct template	       *owner;	/* template this req refers to */
};

#define ARP_INTERNAL	0x01	/* an internal address, created by us */
#define ARP_EXTERNAL	0x02	/* an address discovered by us */

void ndp_init();

struct ndp_req *ndp_new(struct interface *inter,
    struct addr *src_pa, struct addr *src_ha,
    struct addr *pa, struct addr *ha);


void ndp_request(struct interface *,
    struct addr *src_pa, struct addr *src_ha,
    struct addr *dst, void (*)(struct ndp_req *, int, void *, int), void *);

void ndp_discover(struct ndp_req *req, struct addr *ha);

struct ndp_req *ndp_find(struct addr *);

struct ndp_req * ndp_find(struct addr *addr);
void ndp_recv_cb(uint8_t type, struct tuple *summary, const struct icmpv6_msg_nd *query);

void ndp_send(eth_t *eth, uint icmpv6MessageType,
    struct addr linkLayerSource, struct addr linkLayerDestination,
    struct addr ipLayerSource, struct addr ipLayerDestination,
    struct addr advertisementLinkTarget, struct addr advertisementIpTarget);

void ndp_free(struct ndp_req *);


#endif /* NPD_H_ */
