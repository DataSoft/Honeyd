/*
 * Copyright (c) 2002, 2003, 2004 Niels Provos <provos@citi.umich.edu>
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
#ifndef _ROUTER_H_
#define _ROUTER_H_

struct network;

enum route_type {ROUTE_LINK = 0, ROUTE_NET, ROUTE_UNREACH, ROUTE_TUNNEL};

struct link_drop {
	int low;
	int high;
};

struct link_entry {
	SPLAY_ENTRY(link_entry) node;

	struct addr dst;

	/* Link characteristics */
	int latency;
	int packetloss;		/* percent x 100 */
	int bandwidth;		/* multiplier to get delay in us */
	int divider;		/* value to divide by */

	struct link_drop red;	/* Random Early Drop thresholds */

	struct timeval tv_busy;	/* time that we are busy sending */
};

struct router_entry {
	SPLAY_ENTRY(router_entry) node;

	struct router *parent;
	struct router *gw;
	struct addr net;

	struct link_entry *link;
	
	enum route_type type;

	struct addr tunnel_src;
	struct addr tunnel_dst;
};

struct router {
	SPLAY_ENTRY(router) node;

	struct network *routes;

	struct addr addr;		/* IP address of router */
	struct addr network;		/* Responsible (entry router only) */

	SPLAY_HEAD(linktree, link_entry) links;

	int flags;
};

#define ROUTER_ISENTRY	0x0001

extern int router_used;
extern struct network *entry_routers;

void router_init(void);
struct router *router_new(struct addr *);
int router_start(struct addr *, struct addr *);
void router_end(void);
struct router *router_find(struct addr *);
int router_add_link(struct router *, struct addr *);
int router_add_unreach(struct router *, struct addr *);
int router_add_net(struct router *, struct addr *, struct router *, int, int,
    int, struct link_drop *);
int router_add_tunnel(struct router *, struct addr *, struct addr *, struct addr *);

struct link_entry *link_entry_find(struct linktree *, struct addr *);
struct link_entry *link_entry_new(struct addr *);

struct router_entry *router_find_tunnel(struct addr *, struct addr *);
struct router_entry *router_find_nexthop(struct router *, struct addr *);

void *network_lookup(struct network *, struct addr *);
#endif
