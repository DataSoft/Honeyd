/*
 * Copyright (c) 2002, 2003 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 * 
 * <LICENSEHERE>
 */

#include <sys/types.h>
#include <sys/param.h>

#include "config.h"

#include <sys/queue.h>
#include <sys/tree.h>

#include <pcap.h>

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <dnet.h>

#undef timeout_pending
#undef timeout_initialized

#include <event.h>

#include "network.h"
#include "router.h"
#include "pool.h"
#include "interface.h"

/* Structure for routers */
static SPLAY_HEAD(routetree, router) routers;

int
routercompare(struct router *a, struct router *b)
{
	return (addr_cmp(&a->addr, &b->addr));
}

SPLAY_PROTOTYPE(routetree, router, node, routercompare);
SPLAY_GENERATE(routetree, router, node, routercompare);

/* Structure for links */

int
linkcompare(struct link_entry *a, struct link_entry *b)
{
	return (addr_cmp(&a->dst, &b->dst));
}

SPLAY_PROTOTYPE(linktree, link_entry, node, linkcompare);
SPLAY_GENERATE(linktree, link_entry, node, linkcompare);

/* Structure for tunnels */

static SPLAY_HEAD(tunneltree, router_entry) tunnels;

int
tunnelcompare(struct router_entry *a, struct router_entry *b)
{
	int res;

	if ((res = addr_cmp(&a->tunnel_src, &b->tunnel_src)) != 0)
		return (res);
	else
		return (addr_cmp(&a->tunnel_dst, &b->tunnel_dst));
}

SPLAY_PROTOTYPE(tunneltree, router_entry, node, tunnelcompare);
SPLAY_GENERATE(tunneltree, router_entry, node, tunnelcompare);

/* Exported */
int router_used = 0;
struct network *entry_routers = NULL;
struct network *reverse = NULL;

/* Internal */

static struct pool *pool_network;

/* Network trinary tree code by Bill Cheswick; stylified and munged by NP */

static void network_addnode(struct network **, struct network *,
    struct network **);

static void
network_copydata(struct network *dst, struct network *src)
{
	memmove(&dst->data, &src->data, sizeof(dst->data));
}

/*
 *  walk down a tree adding nodes back in
 */
static void
network_walkadd(struct network **root, struct network *net,
    struct network **netqueue)
{
	struct network *left, *right;

	left = net->left;
	right = net->right;
	net->left = NULL;
	net->right = NULL;

	network_addnode(root, net, netqueue);
	if (left != NULL)
		network_walkadd(root, left, netqueue);
	if (right != NULL)
		network_walkadd(root, right, netqueue);
}

/*
 *  calculate depth
 */
static void
network_calcd(struct network *net)
{
	struct network *tmp;
	int depth;

	if (net == NULL)
		return;

	depth = 0;
	if ((tmp = net->left) != NULL)
		depth = tmp->depth;

	tmp = net->right;
	if (tmp != NULL && tmp->depth > depth)
		depth = tmp->depth;

	tmp = net->mid;
	if (tmp != NULL && tmp->depth > depth)
		depth = tmp->depth;

	net->depth = depth + 1;
}

/*
 *  balance the tree at the current node
 */
static void
network_balancetree(struct network **cur)
{
	struct network *net, *left, *right;
	int dl, dr;

	/*
	 * if left and right are too out of balance, rotate tree node
	 */
	net = *cur;
	dl = dr = 0;
	if ((left = net->left) != NULL)
		dl = left->depth;
	if ((right = net->right)!= NULL)
		dr = right->depth;

	if (dl > dr + 1) {
		/* Rotate left */
		net->left = left->right;
		left->right = net;
		*cur = left;

		network_calcd(net);
		network_calcd(left);
	} else if (dr > dl + 1) {
		/* Rotate right */
		net->right = right->left;
		right->left = net;
		*cur = right;

		network_calcd(net);
		network_calcd(right);
	} else
		network_calcd(net);
}

/*
 *  add a new node to the tree
 */
static void
network_addnode(struct network **root, struct network *new,
    struct network **netqueue)
{
	struct network *net, *left;

	if ((net = *root) == NULL) {
		*root = new;
		new->depth = 1;
		return;
	}

	switch(network_compare(new, net)){
	case NET_PRECEEDS:
		network_addnode(&net->left, new, netqueue);
		break;

	case NET_FOLLOWS:
		network_addnode(&net->right, new, netqueue);
		break;

	case NET_CONTAINS:
		/*
		 *  if new node is superset of tree node, replace tree
		 *  node and queue tree node to be merged into root.
		 */
		*root = new;
		new->depth = 1;
		left = pool_alloc(pool_network);
		memset(left, 0, sizeof(struct network));
		left->mid = *netqueue;
		*netqueue = left;
		left->left = net;
		break;

	case NET_EQUALS:
		network_copydata(net, new);
		pool_free(pool_network, new);
		break;

	case NET_CONTAINED:
		network_addnode(&net->mid, new, netqueue);
		break;
	}
	
	network_balancetree(root);
}

/*
 * Add a route to the structure.  a and mask must be in host byte order.
 */
void
network_add(struct network **root, struct addr *addr, void *data)
{
	struct network *netqueue = NULL;
	struct network *p;

	p = pool_alloc(pool_network);
	memset(p, 0, sizeof(struct network));
	p->net = *addr;
	p->data = data;
	network_addnode(root, p, &netqueue);

	while ((p = netqueue) != NULL) {
		netqueue = p->mid;
		network_walkadd(root, p->left, &netqueue);
		pool_free(pool_network, p);
	}
}

/*
 * Find address la. Must be in host byte order.
 */
void *
network_lookup(struct network *root, struct addr *addr)
{
	struct network *net, *last;

	last = NULL;
	for (net = root; net != NULL; ) {
		struct addr tmp;
		
		tmp = net->net;
		tmp.addr_bits = IP_ADDR_BITS;
		if (addr_cmp(addr, &tmp) >= 0) {
			addr_bcast(&net->net, &tmp);
			tmp.addr_bits = IP_ADDR_BITS;
			if (addr_cmp(addr, &tmp) <= 0) {
				last = net;
				net = net->mid;
			} else {
				net = net->right;
			}
		} else {
			net = net->left;
		}
	}

	return (last != NULL ? last->data : NULL);
}

void
network_cleanup(struct network *net, int needfree)
{
	if (net->mid != NULL)
		network_cleanup(net->mid, needfree);
	if (net->left != NULL)
		network_cleanup(net->left, needfree);
	if (net->right != NULL)
		network_cleanup(net->right, needfree);
	if (needfree && net->data != NULL)
		free(net->data);
	pool_free(pool_network, net);
}

/* Functions to deal with Honeyd virtual routers */

void
router_init(void)
{
	SPLAY_INIT(&routers);
	SPLAY_INIT(&tunnels);

	pool_network = pool_init(sizeof(struct network));
}

struct router *
router_find(struct addr *addr)
{
	struct router tmp;

	tmp.addr = *addr;
	return (SPLAY_FIND(routetree, &routers, &tmp));
}

struct router *
router_new(struct addr *addr)
{
	struct router *new;

	if (router_find(addr))
		return (NULL);

	if ((new = calloc(1, sizeof(struct router))) == NULL)
		err(1, "%s: calloc", __FUNCTION__);

	new->routes = NULL;
	new->addr = *addr;

	SPLAY_INIT(&new->links);

	SPLAY_INSERT(routetree, &routers, new);

	return (new);
}

/* Frees the whole routing table */

void
router_end(void)
{
	struct router *router;
	struct router_entry *tunnel;

	/* 
	 * Clean up configured tunnels:
	 * Not really necessary as we do not need to deallocate anything.
	 */
	while ((tunnel = SPLAY_ROOT(&tunnels)) != NULL)
		SPLAY_REMOVE(tunneltree, &tunnels, tunnel);

	while ((router = SPLAY_ROOT(&routers)) != NULL) {
		SPLAY_REMOVE(routetree, &routers, router);

		if (router->routes != NULL)
			network_cleanup(router->routes, 1);
		free(router);
	}

	if (reverse != NULL)
		network_cleanup(reverse, 0);
	if (entry_routers != NULL)
		network_cleanup(entry_routers, 0);

	router_used = 0;
}

/*
 * Defines multiple entry points into the routing topology.
 * The entry is determined by the destination IP address.
 */

int
router_start(struct addr *addr, struct addr *pnetwork)
{
	struct router *entry;
	struct addr tmp, network;

	addr_pton("0.0.0.0/0", &network);
	network.addr_bits = 0;	/* libdnet bug */
	if (pnetwork != NULL)
		network = *pnetwork;

	/* Check for overlap */
	tmp = network;
	tmp.addr_bits = IP_ADDR_BITS;
	if (network_lookup(entry_routers, &tmp) != NULL)
		return (-1);
	addr_bcast(&network, &tmp);
	tmp.addr_bits = IP_ADDR_BITS;
	if (network_lookup(entry_routers, &tmp) != NULL)
		return (-1);

	if (!router_used)
		router_used = 1;

	if ((entry = router_new(addr)) == NULL)
		return (-1);

	entry->network = network;
	entry->flags |= ROUTER_ISENTRY;
	
	network_add(&entry_routers, &entry->network, entry);

	return (0);
}

struct link_entry *
link_entry_find(struct linktree *root, struct addr *dst)
{
	struct link_entry tmp;

	tmp.dst = *dst;
	return (SPLAY_FIND(linktree, root, &tmp));
}

struct link_entry *
link_entry_new(struct addr *dst)
{
	struct link_entry *link;

	if ((link = calloc(1, sizeof(struct link_entry))) == NULL)
		err(1, "%s: calloc", __func__);

	link->dst = *dst;

	return (link);
}

struct router_entry *
router_entry_new(struct addr *net, struct router *parent,
    struct router *gw, enum route_type type)
{
	struct router_entry *rte;

	if ((rte = calloc(1, sizeof(struct router_entry))) == NULL)
		err(1, "%s: calloc", __func__);
	rte->net = *net;
	rte->parent = parent;
	rte->type = type;
	if (type == ROUTE_NET)
		rte->gw = gw;

	return (rte);
}

int
router_add_link(struct router *r, struct addr *addr)
{
	struct router_entry *rte;

	rte = router_entry_new(addr, r, NULL, ROUTE_LINK);
	
	network_add(&r->routes, addr, rte);

	/* Add this router in the reverse lookup */
	network_add(&reverse, addr, r);

	return (0);
}

int
router_add_unreach(struct router *r, struct addr *addr)
{
	struct router_entry *rte;

	rte = router_entry_new(addr, r, NULL, ROUTE_UNREACH);
	
	network_add(&r->routes, addr, rte);

	return (0);
}

int
router_add_net(struct router *r, struct addr *net, struct router *gw,
    int latency, int packetloss, int bandwidth, struct link_drop *drop)
{
	struct link_entry *link;
	struct router_entry *rte;
	int mbw = 0, mdiv = 0;

	/* The link is where packets get queued */
	link = link_entry_find(&r->links, &gw->addr);
	if (link == NULL) {
		link = link_entry_new(&gw->addr);
		SPLAY_INSERT(linktree, &r->links, link);
	}

	if (bandwidth) {
		/* Get an estimate for the multiplier and divider */
		mbw = (8 * 1000000) / bandwidth;
		mdiv = 1000;
		
		if (!mbw) {
			mbw = (8 * 100000000) / bandwidth;
			mdiv = 100000;
		}
	}

	rte = router_entry_new(net, r, gw, ROUTE_NET);

	/* Keep track of attributes */
	rte->link = link;

	/* Only update attributes that have not been set yet */
	if (!link->latency)
		link->latency = latency;
	if (!link->packetloss)
		link->packetloss = packetloss;
	if (!link->bandwidth) {
		link->bandwidth = mbw;
		link->divider = mdiv;
		link->red = *drop;
	}
	
	network_add(&r->routes, net, rte);

	return (0);
}

int
router_add_tunnel(struct router *r, struct addr *net,
    struct addr *tunnel_src, struct addr *tunnel_dst)
{
	struct router_entry *rte;

	/* Match the IP address against an interface */
	if (interface_find_addr(tunnel_src) == NULL)
		return (-1);

	if (router_find_tunnel(tunnel_src, tunnel_dst) != NULL)
		return (-1);

	rte = router_entry_new(net, r, NULL, ROUTE_TUNNEL);
	rte->tunnel_src = *tunnel_src;
	rte->tunnel_dst = *tunnel_dst;
	
	network_add(&r->routes, net, rte);

	SPLAY_INSERT(tunneltree, &tunnels, rte);

	return (0);
}

struct router_entry *
router_find_tunnel(struct addr *src, struct addr *dst)
{
	struct router_entry tmp;

	tmp.tunnel_src = *src;
	tmp.tunnel_dst = *dst;

	return (SPLAY_FIND(tunneltree, &tunnels, &tmp));
}
