/*
 * Copyright (c) 2002, 2003, 2004 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 *
 * <LICENSEHERE>
 */
#ifndef _NETWORK_H_
#define _NETWORK_H_

struct network {
	struct network *left;
	struct network *mid;
	struct network *right;

	uint16_t	depth;
	struct addr	net;

	void	*data;
};

enum net_order
{
	NET_PRECEEDS,
	NET_FOLLOWS,
	NET_EQUALS,
	NET_CONTAINS,
	NET_CONTAINED
};

enum net_order network_compare(struct network *a, struct network *b);

void network_test(void);

#endif
