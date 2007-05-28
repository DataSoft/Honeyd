/*
 * Copyright (c) 2002, 2003 Niels Provos <provos@citi.umich.edu>
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

/*
 *  compare 2 v4 ranges
 */

enum net_order
network_compare(struct network *a, struct network *b)
{
	struct addr addr_a, addr_b;
	struct addr addr_aend, addr_bend;

	/* Set up the addresses; still IPv4 dependent */
	addr_a = a->net;
	addr_a.addr_bits = IP_ADDR_BITS;
	addr_b = b->net;
	addr_b.addr_bits = IP_ADDR_BITS;

	addr_bcast(&a->net, &addr_aend);
	addr_aend.addr_bits = IP_ADDR_BITS;
	addr_bcast(&b->net, &addr_bend);
	addr_bend.addr_bits = IP_ADDR_BITS;

	if (addr_cmp(&addr_aend, &addr_b) < 0)
		return (NET_PRECEEDS);
	if (addr_cmp(&addr_a, &addr_bend) > 0)
		return (NET_FOLLOWS);
	if (addr_cmp(&addr_a, &addr_b) <= 0 && 
	    addr_cmp(&addr_aend, &addr_bend) >= 0){
		if (addr_cmp(&a->net, &b->net) == 0)
			return (NET_EQUALS);
		return (NET_CONTAINS);
	}
	return (NET_CONTAINED);
}

/* Unittests */

static void
network_test_compare(void)
{
	struct addr one, two;
	struct network net_one, net_two;

	addr_pton("1.0.0.0/24", &one);
	addr_pton("2.0.0.0/24", &two);
	net_one.net = one;
	net_two.net = two;

	if (network_compare(&net_one, &net_two) != NET_PRECEEDS)
		errx(1, "network_compare");
	if (network_compare(&net_two, &net_one) != NET_FOLLOWS)
		errx(1, "network_compare");
	if (network_compare(&net_two, &net_two) != NET_EQUALS)
		errx(1, "network_compare");

	addr_pton("2.1.0.0/24", &one);
	addr_pton("2.0.0.0/8", &two);
	net_one.net = one;
	net_two.net = two;
	if (network_compare(&net_one, &net_two) != NET_CONTAINED)
		errx(1, "network_compare: !contained");
	if (network_compare(&net_two, &net_one) != NET_CONTAINS)
		errx(1, "network_compare: !contains");

	fprintf(stderr, "\t%s: OK\n", __func__);
}

void
network_test(void)
{
	network_test_compare();
}
