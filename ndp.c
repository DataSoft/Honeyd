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

#include <sys/types.h>
#include <sys/param.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/ioctl.h>
#include <sys/tree.h>
#include <sys/queue.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <assert.h>

#include <event.h>
#include <pcap.h>
#include <dnet.h>

#include "honeyd.h"
#include "template.h"
#include "router.h"
#include "interface.h"
#include "icmpv6.h"
#include "tuple.h"
#include "ndp.h"

#include "debug.h"

/* For the physical (IP) address */
static SPLAY_HEAD(pandptree, ndp_req) pa_ndp_reqs;

static int
pandp_compare(struct ndp_req *a, struct ndp_req *b)
{
	return (addr_cmp(&a->pa, &b->pa));
}

SPLAY_PROTOTYPE(pandptree, ndp_req, next_pa, pandp_compare);
SPLAY_GENERATE(pandptree, ndp_req, next_pa, pandp_compare);

void
ndp_init(void)
{
	SPLAY_INIT(&pa_ndp_reqs);
}

struct ndp_req *
ndp_new(struct interface *inter,
    struct addr *src_pa, struct addr *src_ha,
    struct addr *pa, struct addr *ha)
{
	struct ndp_req *req;

	if ((req = calloc(1, sizeof(*req))) == NULL)
		return (NULL);

	req->inter = inter;

	if (src_pa != NULL)
		req->src_pa = *src_pa;
	if (src_ha != NULL)
		req->src_ha = *src_ha;

	if (pa != NULL) {
		req->pa = *pa;
		SPLAY_INSERT(pandptree, &pa_ndp_reqs, req);
	}

	// TODO ipv6: Do we want another MAC -> thing tree here? Need to think about this. Maybe refactor the hardware mapping out.
	/*
	if (ha != NULL) {
		req->ha = *ha;
		assert (SPLAY_FIND(haarptree, &ha_arp_reqs, req) == NULL);
		SPLAY_INSERT(haarptree, &ha_arp_reqs, req);
	}
	*/

	// TODO ipv6: Why's this happening here? Is this just init stuff?
	//evtimer_set(&req->active, arp_timeout, req);
	//evtimer_set(&req->discover, arp_discovercb, req);

	return (req);
}

void
ndp_recv_cb(struct tuple *summary, const struct icmpv6_msg_nd *query)
{
	struct addr queryIP;
	addr_pack(&queryIP, ADDR_TYPE_IP6, IP6_ADDR_BITS, &query->icmpv6_target ,IP6_ADDR_LEN);
	printf("Got a request for IP %s\n", addr_ntoa(&queryIP));

}
