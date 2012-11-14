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
/*
 *
 * Copyright (c) 2000, 2001, 2002 Dug Song <dugsong@monkey.org>
 * All rights reserved, all wrongs reversed.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the authors may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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
#include "arp.h"
#include "debug.h"

/* Time in seconds before expiration of ARP entries */
#define ARP_MAX_ACTIVE		600

/* Exported */
int need_arp = 0;	/* We set this if we need to listen to arp traffic */

/* Imported */
extern struct network *reverse;

/* Internal */

/* For the physical (IP) address */
static SPLAY_HEAD(paarptree, arp_req) pa_arp_reqs;

static int
pa_compare(struct arp_req *a, struct arp_req *b)
{
	return (addr_cmp(&a->pa, &b->pa));
}

SPLAY_PROTOTYPE(paarptree, arp_req, next_pa, pa_compare);
SPLAY_GENERATE(paarptree, arp_req, next_pa, pa_compare);

/* For the hardware address */
static SPLAY_HEAD(haarptree, arp_req) ha_arp_reqs;

static int
ha_compare(struct arp_req *a, struct arp_req *b)
{
	return (addr_cmp(&a->ha, &b->ha));
}

SPLAY_PROTOTYPE(haarptree, arp_req, next_ha, ha_compare);
SPLAY_GENERATE(haarptree, arp_req, next_ha, ha_compare);


void
arp_init(void)
{
	SPLAY_INIT(&pa_arp_reqs);
	SPLAY_INIT(&ha_arp_reqs);
}

static void
arp_send(eth_t *eth, int op,
    struct addr *sha, struct addr *spa,
    struct addr *tha, struct addr *tpa)
{
	u_char pkt[ETH_HDR_LEN + ARP_HDR_LEN + ARP_ETHIP_LEN];

	eth_pack_hdr(pkt, tha->addr_eth, sha->addr_eth, ETH_TYPE_ARP);
	arp_pack_hdr_ethip(pkt + ETH_HDR_LEN, op, sha->addr_eth,
	    spa->addr_ip, tha->addr_eth, tpa->addr_ip);
	
	if (op == ARP_OP_REQUEST) {
		syslog(LOG_DEBUG, "%s: who-has %s tell %s", __func__,
		    addr_ntoa(tpa), addr_ntoa(spa));
	} else if (op == ARP_OP_REPLY) {
		syslog(LOG_INFO, "arp reply %s is-at %s",
		    addr_ntoa(spa), addr_ntoa(sha));
	}
	if (eth_send(eth, pkt, sizeof(pkt)) != sizeof(pkt))
		syslog(LOG_ERR, "couldn't send packet: %m");
}

void
arp_free(struct arp_req *req)
{
	SPLAY_REMOVE(paarptree, &pa_arp_reqs, req);

	if (SPLAY_FIND(haarptree, &ha_arp_reqs, req) != NULL)
		SPLAY_REMOVE(haarptree, &ha_arp_reqs, req);

	evtimer_del(&req->active);
	evtimer_del(&req->discover);
	free(req);
}

static void
arp_timeout(int fd, short event, void *arg)
{
	struct arp_req *req = arg;
	
	syslog(LOG_DEBUG, "%s: expiring %s", __func__, addr_ntoa(&req->pa));
	arp_free(req);
}

static void
arp_discover(struct arp_req *req, struct addr *ha)
{
	struct interface *inter = req->inter;
	struct timeval tv = {0, 500000};

	struct addr bcast;
	addr_pack(&bcast, ADDR_TYPE_ETH, ETH_ADDR_BITS,
	    ETH_ADDR_BROADCAST, ETH_ADDR_LEN);

	if (ha != NULL) {
		memcpy(&req->ha, ha, sizeof(*ha));

		// Don't insert the broadcast MAC address into the ARP table
		if (0 != memcmp(&ha->__addr_u, &bcast.__addr_u, ETH_ADDR_LEN))
		{

			/*
			 * We might get multiple packets, so we need to remove
			 * the entry before we can insert it again.
			 */
			if (SPLAY_FIND(haarptree, &ha_arp_reqs, req) != NULL)
				SPLAY_REMOVE(haarptree, &ha_arp_reqs, req);

			if (SPLAY_FIND(haarptree, &ha_arp_reqs, req) == NULL)
				SPLAY_INSERT(haarptree, &ha_arp_reqs, req);
		}
	}

	if ((req->cnt < 2) && (inter != NULL)) {
		arp_send(inter->if_eth, ARP_OP_REQUEST,
		    &req->src_ha,   /* ethernet */
		    &req->src_pa,   /* ip */
		    &req->ha, &req->pa);

		/* XXX - use reversemap on networks to find router ip */
		evtimer_add(&req->discover, &tv);
	} else
		(*req->cb)(req, 0, req->arg);
	req->cnt++;
}

static void
arp_discovercb(int fd, short event, void *arg)
{
	struct arp_req *req = arg;

	arp_discover(req, NULL);
}

/* Find an arp entry based on the corresponding IP or hardware address */

struct arp_req *
arp_find(struct addr *addr)
{
	struct arp_req tmp, *res = NULL;

	if (addr->addr_type == ADDR_TYPE_IP) {
		tmp.pa = *addr;
		res = SPLAY_FIND(paarptree, &pa_arp_reqs, &tmp);
	} else if (addr->addr_type == ADDR_TYPE_ETH) {
		tmp.ha = *addr;
		res = SPLAY_FIND(haarptree, &ha_arp_reqs, &tmp);
	} else {
		errx(1, "%s: lookup for unsupported address type", __func__);
	}

	return (res);
}

/* 
 * Allocates a new arp info structure and inserts it into the appropriate
 * trees so that we can find it later.
 */

struct arp_req *
arp_new(struct interface *inter,
    struct addr *src_pa, struct addr *src_ha,
    struct addr *pa, struct addr *ha)
{
	struct arp_req *req;

	if ((req = calloc(1, sizeof(*req))) == NULL)
		return (NULL);

	req->inter = inter;

	if (src_pa != NULL)
		req->src_pa = *src_pa;
	if (src_ha != NULL)
		req->src_ha = *src_ha;

	if (pa != NULL) {
		req->pa = *pa;
		SPLAY_INSERT(paarptree, &pa_arp_reqs, req);
	}

	if (ha != NULL) {
		req->ha = *ha;
		assert (SPLAY_FIND(haarptree, &ha_arp_reqs, req) == NULL);
		SPLAY_INSERT(haarptree, &ha_arp_reqs, req);
	}

	evtimer_set(&req->active, arp_timeout, req);
	evtimer_set(&req->discover, arp_discovercb, req);
			
	return (req);
}

/* Request the resolution of an IP address to an ethernet address */

void
arp_request(struct interface *inter,
    struct addr *src_pa, struct addr *src_ha,
    struct addr *addr, void (*cb)(struct arp_req *, int, void *), void *arg)
{
	struct arp_req *req;
	struct addr bcast;
	struct timeval tv;

	if ((req = arp_new(inter, src_pa, src_ha, addr, NULL)) == NULL) {
		syslog(LOG_ERR, "calloc: %m");
		return;
	}
			
	req->cb = cb;
	req->arg = arg;

	timerclear(&tv);
	tv.tv_sec = ARP_MAX_ACTIVE;
	evtimer_add(&req->active, &tv);

	addr_pack(&bcast, ADDR_TYPE_ETH, ETH_ADDR_BITS,
	    ETH_ADDR_BROADCAST, ETH_ADDR_LEN);
	arp_discover(req, &bcast);
}

/*
 * This requires better input checking;
 * need to check both src and dst adress.
 */

void
arp_recv_cb(u_char *u, const struct pcap_pkthdr *pkthdr, const u_char *pkt)
{
	struct interface *inter = (struct interface *)u;
	struct template *tmpl;
	struct arp_hdr *arp;
	struct arp_ethip *ethip;
	struct arp_req *req;
	struct arp_entry src, dst;
	struct addr *reply_sha;

	if (pkthdr->caplen < inter->if_dloff + ARP_HDR_LEN + ARP_ETHIP_LEN)
		return;

	arp = (struct arp_hdr *)(pkt + inter->if_dloff);	
	ethip = (struct arp_ethip *)(arp + 1);
	
	addr_pack(&src.arp_ha, ADDR_TYPE_ETH, ETH_ADDR_BITS,
	    ethip->ar_sha, ETH_ADDR_LEN);
	addr_pack(&src.arp_pa, ADDR_TYPE_IP, IP_ADDR_BITS,
	    ethip->ar_spa, IP_ADDR_LEN);
	    
	switch (ntohs(arp->ar_op)) {
		
	case ARP_OP_REQUEST:
		addr_pack(&dst.arp_pa, ADDR_TYPE_IP, IP_ADDR_BITS,
		    &ethip->ar_tpa, IP_ADDR_LEN);

		/* Check if we are responsible for this network or address */
		req = arp_find(&dst.arp_pa);
		if (network_lookup(reverse, &dst.arp_pa) == NULL && 
		    req == NULL) {
		ignore:
			DFPRINTF(2, (stderr,
				"ignoring arp request on %s for %s: %p\n",
				inter->if_ent.intf_name,
				addr_ntoa(&dst.arp_pa), req));
			return;
		}

		/*
		 * If we discovered this address ourselves, we do not
		 * want to send a reply - although we could.
		 */
		if (req != NULL && (req->flags & ARP_EXTERNAL))
			goto ignore;

		tmpl = template_find(addr_ntoa(&dst.arp_pa));

		/*
		 * If this template points to an external host,
		 * we do not answer for it.  It has to answer itself.
		 */
		if (tmpl != NULL && (tmpl->flags & TEMPLATE_EXTERNAL))
			goto ignore;

		/*
		 * We need to either reply with our interface address or
		 * with the address configured in the template.
		 */
		if (tmpl == NULL || tmpl->ethernet_addr == NULL)
			reply_sha = &inter->if_ent.intf_link_addr;
		else
			reply_sha = tmpl->ethernet_addr;

		/* Send reply */
		arp_send(inter->if_eth, ARP_OP_REPLY,
		    reply_sha, &dst.arp_pa,
		    &src.arp_ha, &src.arp_pa);
		break;
		
	case ARP_OP_REPLY:
		addr_pack(&src.arp_pa, ADDR_TYPE_IP, IP_ADDR_BITS,
		    &ethip->ar_spa, IP_ADDR_LEN);
		if ((req = arp_find(&src.arp_pa)) != NULL) {
			addr_pack(&req->ha, ADDR_TYPE_ETH, ETH_ADDR_BITS,
			    ethip->ar_sha, ETH_ADDR_LEN);

			/*
			 * Ignore arp replies that we generate ourselves.
			 * Because we fake ethernet mac addresses so
			 * successfully or pcap filter does not know that
			 * this is a Honeyd packet.
			 */
			if ( !(req->flags & ARP_INTERNAL) ) {
				/* Signal success */
				req->flags |= ARP_EXTERNAL;
				req->cnt = -1;
				assert(req->cb != NULL);
				(*req->cb)(req, 1, req->arg);
				evtimer_del(&req->discover);

				syslog(LOG_DEBUG, "%s: %s at %s", __func__,
				    addr_ntoa(&req->pa), addr_ntoa(&req->ha));
			}
		}
		break;
	}
}
