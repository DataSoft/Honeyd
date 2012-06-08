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

#include <sys/types.h>
#include <sys/param.h>

#include "config.h"

#include <sys/queue.h>
#include <sys/tree.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <syslog.h>

#include <dnet.h>

#undef timeout_pending
#undef timeout_initialized

#include <event.h>

#include "honeyd.h"
#include "gre.h"

extern rand_t *honeyd_rand;
extern int honeyd_ttl;

static u_char pkt[IP_LEN_MAX];


int
gre_decapsulate(struct ip_hdr *oip, u_short oiplen,
    struct ip_hdr **pip, u_short *piplen)
{
	struct gre_hdr *gre;
	struct ip_hdr *ip;
	u_char *end = (u_char *)oip + oiplen;
	u_char *data;
	uint16_t flags, proto, iplen;

	gre = (struct gre_hdr *)((u_char *)oip + (oip->ip_hl << 2));
	data = (u_char *)(gre + 1);

	if (end <= data)
		return (-1);

	/* We support only RFC 2784 */
	flags = ntohs(gre->gre_flags);
	if ((flags & ~GRE_CHECKSUM) != 0) {
		syslog(LOG_DEBUG,
		    "%s: dropping RFC 1701 encapsulation: flags = %x",
		    __func__, flags);
		return (-1);
	}

	proto = ntohs(gre->gre_proto);
	if (proto != GRE_IP4PROTO) {
		syslog(LOG_DEBUG,
		    "%s: dropping encapsulated packet: bad protocol %d",
		    __func__, proto);
		return (-1);
	}

	if (!(flags & GRE_CHECKSUM))
		data = GRE_NOCKSUM_DATA(gre);

	/* Check for the proper length of the packet */
	ip = (struct ip_hdr *)data;
	if (data + sizeof(struct ip_hdr) > end)
		return (-1);

	iplen = ntohs(ip->ip_len);
	if (data + iplen > end)
		return (-1);

	if (flags & GRE_CHECKSUM) {
		u_int sum = gre->gre_sum, tmp;
		gre->gre_sum = 0;

		tmp = ip_cksum_add(gre, sizeof(struct gre_hdr) + iplen, 0);
		tmp = ip_cksum_carry(tmp);
		if (sum != tmp) {
			syslog(LOG_INFO,
			    "%s: dropping encapsulated packet: bad checksum: %x vs %x",
			    __func__, ntohs(sum), ntohs(tmp));
			return (-1);
		}
	}

	*pip = ip;
	*piplen = iplen;

	return (0);
}

int
gre_encapsulate(ip_t *honeyd_ip, struct addr *src, struct addr *dst,
    struct ip_hdr *iip, u_int iiplen)
{
	struct ip_hdr *oip = (struct ip_hdr *)pkt;
	struct gre_hdr *gre = (struct gre_hdr *)(oip + 1);
	u_char *data = (u_char *)(gre + 1);
	u_int iplen, sum;

	iplen = sizeof(struct ip_hdr) + sizeof(struct gre_hdr) + iiplen;

	if (iplen > sizeof(pkt)) {
		syslog(LOG_ERR, "%s: packet too long: %d", __func__, iplen);
		return (-1);
	}

	ip_pack_hdr(pkt, 0, iplen, rand_uint16(honeyd_rand), 
	    0, honeyd_ttl, IP_PROTO_GRE, src->addr_ip, dst->addr_ip);

	memset(gre, 0, sizeof(struct gre_hdr));
	gre->gre_flags = htons(GRE_CHECKSUM | GRE_VERSION);
	gre->gre_proto = htons(GRE_IP4PROTO);

	/* Copy the payload */
	memcpy(data, iip, iiplen);

	/* Calculate the checksum */
	sum = ip_cksum_add(gre, iiplen + sizeof(struct gre_hdr), 0);
	gre->gre_sum = ip_cksum_carry(sum);

	ip_checksum(oip, iplen);

	return (ip_send(honeyd_ip, pkt, iplen) != iplen ? -1 : 0);
}
