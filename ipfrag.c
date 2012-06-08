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

#include <sys/param.h>
#include <sys/types.h>

#include "config.h"
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#include <sys/stat.h>
#include <sys/tree.h>
#include <sys/wait.h>
#include <sys/queue.h>

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <dnet.h>
#include <ctype.h>

#undef timeout_pending
#undef timeout_initialized

#include <event.h>

#include "honeyd.h"
#include "template.h"
#include "personality.h"
#include "ipfrag.h"
#include "pool.h"

extern struct pool *pool_pkt;

static u_char buf[IP_LEN_MAX];  /* for complete packet */

SPLAY_HEAD(fragtree, fragment) fragments;

#define DIFF(a,b) do { \
	if ((a) < (b)) return -1; \
	if ((a) > (b)) return 1; \
} while (0)

int
fragcompare(struct fragment *a, struct fragment *b)
{
	DIFF(a->ip_src, b->ip_src);
	DIFF(a->ip_dst, b->ip_dst);
	DIFF(a->ip_id, b->ip_id);
	DIFF(a->ip_proto, b->ip_proto);

	return (0);
}

SPLAY_PROTOTYPE(fragtree, fragment, node, fragcompare);

SPLAY_GENERATE(fragtree, fragment, node, fragcompare);

TAILQ_HEAD(fragqueue, fragment) fraglru;

int nfragments;
int nfragmem;

void
ip_fragment_init(void)
{
	SPLAY_INIT(&fragments);
	TAILQ_INIT(&fraglru);

	nfragments = 0;
	nfragmem = 0;
}

struct fragment *
ip_fragment_find(ip_addr_t src, ip_addr_t dst, u_short id, u_char proto)
{
	struct fragment tmp, *frag;

	tmp.ip_src = src;
	tmp.ip_dst = dst;
	tmp.ip_id = id;
	tmp.ip_proto = proto;

	frag = SPLAY_FIND(fragtree, &fragments, &tmp);

	if (frag != NULL) {
		TAILQ_REMOVE(&fraglru, frag, next);
		TAILQ_INSERT_HEAD(&fraglru, frag, next);
	}

	return (frag);
}

/* Free a fragment by removing it from all lists, etc... */
void
ip_fragent_free(struct fragent *ent)
{
	nfragmem -= ent->size;

	free(ent->data);
	free(ent);
}

void
ip_fragment_free(struct fragment *tmp)
{
	struct fragent *ent;

	evtimer_del(&tmp->timeout);

	SPLAY_REMOVE(fragtree, &fragments, tmp);
	TAILQ_REMOVE(&fraglru, tmp, next);
	nfragments--;

	for (ent = TAILQ_FIRST(&tmp->fraglist); ent;
	    ent = TAILQ_FIRST(&tmp->fraglist)) {
		TAILQ_REMOVE(&tmp->fraglist, ent, next);

		ip_fragent_free(ent);
	}
	free(tmp);
}

void
ip_fragment_timeout(int fd, short which, void *arg)
{
	struct fragment *tmp = arg;
	struct addr src;

	addr_pack(&src, ADDR_TYPE_IP, IP_ADDR_BITS, &tmp->ip_src, IP_ADDR_LEN);

	syslog(LOG_DEBUG, "Expiring fragment from %s, id %d",
	    addr_ntoa(&src), ntohs(tmp->ip_id));

	ip_fragment_free(tmp);
}

void
ip_fragment_reclaim(int count)
{
	struct fragment *tmp;
	for (tmp = TAILQ_LAST(&fraglru, fragqueue); tmp && count;
	    tmp = TAILQ_LAST(&fraglru, fragqueue)) {
		ip_fragment_free(tmp);
		count--;
	}
}

struct fragment *
ip_fragment_new(ip_addr_t src, ip_addr_t dst, u_short id, u_char proto,
    enum fragpolicy pl)
{
	struct fragment *tmp = NULL;
	struct timeval tv = { IPFRAG_TIMEOUT, 0};
	int reclaim = 0;

	if (nfragmem > IPFRAG_MAX_MEM || nfragments > IPFRAG_MAX_FRAGS)
		ip_fragment_reclaim(nfragments/10);

	while (tmp == NULL && reclaim < 2) {
		tmp = calloc(1, sizeof(struct fragment));
		if (tmp == NULL) {
			reclaim++;
			ip_fragment_reclaim(nfragments/10);
		}
	}

	if (tmp == NULL)
		return (NULL);

	tmp->ip_src = src;
	tmp->ip_dst = dst;
	tmp->ip_id = id;
	tmp->ip_proto = proto;
	tmp->fragp = pl;

	TAILQ_INIT(&tmp->fraglist);
	evtimer_set(&tmp->timeout, ip_fragment_timeout, tmp);
	evtimer_add(&tmp->timeout, &tv);

	SPLAY_INSERT(fragtree, &fragments, tmp);
	TAILQ_INSERT_HEAD(&fraglru, tmp, next);
	nfragments++;

	return (tmp);
}

int
ip_fragment_insert(struct fragment *fragq, struct fragent *ent, short mf)
{
	struct fragent *prev, *after;
	struct ip_hdr *ip;
	u_char *data;
	u_short overlap;
	u_short max;
	u_short off;
	u_short len;

	off = ent->off;
	len = ent->len;
	max = off + len;

	if (fragq->maxlen < max)
		fragq->maxlen = max;
	if (!mf)
		fragq->hadlastpacket = 1;

	prev = NULL;
	for (after = TAILQ_FIRST(&fragq->fraglist); after;
	    after = TAILQ_NEXT(after, next)) {
		if (off < after->off)
			break;
		prev = after;
	}

	if (prev && prev->off + prev->len > off) {
		overlap = prev->off + prev->len - off;

		if (overlap >= len) {
			if (fragq->fragp == FRAG_NEW) {
				u_char *odata = prev->data + off - prev->off;
				memcpy(odata, ent->data, len);
			}
			goto free_fragment;
		}

		if (fragq->fragp == FRAG_OLD) {
			u_char *odata = prev->data + prev->len - overlap;
			memcpy(ent->data, odata, overlap);
		}
		prev->len -= overlap;
	}

	if (after && off + len > after->off) {
		overlap = off + len - after->off;

		if (overlap >= after->len) {
			if (fragq->fragp == FRAG_OLD) {
				u_char *ndata = ent->data + after->off - off;
				memcpy(ndata, after->data, after->len);
			}
			
			/* Drop the old fragment */
			TAILQ_REMOVE(&fragq->fraglist, after, next);
			ip_fragent_free(after);
		} else {
			/* Trim the overlap */
			if (fragq->fragp == FRAG_NEW) {
				u_char *ndata = ent->data + len - overlap;
				memcpy(after->data, ndata, overlap);
			}
			len -= overlap;
			ent->len = len;
		}
	}

	if (prev)
		TAILQ_INSERT_AFTER(&fragq->fraglist, prev, ent, next);
	else
		TAILQ_INSERT_HEAD(&fragq->fraglist, ent, next);

	/* Waiting for more data */
	if (!fragq->hadlastpacket)
		return (0);

	off = 0;
	TAILQ_FOREACH(ent, &fragq->fraglist, next) {
		if (ent->off != off)
			break;
		off = ent->off + ent->len;
	}

	if (ent)
		return (0);

	/* Completely assembled */

	data = buf;
	ip = (struct ip_hdr *)data;
	for(ent = TAILQ_FIRST(&fragq->fraglist); ent;
	    ent = TAILQ_FIRST(&fragq->fraglist)) {
		TAILQ_REMOVE(&fragq->fraglist, ent, next);

		memcpy(data, ent->data, ent->len);
		data += ent->len;
		ip_fragent_free(ent);
	}

	ip->ip_len = htons(fragq->maxlen);
	ip->ip_off = 0;

	ip_fragment_free(fragq);

	return (1);

 free_fragment:
	ip_fragent_free(ent);
	return (0);
}

/*
 * Reassembles fragmented IP packets.
 *
 * Return:
 *  0 - successfully reassembled
 * -1 - not reassembled yet.
 */

int
ip_fragment(struct template *tmpl, struct ip_hdr *ip, u_short len,
    struct ip_hdr **pip, u_short *piplen)
{
	struct addr src;
	struct personality *person = NULL;
	struct fragment *fragq;
	struct fragent *ent;
	u_char *dat;
	short mf;
	u_short off;
	u_short hlen;
	enum fragpolicy fragp = FRAG_OLD;
	
	addr_pack(&src, ADDR_TYPE_IP, IP_ADDR_BITS, &ip->ip_src, IP_ADDR_LEN);

	if (tmpl != NULL && (person = tmpl->person) != NULL)
		fragp = person->fragp;

	if (fragp == FRAG_DROP)
		goto drop;

	fragq = ip_fragment_find(ip->ip_src, ip->ip_dst, ip->ip_id, ip->ip_p);

	/* Nothing here for now */
	off = ntohs(ip->ip_off);
	if (off & IP_DF)
		goto freeall;
	mf = off & IP_MF;
	off &= IP_OFFMASK;
	off <<= 3;

	dat = (u_char *)ip;
	hlen = ip->ip_hl << 2;
	if (mf && ((len - hlen) & 0x7))
		goto freeall;

	if (off) {
		len -= hlen;
		dat += hlen;
		off += hlen;
	}

	if (off + len > IP_LEN_MAX || len == 0)
		goto freeall;

	if (fragq == NULL) {
		fragq = ip_fragment_new(ip->ip_src, ip->ip_dst, ip->ip_id,
		    ip->ip_p, fragp);
		if (fragq == NULL)
			goto drop;
	}

	if ((ent = calloc(1, sizeof(struct fragent))) == NULL)
		goto freeall;

	ent->off = off;
	ent->len = len;
	ent->size = len;
	if ((ent->data = malloc(len)) == NULL) {
		free(ent);
		goto freeall;
	}
	memcpy(ent->data, dat, len);
	nfragmem += len;

	syslog(LOG_DEBUG,  "Received fragment from %s, id %d: %d@%d",
	    addr_ntoa(&src), ntohs(ip->ip_id), len, off);

	if (ip_fragment_insert(fragq, ent, mf)) {
		ip = (struct ip_hdr *)buf;
		len = ntohs(ip->ip_len);

		*pip = ip;
		*piplen = len;

		/* Successfully reassembled */
		return (0);
	}
	return (-1);

 freeall:
	syslog(LOG_DEBUG,  "%s fragment from %s, id %d: %d@%d",
	    fragq ? "Freeing" : "Dropping",
	    addr_ntoa(&src), ntohs(ip->ip_id), len, off);

	if (fragq)
		ip_fragment_free(fragq);
	return (-1);

 drop:
	syslog(LOG_DEBUG, "Dropping fragment from %s", addr_ntoa(&src));

	return (-1);
}

void
ip_send_fragments(u_int mtu, struct ip_hdr *ip, u_int iplen, struct spoof spoof)
{
	struct ip_hdr *nip;
	u_int iphlen, datlen, offset, pdatlen, size;
	u_char *p;

	/* Need to calculate the checksum for the protocol */
	ip_checksum(ip, iplen);

	iphlen = ip->ip_hl << 2;
	datlen = iplen - iphlen;

	pdatlen = (mtu - iphlen) & (~0x7);
	offset = 0;
	p = (u_char *)ip + iphlen;
	while (datlen) {
		nip = pool_alloc(pool_pkt);

		size = datlen > pdatlen ? pdatlen : datlen;

		memcpy(nip, ip, iphlen);
		memcpy((u_char *)nip + iphlen, p, size);

		p += size;
		datlen -= size;

		nip->ip_len = htons(iphlen + size);
		nip->ip_off = htons((offset >> 3) | (datlen ? IP_MF : 0));
		
		/* Send the packet:
		 * takes also care of deallocating this packet.
		 */
		honeyd_ip_send((u_char *)nip, iphlen + size, spoof);

		offset += size;
	}
}
