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
#include <assert.h>

#undef timeout_pending
#undef timeout_initialized

#include <event.h>

#include "honeyd.h"
#include "template.h"
#include "osfp.h"
#include "hooks.h"

struct pf_osfp_enlist;
int pfctl_file_fingerprints(int, int, const char *);
void pf_osfp_initialize(void);
int pf_osfp_match(struct pf_osfp_enlist *, pf_osfp_t);
struct pf_osfp_enlist *pf_osfp_fingerprint_hdr(const struct ip_hdr *, const struct tcp_hdr *);

void honeyd_osfp_input(struct tuple *, u_char *, u_int, void *);
static struct osfp *honeyd_osfp_cache(const struct ip_hdr *);

SPLAY_HEAD(osfptree, osfp) osfp_buckets[OSFP_HASHSIZE];

int
osfp_compare(struct osfp *a, struct osfp *b)
{
	if (a->src < b->src)
		return (-1);
	else if (a->src > b->src)
		return (1);
	return (0);
}

SPLAY_PROTOTYPE(osfptree, osfp, node, osfp_compare);
SPLAY_GENERATE(osfptree, osfp, node, osfp_compare);

int
honeyd_osfp_init(const char *filename)
{
	int i;

	pf_osfp_initialize();
	if (pfctl_file_fingerprints(0, 0, filename) != 0)
		return (-1);

	/* Add a hooks entry so that we get TCP input packets */
	hooks_add_packet_hook(IP_PROTO_TCP, HD_INCOMING,
	    honeyd_osfp_input, NULL);

	/* Initialize hash buckets */
	for (i = 0; i < OSFP_HASHSIZE; i++)
		SPLAY_INIT(&osfp_buckets[i]);

	return (0);
}

static struct osfptree *
honeyd_osfp_hash(const struct ip_hdr *ip)
{
	struct osfptree *root;
	int i;
	u_char *bin;
	u_char h = 0;
	
	bin = (u_char *)&ip->ip_src;
	for (i = 0; i < sizeof(ip->ip_src); i++)
		h ^= *bin++;

	root = &osfp_buckets[h & (OSFP_HASHSIZE - 1)];
	return (root);
}

void
honeyd_osfp_timeout(int fd, short what, void *arg)
{
	struct osfp *entry = arg;
	struct osfptree *root;
	struct ip_hdr ip;
	struct addr src;

	addr_pack(&src, ADDR_TYPE_IP, IP_ADDR_BITS, &entry->src, IP_ADDR_LEN);
	syslog(LOG_DEBUG, "Expiring OS fingerprint for %s", addr_ntoa(&src));

	ip.ip_src = entry->src;
	root = honeyd_osfp_hash(&ip);
	SPLAY_REMOVE(osfptree, root, entry);

	free(entry);
}

static void
honeyd_osfp_cache_insert(const struct ip_hdr *ip, struct pf_osfp_enlist *list)
{
	struct timeval tv;
	struct osfptree *root;
	struct osfp *entry;

	/* Create a new entry unless we have it cached already */
	if ((entry = honeyd_osfp_cache(ip)) == NULL) {
		if ((entry = calloc(1, sizeof(struct osfp))) == NULL) {
			warn("%s: calloc", __func__);
			return;
		}

		entry->src = ip->ip_src;
		entry->timeout = evtimer_new(libevent_base, honeyd_osfp_timeout, entry);
		root = honeyd_osfp_hash(ip);

		SPLAY_INSERT(osfptree, root, entry);
	}

	entry->list = list;
	
	timerclear(&tv);
	tv.tv_sec = OSFP_TIMEOUT;
	evtimer_add(entry->timeout, &tv);
}

static struct osfp *
honeyd_osfp_cache(const struct ip_hdr *ip)
{
	struct timeval tv;
	struct osfptree *root;
	struct osfp tmp, *entry;

	root = honeyd_osfp_hash(ip);

	tmp.src = ip->ip_src;

	entry = SPLAY_FIND(osfptree, root, &tmp);
	if (entry == NULL)
		return (NULL);

	assert(entry->src == ip->ip_src);

	/* Update timeout */
	timerclear(&tv);
	tv.tv_sec = OSFP_TIMEOUT;
	evtimer_add(entry->timeout, &tv);

	return (entry);
}

int
honeyd_osfp_match(const struct ip_hdr *ip, pf_osfp_t fp)
{
	struct pf_osfp_enlist *list;
	const struct tcp_hdr *tcp;

	tcp = (const struct tcp_hdr *)((u_char *)ip + (ip->ip_hl << 2));

	list = pf_osfp_fingerprint_hdr(ip, tcp);
	if (list == NULL) {
		struct osfp *entry = honeyd_osfp_cache(ip);
		if (entry != NULL)
			list = entry->list;
	}

	return (pf_osfp_match(list, fp));
}

void
honeyd_osfp_input(struct tuple *conhdr, u_char *pkt, u_int plen, void *arg)
{
	const struct ip_hdr *ip = (struct ip_hdr *)pkt;
	const struct tcp_hdr *tcp;
	struct pf_osfp_enlist *list;
	u_short iphlen = ip->ip_hl << 2;

	/* Sanity check */
	if (iphlen + sizeof(struct tcp_hdr) > plen)
		return;

	tcp = (const struct tcp_hdr *)(pkt + iphlen);

	/* Only intercept syn packets */
	if ((tcp->th_flags & (TH_SYN|TH_ACK)) != TH_SYN)
		return;
	
	list = pf_osfp_fingerprint_hdr(ip, tcp);
	if (list == NULL)
		return;

	honeyd_osfp_cache_insert(ip, list);
}

char *
honeyd_osfp_name(struct ip_hdr *ip)
{
	static char name[128];
	struct osfp *cache;
	struct pf_osfp_enlist *list;
	struct pf_osfp_entry *entry;

	cache = honeyd_osfp_cache(ip);
	if (cache == NULL)
		return (NULL);
	list = cache->list;

	entry = SLIST_FIRST(list);

	snprintf(name, sizeof(name), "%s %s %s",
	    entry->fp_class_nm,
	    entry->fp_version_nm,
	    entry->fp_subtype_nm);
	
	return (name);
}
