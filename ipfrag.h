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
#ifndef _IPFRAG_H_
#define _IPFRAG_H_

struct fragent {
	TAILQ_ENTRY(fragent) next;
	u_short off;
	u_short len;
	u_short size;
	u_char *data;
};

struct fragment {
	SPLAY_ENTRY(fragment) node;
	TAILQ_ENTRY(fragment) next;

	TAILQ_HEAD(fragq, fragent) fraglist;
	struct event *timeout;

	enum fragpolicy fragp;

	ip_addr_t ip_src;	/* Network order */
	ip_addr_t ip_dst;	/* Network order */
	u_short ip_id;		/* Network order */
	u_char ip_proto;

	u_short maxlen;		
	u_short hadlastpacket;
};

#define IPFRAG_TIMEOUT		30

#define IPFRAG_MAX_MEM		(25*1024*1024)
#define IPFRAG_MAX_FRAGS	(10000)

void ip_fragment_init(void);
int ip_fragment(struct template *, struct ip_hdr *, u_short,
    struct ip_hdr **, u_short *);
void ip_send_fragments(u_int, struct ip_hdr *, u_int, struct spoof);
#endif
