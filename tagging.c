/*
 * Copyright (c) 2003, 2004 Niels Provos <provos@citi.umich.edu>
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

#include <event.h>
#include <pcap.h>
#include <dnet.h>

#include "tagging.h"

struct evbuffer *_buf;

void
tagging_init()
{
	_buf = evbuffer_new();
}

void
tag_marshal_record(struct evbuffer *evbuf, uint8_t tag, struct record *record)
{
	struct evbuffer *tmp = evbuffer_new();

	record_marshal(tmp, record);
	evtag_marshal(evbuf, tag, EVBUFFER_DATA(tmp), EVBUFFER_LENGTH(tmp));
	evbuffer_free(tmp);
}

/* 
 * Functions for un/marshaling dnet's struct addr; we create a tagged
 * stream to save space.  Otherwise, we would have pay the overhead of
 * IPv6 address sizes for every kind of address.
 */

void
addr_marshal(struct evbuffer *evbuf, struct addr *addr)
{
	evtag_marshal_int(evbuf, ADDR_TYPE, addr->addr_type);
	evtag_marshal_int(evbuf, ADDR_BITS, addr->addr_bits);

	switch(addr->addr_type)
	{
		case ADDR_TYPE_ETH:
		{
			evtag_marshal(evbuf, ADDR_ADDR, &(addr->addr_eth), sizeof(addr->addr_eth));
			break;
		}
		case ADDR_TYPE_IP:
		{
			evtag_marshal(evbuf, ADDR_ADDR, &(addr->addr_ip), sizeof(addr->addr_ip));
			break;
		}
		case ADDR_TYPE_IP6:
		{
			evtag_marshal(evbuf, ADDR_ADDR, &(addr->addr_ip6), sizeof(addr->addr_ip6));
			break;
		}
	}
}

/* 
 * Functions to un/marshal records.
 */

void
record_marshal(struct evbuffer *evbuf, struct record *record)
{
	struct evbuffer *addr = evbuffer_new();
	struct hash *hash;

	if (timerisset(&record->tv_start))
		evtag_marshal_timeval(evbuf, REC_TV_START, &record->tv_start);
	if (timerisset(&record->tv_end))
		evtag_marshal_timeval(evbuf, REC_TV_END, &record->tv_end);

	/* Encode an address */
	evbuffer_drain(addr, EVBUFFER_LENGTH(addr));
	addr_marshal(addr, &record->src);
	evtag_marshal(evbuf, REC_SRC, EVBUFFER_DATA(addr), EVBUFFER_LENGTH(addr));

	evbuffer_drain(addr, EVBUFFER_LENGTH(addr));
	addr_marshal(addr, &record->dst);
	evtag_marshal(evbuf, REC_DST, EVBUFFER_DATA(addr), EVBUFFER_LENGTH(addr));

	evtag_marshal_int(evbuf, REC_SRC_PORT, record->src_port);
	evtag_marshal_int(evbuf, REC_DST_PORT, record->dst_port);
	evtag_marshal_int(evbuf, REC_PROTO, record->proto);
	evtag_marshal_int(evbuf, REC_STATE, record->state);

	if (record->os_fp != NULL)
		evtag_marshal_string(evbuf, REC_OS_FP, record->os_fp);

	TAILQ_FOREACH(hash, &record->hashes, next)
		evtag_marshal(evbuf, REC_HASH, hash->digest, sizeof(hash->digest));

	if (record->bytes)
		evtag_marshal_int(evbuf, REC_BYTES, record->bytes);
	if (record->flags)
		evtag_marshal_int(evbuf, REC_FLAGS, record->flags);

	evbuffer_free(addr);
}
