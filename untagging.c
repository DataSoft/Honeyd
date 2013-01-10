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
#include "untagging.h"

int
tag_unmarshal_record(struct evbuffer *evbuf, uint8_t need_tag,
    struct record *record)
{
	ev_uint32_t tag;

	struct evbuffer *tmp = evbuffer_new();

	if (evtag_unmarshal(evbuf, &tag, tmp) == -1 || tag != need_tag)
		goto error;

	if (record_unmarshal(record, tmp) == -1)
		goto error;

	evbuffer_free(tmp);
	return (0);

 error:
	evbuffer_free(tmp);
	return (-1);
}

/* 
 * Functions for un/marshaling dnet's struct addr; we create a tagged
 * stream to save space.  Otherwise, we would have pay the overhead of
 * IPv6 address sizes for every kind of address.
 */

int
addr_unmarshal(struct addr* addr, struct evbuffer *evbuf)
{
	uint32_t tmp_int;

	memset(addr, 0, sizeof(struct addr));

	if (evtag_unmarshal_int(evbuf, ADDR_TYPE,	&tmp_int) == -1)
		return (-1);
	addr->addr_type = tmp_int;

	if (evtag_unmarshal_int(evbuf, ADDR_BITS, &tmp_int) == -1)
		return (-1);
	addr->addr_bits = tmp_int;

	switch (addr->addr_type) {
	case ADDR_TYPE_ETH:
		evtag_unmarshal_fixed(evbuf, ADDR_ADDR,
		    &addr->addr_eth, sizeof(addr->addr_eth));
		break;
	case ADDR_TYPE_IP:
		evtag_unmarshal_fixed(evbuf, ADDR_ADDR,
		    &addr->addr_ip, sizeof(addr->addr_ip));
		break;
	case ADDR_TYPE_IP6:
		evtag_unmarshal_fixed(evbuf, ADDR_ADDR,
		    &addr->addr_ip6, sizeof(addr->addr_ip6));
		break;
	default:
		return (-1);
	}

	return (0);
}

/* 
 * Functions to un/marshal records.
 */

int
record_unmarshal(struct record *record, struct evbuffer *evbuf)
{
	struct evbuffer *tmp = evbuffer_new();
	uint32_t integer;
	ev_uint32_t tag;

	memset(record, 0, sizeof(struct record));
	TAILQ_INIT(&record->hashes);

	/* The timevals are optional, so we need to check their presence */
	if (evtag_peek(evbuf, &tag) != -1 && tag == REC_TV_START) {
		if (evtag_unmarshal_timeval(evbuf, REC_TV_START,
			&record->tv_start) == -1)
			goto error;
	}
	if (evtag_peek(evbuf, &tag) != -1 && tag == REC_TV_END) {
		if (evtag_unmarshal_timeval(evbuf, REC_TV_END,
			&record->tv_end) == -1)
			goto error;
	}

	evbuffer_drain(tmp, EVBUFFER_LENGTH(tmp));
	if (evtag_unmarshal(evbuf, &tag, tmp) == -1 || tag != REC_SRC)
		goto error;
	if (addr_unmarshal(&record->src, tmp) == -1)
		goto error;

	evbuffer_drain(tmp, EVBUFFER_LENGTH(tmp));
	if (evtag_unmarshal(evbuf, &tag, tmp) == -1 || tag != REC_DST)
		goto error;
	if (addr_unmarshal(&record->dst, tmp) == -1)
		goto error;

	if (evtag_unmarshal_int(evbuf, REC_SRC_PORT, &integer) == -1)
		goto error;
	record->src_port = integer;
	if (evtag_unmarshal_int(evbuf, REC_DST_PORT, &integer) == -1)
		goto error;
	record->dst_port = integer;
	if (evtag_unmarshal_int(evbuf, REC_PROTO, &integer) == -1)
		goto error;
	record->proto = integer;
	if (evtag_unmarshal_int(evbuf, REC_STATE, &integer) == -1)
		goto error;
	record->state = integer;

	while (evtag_peek(evbuf, &tag) != -1) {
		switch(tag) {
		case REC_OS_FP:
			if (evtag_unmarshal_string(evbuf, tag,
				&record->os_fp) == -1)
				goto error;
			break;

		case REC_HASH: {
			struct hash *tmp;

			if ((tmp = calloc(1, sizeof(struct hash))) == NULL)
			{
				syslog(LOG_ERR, "%s: calloc", __func__);
				exit(EXIT_FAILURE);
			}
			if (evtag_unmarshal_fixed(evbuf, REC_HASH, tmp->digest,
				sizeof(tmp->digest)) == -1) {
				free(tmp);
				goto error;
			}
			TAILQ_INSERT_TAIL(&record->hashes, tmp, next);
		}
			break;
		case REC_BYTES:
			if (evtag_unmarshal_int(evbuf, tag,&record->bytes) == -1)
				goto error;
			break;
		case REC_FLAGS:
			if (evtag_unmarshal_int(evbuf, tag,&record->flags) == -1)
				goto error;
			break;
		default:
			syslog(LOG_DEBUG, "Ignoring unknown record tag %d",
			    tag);
			evtag_consume(evbuf);
			break;
		}
	}

	evbuffer_free(tmp);
	return (0);

 error:
	evbuffer_free(tmp);
	return (-1);
}
