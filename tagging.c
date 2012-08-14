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

/*
 * Marshal a data type, the general format is as follows:
 *
 * tag number: one byte; length: var bytes; payload: var bytes
 */

void
tag_marshal(struct evbuffer *evbuf, uint8_t tag, void *data, uint16_t len)
{
	evbuffer_add(evbuf, &tag, sizeof(tag));
	encode_int(evbuf, len);
	evbuffer_add(evbuf, data, len);
}

/* Marshaling for integers */
void
tag_marshal_int(struct evbuffer *evbuf, uint8_t tag, uint32_t integer)
{
	evbuffer_drain(_buf, EVBUFFER_LENGTH(_buf));
	encode_int(_buf, integer);

	evbuffer_add(evbuf, &tag, sizeof(tag));
	encode_int(evbuf, EVBUFFER_LENGTH(_buf));
	evbuffer_add_buffer(evbuf, _buf);
}

void
tag_marshal_string(struct evbuffer *buf, uint8_t tag, char *string)
{
	tag_marshal(buf, tag, string, strlen(string));
}

void
tag_marshal_timeval(struct evbuffer *evbuf, uint8_t tag, struct timeval *tv)
{
	evbuffer_drain(_buf, EVBUFFER_LENGTH(_buf));

	encode_int(_buf, tv->tv_sec);
	encode_int(_buf, tv->tv_usec);

	tag_marshal(evbuf, tag, EVBUFFER_DATA(_buf),
	    EVBUFFER_LENGTH(_buf));
}

void
tag_marshal_record(struct evbuffer *evbuf, uint8_t tag, struct record *record)
{
	struct evbuffer *tmp = evbuffer_new();

	record_marshal(tmp, record);
	tag_marshal(evbuf, tag, EVBUFFER_DATA(tmp), EVBUFFER_LENGTH(tmp));
	evbuffer_free(tmp);
}

/* 
 * Functions for un/marshaling dnet's struct addr; we create a tagged
 * stream to save space.  Otherwise, we would have pay the overhead of
 * IPv6 address sizes for every kind of address.
 */

#define MARSHAL(tag, what) do { \
	tag_marshal(evbuf, tag, &(what), sizeof(what)); \
} while (0)

void
addr_marshal(struct evbuffer *evbuf, struct addr *addr)
{
	tag_marshal_int(evbuf, ADDR_TYPE, addr->addr_type);
	tag_marshal_int(evbuf, ADDR_BITS, addr->addr_bits);

	switch (addr->addr_type) {
	case ADDR_TYPE_ETH:
		MARSHAL(ADDR_ADDR, addr->addr_eth);
		break;
	case ADDR_TYPE_IP:
		MARSHAL(ADDR_ADDR, addr->addr_ip);
		break;
	case ADDR_TYPE_IP6:
		MARSHAL(ADDR_ADDR, addr->addr_ip6);
		break;
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
		tag_marshal_timeval(evbuf, REC_TV_START, &record->tv_start);
	if (timerisset(&record->tv_end))
		tag_marshal_timeval(evbuf, REC_TV_END, &record->tv_end);

	/* Encode an address */
	evbuffer_drain(addr, EVBUFFER_LENGTH(addr));
	addr_marshal(addr, &record->src);
	tag_marshal(evbuf, REC_SRC, EVBUFFER_DATA(addr), EVBUFFER_LENGTH(addr));

	evbuffer_drain(addr, EVBUFFER_LENGTH(addr));
	addr_marshal(addr, &record->dst);
	tag_marshal(evbuf, REC_DST, EVBUFFER_DATA(addr), EVBUFFER_LENGTH(addr));

	tag_marshal_int(evbuf, REC_SRC_PORT, record->src_port);
	tag_marshal_int(evbuf, REC_DST_PORT, record->dst_port);
	tag_marshal_int(evbuf, REC_PROTO, record->proto);
	tag_marshal_int(evbuf, REC_STATE, record->state);

	if (record->os_fp != NULL)
		tag_marshal_string(evbuf, REC_OS_FP, record->os_fp);

	TAILQ_FOREACH(hash, &record->hashes, next)
	    tag_marshal(evbuf, REC_HASH, hash->digest, sizeof(hash->digest));

	if (record->bytes)
		tag_marshal_int(evbuf, REC_BYTES, record->bytes);
	if (record->flags)
		tag_marshal_int(evbuf, REC_FLAGS, record->flags);

	evbuffer_free(addr);
}
