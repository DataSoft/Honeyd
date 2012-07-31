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

extern struct evbuffer *_buf;

static int __inline
decode_int_internal(uint32_t *pnumber, struct evbuffer *evbuf, int dodrain)
{
	uint32_t number = 0;
	uint8_t *data = EVBUFFER_DATA(evbuf);
	int len = EVBUFFER_LENGTH(evbuf);
	int nibbles = 0, off;

	if (!len)
		return (-1);

	nibbles = ((data[0] & 0xf0) >> 4) + 1;
	if (nibbles > 8 || (nibbles >> 1) > len - 1)
		return (-1);

	off = nibbles;
	while (off > 0) {
		number <<= 4;
		if (off & 0x1)
			number |= data[off >> 1] & 0x0f;
		else
			number |= (data[off >> 1] & 0xf0) >> 4;
		off--;
	}

	len = (nibbles >> 1) + 1;
	if (dodrain)
		evbuffer_drain(evbuf, len);

	*pnumber = number;

	return (len);
}

int
decode_int(uint32_t *pnumber, struct evbuffer *evbuf)
{
	return (decode_int_internal(pnumber, evbuf, 1) == -1 ? -1 : 0);
}

int
tag_peek(struct evbuffer *evbuf, uint8_t *ptag)
{
	if (EVBUFFER_LENGTH(evbuf) < 2)
		return (-1);
	*ptag = EVBUFFER_DATA(evbuf)[0];

	return (0);
}

int
tag_peek_length(struct evbuffer *evbuf, uint32_t *plength)
{
	struct evbuffer *tmp = evbuffer_new();
	int res;

	if (EVBUFFER_LENGTH(evbuf) < 2)
	{
		evbuffer_free(tmp);
		return (-1);
	}

	if(evbuffer_add_buffer(tmp, evbuf) == -1)
	{
		//Error, copy failed
		evbuffer_free(tmp);
		return -1;
	}

	evbuffer_drain(tmp, 1);

	res = decode_int_internal(plength, tmp, 0);
	if (res == -1)
	{
		evbuffer_free(tmp);
		return (-1);
	}

	*plength += res + 1;

	evbuffer_free(tmp);
	return (0);
}

int
tag_consume(struct evbuffer *evbuf)
{
	uint32_t len;
	evbuffer_drain(evbuf, 1);
	if (decode_int(&len, evbuf) == -1)
		return (-1);
	evbuffer_drain(evbuf, len);

	return (0);
}

/* Reads the data type from an event buffer */

int
tag_unmarshal(struct evbuffer *src, uint8_t *ptag, struct evbuffer *dst)
{
	uint8_t tag;
	uint16_t len;
	uint32_t integer;

	if (evbuffer_remove(src, &tag, sizeof(tag)) != sizeof(tag))
		return (-1);
	if (decode_int(&integer, src) == -1)
		return (-1);
	len = integer;

	if (EVBUFFER_LENGTH(src) < len)
		return (-1);

	if (evbuffer_add(dst, EVBUFFER_DATA(src), len) == -1)
		return (-1);

	evbuffer_drain(src, len);

	*ptag = tag;
	return (len);
}

/* Marshaling for integers */

int
tag_unmarshal_int(struct evbuffer *evbuf, uint8_t need_tag, uint32_t *pinteger)
{
	uint8_t tag;
	uint16_t len;
	uint32_t integer;

	if (evbuffer_remove(evbuf, &tag, sizeof(tag)) != sizeof(tag) ||
	    tag != need_tag)
		return (-1);
	if (decode_int(&integer, evbuf) == -1)
		return (-1);
	len = integer;

	if (EVBUFFER_LENGTH(evbuf) < len)
		return (-1);
	
	evbuffer_drain(_buf, EVBUFFER_LENGTH(_buf));
	if (evbuffer_add(_buf, EVBUFFER_DATA(evbuf), len) == -1)
		return (-1);

	evbuffer_drain(evbuf, len);

	return (decode_int(pinteger, _buf));
}

/* Unmarshal a fixed length tag */

int
tag_unmarshal_fixed(struct evbuffer *src, uint8_t need_tag, void *data,
    size_t len)
{
	uint8_t tag;

	/* Initialize this event buffer so that we can read into it */
	evbuffer_drain(_buf, EVBUFFER_LENGTH(_buf));

	/* Now unmarshal a tag and check that it matches the tag we want */
	if (tag_unmarshal(src, &tag, _buf) == -1 || tag != need_tag)
		return (-1);

	if (EVBUFFER_LENGTH(_buf) != len)
		return (-1);

	memcpy(data, EVBUFFER_DATA(_buf), len);
	return (0);
}

int
tag_unmarshal_string(struct evbuffer *evbuf, uint8_t need_tag, char **pstring)
{
	uint8_t tag;

	evbuffer_drain(_buf, EVBUFFER_LENGTH(_buf));

	if (tag_unmarshal(evbuf, &tag, _buf) == -1 || tag != need_tag)
		return (-1);

	*pstring = calloc(EVBUFFER_LENGTH(_buf) + 1, 1);
	if (*pstring == NULL)
		err(1, "%s: calloc", __func__);
	evbuffer_remove(_buf, *pstring, EVBUFFER_LENGTH(_buf));

	return (0);
}

int
tag_unmarshal_timeval(struct evbuffer *evbuf, uint8_t need_tag,
    struct timeval *ptv)
{
	uint8_t tag;
	uint32_t integer;

	evbuffer_drain(_buf, EVBUFFER_LENGTH(_buf));
	if (tag_unmarshal(evbuf, &tag, _buf) == -1 || tag != need_tag)
		return (-1);

	if (decode_int(&integer, _buf) == -1)
		return (-1);
	ptv->tv_sec = integer;
	if (decode_int(&integer, _buf) == -1)
		return (-1);
	ptv->tv_usec = integer;

	return (0);
}

int
tag_unmarshal_record(struct evbuffer *evbuf, uint8_t need_tag,
    struct record *record)
{
	uint8_t tag;

	struct evbuffer *tmp = evbuffer_new();

	if (tag_unmarshal(evbuf, &tag, tmp) == -1 || tag != need_tag)
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

#define UNMARSHAL(tag, what) \
	tag_unmarshal_fixed(evbuf, tag, &(what), sizeof(what))

int
addr_unmarshal(struct addr* addr, struct evbuffer *evbuf)
{
	uint32_t tmp_int;

	memset(addr, 0, sizeof(struct addr));

	if (tag_unmarshal_int(evbuf, ADDR_TYPE,	&tmp_int) == -1)
		return (-1);
	addr->addr_type = tmp_int;

	if (tag_unmarshal_int(evbuf, ADDR_BITS, &tmp_int) == -1)
		return (-1);
	addr->addr_bits = tmp_int;

	switch (addr->addr_type) {
	case ADDR_TYPE_ETH:
		tag_unmarshal_fixed(evbuf, ADDR_ADDR,
		    &addr->addr_eth, sizeof(addr->addr_eth));
		break;
	case ADDR_TYPE_IP:
		tag_unmarshal_fixed(evbuf, ADDR_ADDR,
		    &addr->addr_ip, sizeof(addr->addr_ip));
		break;
	case ADDR_TYPE_IP6:
		tag_unmarshal_fixed(evbuf, ADDR_ADDR,
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
	uint8_t tag;

	memset(record, 0, sizeof(struct record));
	TAILQ_INIT(&record->hashes);

	/* The timevals are optional, so we need to check their presence */
	if (tag_peek(evbuf, &tag) != -1 && tag == REC_TV_START) {
		if (tag_unmarshal_timeval(evbuf, REC_TV_START,
			&record->tv_start) == -1)
			goto error;
	}
	if (tag_peek(evbuf, &tag) != -1 && tag == REC_TV_END) {
		if (tag_unmarshal_timeval(evbuf, REC_TV_END,
			&record->tv_end) == -1)
			goto error;
	}

	evbuffer_drain(tmp, EVBUFFER_LENGTH(tmp));
	if (tag_unmarshal(evbuf, &tag, tmp) == -1 || tag != REC_SRC)
		goto error;
	if (addr_unmarshal(&record->src, tmp) == -1)
		goto error;

	evbuffer_drain(tmp, EVBUFFER_LENGTH(tmp));
	if (tag_unmarshal(evbuf, &tag, tmp) == -1 || tag != REC_DST)
		goto error;
	if (addr_unmarshal(&record->dst, tmp) == -1)
		goto error;

	if (tag_unmarshal_int(evbuf, REC_SRC_PORT, &integer) == -1)
		goto error;
	record->src_port = integer;
	if (tag_unmarshal_int(evbuf, REC_DST_PORT, &integer) == -1)
		goto error;
	record->dst_port = integer;
	if (tag_unmarshal_int(evbuf, REC_PROTO, &integer) == -1)
		goto error;
	record->proto = integer;
	if (tag_unmarshal_int(evbuf, REC_STATE, &integer) == -1)
		goto error;
	record->state = integer;

	while (tag_peek(evbuf, &tag) != -1) {
		switch(tag) {
		case REC_OS_FP:
			if (tag_unmarshal_string(evbuf, tag,
				&record->os_fp) == -1)
				goto error;
			break;

		case REC_HASH: {
			struct hash *tmp;

			if ((tmp = calloc(1, sizeof(struct hash))) == NULL)
				err(1, "%s: calloc", __func__);
			if (tag_unmarshal_fixed(evbuf, REC_HASH, tmp->digest,
				sizeof(tmp->digest)) == -1) {
				free(tmp);
				goto error;
			}
			TAILQ_INSERT_TAIL(&record->hashes, tmp, next);
		}
			break;
		case REC_BYTES:
			if (tag_unmarshal_int(evbuf, tag,&record->bytes) == -1)
				goto error;
			break;
		case REC_FLAGS:
			if (tag_unmarshal_int(evbuf, tag,&record->flags) == -1)
				goto error;
			break;
		default:
			syslog(LOG_DEBUG, "Ignoring unknown record tag %d",
			    tag);
			tag_consume(evbuf);
			break;
		}
	}

	evbuffer_free(tmp);
	return (0);

 error:
	evbuffer_free(tmp);
	return (-1);
}

#define TEST_MAX_INT	6

void
tagging_int_test(void)
{
	struct evbuffer *tmp = evbuffer_new();
	uint32_t integers[TEST_MAX_INT] = {
		0xaf0, 0x1000, 0x1, 0xdeadbeef, 0x00, 0xbef000
	};
	uint32_t integer;
	int i;

	for (i = 0; i < TEST_MAX_INT; i++) {
		int oldlen, newlen;
		oldlen = EVBUFFER_LENGTH(tmp);
		encode_int(tmp, integers[i]);
		newlen = EVBUFFER_LENGTH(tmp);
		fprintf(stderr, "\t\tencoded 0x%08x with %d bytes\n",
		    integers[i], newlen - oldlen);
	}

	for (i = 0; i < TEST_MAX_INT; i++) {
		if (decode_int(&integer, tmp) == -1)
			errx(1, "decode %d failed", i);
		if (integer != integers[i])
			errx(1, "got %x, wanted %x", integer, integers[i]);
	}

	if (EVBUFFER_LENGTH(tmp) != 0)
		errx(1, "trailing data");
	evbuffer_free(tmp);

	fprintf(stderr, "\t%s: OK\n", __func__);
}

void
tagging_addr_test(void)
{
	struct evbuffer *tmp = evbuffer_new();
	struct addr one, two;

	addr_pton("192.168.1.16/28", &one);
	addr_marshal(tmp, &one);
	if (addr_unmarshal(&two, tmp) == -1)
		errx(1, "addr unmarshal failed.");
	if (addr_cmp(&one, &two) != 0)
		errx(1, "addr %s != %s", addr_ntoa(&one), addr_ntoa(&two));

	evbuffer_free(tmp);

	fprintf(stderr, "\t%s: OK\n", __func__);
}

void
tagging_record_test(void)
{
	struct evbuffer *tmp = evbuffer_new();
	struct record one, two;
	uint32_t length = 0;

	memset(&one, 0, sizeof(one));
	memset(&two, 0, sizeof(two));

	TAILQ_INIT(&one.hashes);
	addr_pton("127.0.0.1", &one.src);
	addr_pton("192.168.0.1", &one.dst);
	gettimeofday(&one.tv_start, NULL);
	one.proto = IP_PROTO_TCP;
	one.os_fp = "Honeyd Machine";
	one.bytes = 100;

	record_marshal(tmp, &one);
	if (tag_peek_length(tmp, &length) == -1 || length == 0)
		errx(1, "tag_peek_length failed.");

	if (record_unmarshal(&two, tmp) == -1)
		errx(1, "record unmarshal failed.");
	if (strcmp(one.os_fp, two.os_fp) != 0)
		errx(1, "fingerprints not the same");

	/* Equal out the variable fields */
	free(two.os_fp); two.os_fp = one.os_fp;
	two.hashes = one.hashes;

	if (memcmp(&one, &two, sizeof(one)) != 0)
		errx(1, "records not the same");

	evbuffer_free(tmp);

	fprintf(stderr, "\t%s: OK\n", __func__);
}

void
tagging_fuzz()
{
	u_char buffer[4096];
	struct evbuffer *tmp = evbuffer_new();
	rand_t *rand = rand_open();
	struct record record;
	struct addr addr;
	int i, j;

	for (j = 0; j < 100; j++) {
		for (i = 0; i < sizeof(buffer); i++)
			buffer[i] = rand_uint8(rand);
		evbuffer_drain(tmp, -1);
		evbuffer_add(tmp, buffer, sizeof(buffer));

		if (tag_unmarshal_record(tmp, 1, &record) != -1)
			errx(1, "tag_unmarshal_record should have failed");
		if (addr_unmarshal(&addr, tmp) != -1)
			errx(1, "addr_unmarshal should have failed");
		if (record_unmarshal(&record, tmp) != -1)
			errx(1, "record_unmarshal should have failed");
	}

	/* Now insert some corruption into the tag length field */
	evbuffer_drain(tmp, -1);
	addr_pton("127.0.0.0/20", &addr);
	addr_marshal(tmp, &addr);
	evbuffer_add(tmp, buffer, sizeof(buffer));

	EVBUFFER_DATA(tmp)[1] = 0xff;
	if (addr_unmarshal(&addr, tmp) != -1)
		errx(1, "addr_unmarshal should have failed");

	evbuffer_free(tmp);

	rand_close(rand);
	fprintf(stderr, "\t%s: OK\n", __func__);
}

void
tagging_test(void)
{
	tagging_init();
	tagging_int_test();
	tagging_addr_test();
	tagging_record_test();
	tagging_fuzz();
}
