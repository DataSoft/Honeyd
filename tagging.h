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

#ifndef _TAGGING_
#define _TAGGING_

#define SHINGLE_MIN	32
#define SHINGLE_MAX	1024
#define SHINGLE_SIZE	8

struct hash {
	TAILQ_ENTRY(hash) next;
	u_char digest[SHINGLE_SIZE];
};

enum RECORDTAGS {
	REC_TV_START, REC_TV_END, REC_SRC, REC_DST, REC_SRC_PORT, REC_DST_PORT,
	REC_PROTO, REC_STATE, REC_OS_FP, REC_HASH, REC_BYTES, REC_FLAGS,
	REC_MAX_TAGS
};

extern enum RECORDTAGS record_tags;

#define RECORD_STATE_NEW	0x01

struct record {
	struct timeval tv_start;	/* optional */
	struct timeval tv_end;		/* optional */
	struct addr src;
	struct addr dst;
	uint16_t src_port;
	uint16_t dst_port;
	uint8_t proto;
	uint8_t state;
	char *os_fp;			/* optional */
	uint32_t bytes;			/* optional */
	uint32_t flags;			/* optional */
#define REC_FLAG_LOCAL	0x0001		/* local connection */

	TAILQ_HEAD(hashq, hash) hashes;	/* optional */
};

enum STATE {
	ADDR_TYPE, ADDR_BITS, ADDR_ADDR, ADDR_MAX_TAGS
};

extern enum STATE address_tags;


void record_marshal(struct evbuffer *, struct record *);

void addr_marshal(struct evbuffer *, struct addr *);

void tag_marshal_record(struct evbuffer *evbuf, uint8_t tag,
    struct record *record);

#endif /* _TAGGING_ */
