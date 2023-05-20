#pragma once
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

#ifndef _STATS_
#define _STATS_

#include <sha1.h>
#include "honeyd.h"
#include "tagging.h"

struct record;

struct hmac_state {
#define HMAC_BLOCK_SIZE	64
	u_char ipad[64];
	u_char opad[64];
	SHA1_CTX ictx;
	SHA1_CTX octx;
};

/* Functions exported to the public */

/*
 * Export records to a remote stats collector.  username and password are
 * used to authenticate the origin of the data.
 */
void stats_init_collect(struct addr *remote, u_short port,
    char *username, char *password);
/*
 * Initialize stats collection so that other consumers can make use of them.
 */
void stats_init(void);

/*
 * Register a callback that gets executed everytime that a record is being
 * created.
 */
void stats_register_cb(int (*cb)(const struct record *, void *), void *cb_arg);

void stats_test(void);

#define STATS_MAX_HASHES		64
#define STATS_MAX_SIZE			1400
#define STATS_TIMEOUT			300
#define STATS_SEND_TIMEOUT		15
#define STATS_MEASUREMENT_INTERVAL	20

struct stats {
	SPLAY_ENTRY(stats) node;
	TAILQ_ENTRY(stats) next;

	struct tuple conhdr;
	struct record record;

	struct hashq hashes;
	struct evbuffer *evbuf;

	struct event *ev_timeout;

	uint8_t isactive:1,
		needelete:1,
		reserved:4;
};

enum MEASURETAGS {
	M_COUNTER, M_TV_START, M_TV_END, M_RECORD, M_MAX
};

extern enum MEASURETAGS measurement_tags;

struct measurement {
	uint32_t counter;
	struct timeval tv_start;
	struct timeval tv_end;
};

#ifndef SHA1_DIGESTSIZE
#define SHA1_DIGESTSIZE	20
#endif

enum SIGTAGS {
	SIG_NAME, SIG_DIGEST, SIG_DATA, SIG_COMPRESSED_DATA, SIG_MAX
};

extern enum SIGTAGS signature_tags;

struct signature {
	char *name;
	u_char digest[SHA1_DIGESTSIZE];
};

struct hashq;
struct stats_packet {
	TAILQ_ENTRY(stats_packet) next;

	struct evbuffer *evbuf;
};

struct hashq;
void record_remove_hashes(struct hashq *r);
void record_add_hash(struct hashq *r, void *data, size_t len);
void record_fill(struct record *r, const struct tuple *hdr);
void record_clean(struct record *r);

void stats_free(struct stats *);

void stats_compress(struct evbuffer *evbuf);
int stats_decompress(struct evbuffer *evbuf);

void stats_measure_cb(int fd, short what, void *arg);

void hmac_init(struct hmac_state *, const char *);
int hmac_verify(const struct hmac_state *, u_char *sign, size_t signlen,
    const void *data, size_t len);

#endif /* _STATS_ */
