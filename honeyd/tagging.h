/*
 * Copyright (c) 2003, 2004 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 *
 * <LICENSEHERE>
 */

#ifndef _TAGGING_
#define _TAGGING_

void tagging_init(void);

#define SHINGLE_MIN	32
#define SHINGLE_MAX	1024
#define SHINGLE_SIZE	8

struct hash {
	TAILQ_ENTRY(hash) next;
	u_char digest[SHINGLE_SIZE];
};

enum {
	REC_TV_START, REC_TV_END, REC_SRC, REC_DST, REC_SRC_PORT, REC_DST_PORT,
	REC_PROTO, REC_STATE, REC_OS_FP, REC_HASH, REC_BYTES, REC_FLAGS,
	REC_MAX_TAGS
} record_tags;

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

enum {
	ADDR_TYPE, ADDR_BITS, ADDR_ADDR, ADDR_MAX_TAGS
} address_tags;

void record_marshal(struct evbuffer *, struct record *);

void addr_marshal(struct evbuffer *, struct addr *);

/* 
 * Marshaling tagged data - We assume that all tags are inserted in their
 * numeric order - so that unknown tags will always be higher than the
 * known ones - and we can just ignore the end of an event buffer.
 */

void tag_marshal(struct evbuffer *evbuf, uint8_t tag, void *data,
    uint16_t len);

void encode_int(struct evbuffer *evbuf, uint32_t number);

void tag_marshal_int(struct evbuffer *evbuf, uint8_t tag, uint32_t integer);

void tag_marshal_string(struct evbuffer *buf, uint8_t tag, char *string);

void tag_marshal_timeval(struct evbuffer *evbuf, uint8_t tag,
    struct timeval *tv);

void tag_marshal_record(struct evbuffer *evbuf, uint8_t tag,
    struct record *record);

#endif /* _TAGGING_ */
