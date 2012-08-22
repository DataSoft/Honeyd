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
#include <sha1.h>
#ifdef HAVE_ASSERT_U
#include <assert.h>
#else
#define assert(x)
#endif

#include <event.h>
#include <pcap.h>
#include <dnet.h>
#include <zlib.h>

#include "honeyd.h"
#include "hooks.h"
#include "tagging.h"
#include "osfp.h"
#include "stats.h"

int make_socket(int (*f)(int, const struct sockaddr *, socklen_t), int type,
    char *, uint16_t);
static void stats_make_fd(struct addr *, u_short);
static void stats_activate(struct stats *stats);
static void stats_deactivate(struct stats *stats);

/* Many static variables.  We don't like them */

/* We might have other consumers of our created records */
struct statscb {
	TAILQ_ENTRY(statscb) next;

	int (*cb)(const struct record *, void *);
	void *cb_arg;
};

struct statscontrol {
	char *user_name;
	char *user_key;
	struct addr *user_dst;
	u_short user_port;
	int stats_fd;
	struct event ev_send;

	struct measurement measurement;
	struct timeval tv_start;
	struct event ev_measure;
	struct evbuffer *evbuf_measure;
	struct evbuffer *evbuf_tmp;

	struct hmac_state hmac;

	TAILQ_HEAD(statscbq, statscb) callbacks;

	TAILQ_HEAD(statspackets, stats_packet) send_queue;
	TAILQ_HEAD(statsqueue, stats) active_stats;
	SPLAY_HEAD(statstree, stats) all_stats;
};

struct statscontrol sc;


static int
compare(struct stats *a, struct stats *b)
{
	return (conhdr_compare(&a->conhdr, &b->conhdr));
}

SPLAY_PROTOTYPE(statstree, stats, node, compare);
SPLAY_GENERATE(statstree, stats, node, compare);

/* Initialize the message authentication code that we use for signing */

void
hmac_init(struct hmac_state *hmac, const char *key)
{
	int i;

	memset(hmac->ipad, 0x36, sizeof(hmac->ipad));
	memset(hmac->opad, 0x5c, sizeof(hmac->opad));

	for (i = 0; i < strlen(key) + 1 && i < sizeof(hmac->ipad); i++) {
		hmac->ipad[i] ^= key[i];
		hmac->opad[i] ^= key[i];
	}

	SHA1Init(&hmac->ictx);
	SHA1Update(&hmac->ictx, hmac->ipad, sizeof(hmac->ipad));
	SHA1Init(&hmac->octx);
	SHA1Update(&hmac->octx, hmac->opad, sizeof(hmac->opad));
}

void
hmac_sign(const struct hmac_state *hmac, u_char *dst, size_t dstlen,
    const void *data, size_t len)
{
	SHA1_CTX ctx;
	u_char digest[SHA1_DIGESTSIZE];

	assert(dstlen <= SHA1_DIGESTSIZE);

	ctx = hmac->ictx;
	SHA1Update(&ctx, data, len);
	SHA1Final(digest, &ctx);

	ctx = hmac->octx;
	SHA1Update(&ctx, digest, sizeof(digest));
	SHA1Final(digest, &ctx);

	memcpy(dst, digest, dstlen);
}

int
hmac_verify(const struct hmac_state *hmac, u_char *sign, size_t signlen,
    const void *data, size_t len)
{
	u_char digest[SHA1_DIGESTSIZE];

	assert(signlen <= SHA1_DIGESTSIZE);

	hmac_sign(hmac, digest, sizeof(digest), data, len);

	return (memcmp(digest, sign, signlen) == 0);
}

/* Per packet compression */

void
stats_compress(struct evbuffer *evbuf)
{
	static struct evbuffer *tmp;
	static z_stream stream;
	static u_char buffer[2048];
	int status;
	
	/* Initialize buffer and compressor */
	if (tmp == NULL) {
		tmp = evbuffer_new();
		deflateInit(&stream, 9);
	}
	deflateReset(&stream);

	stream.next_in = EVBUFFER_DATA(evbuf);
	stream.avail_in = EVBUFFER_LENGTH(evbuf);

	do {
		stream.next_out = buffer;
		stream.avail_out = sizeof(buffer);

		status = deflate(&stream, Z_FULL_FLUSH);

		switch (status) {
		case Z_OK:
			/* Append compress data to buffer */
			evbuffer_add(tmp, buffer,
			    sizeof(buffer) - stream.avail_out);
			break;
		default:
			errx(1, "%s: deflate failed with %d",
			    __func__, status);
			/* NOTREACHED */
		}
	} while (stream.avail_out == 0);

	evbuffer_drain(evbuf, EVBUFFER_LENGTH(evbuf));
	evbuffer_add_buffer(evbuf, tmp);
}

int
stats_decompress(struct evbuffer *evbuf)
{
	static struct evbuffer *tmp;
	static z_stream stream;
	static u_char buffer[2048];
	int status, done = 0;
	
	/* Initialize buffer and compressor */
	if (tmp == NULL) {
		tmp = evbuffer_new();
		inflateInit(&stream);
	}
	inflateReset(&stream);

	stream.next_in = EVBUFFER_DATA(evbuf);
	stream.avail_in = EVBUFFER_LENGTH(evbuf);

	do {
		stream.next_out = buffer;
		stream.avail_out = sizeof(buffer);

		status = inflate(&stream, Z_FULL_FLUSH);

		switch (status) {
		case Z_OK:
			/* Append compress data to buffer */
			evbuffer_add(tmp, buffer,
			    sizeof(buffer) - stream.avail_out);
			break;

		case Z_BUF_ERROR:
			done = 1;
			break;

		default:
			warnx("%s: inflate failed with %d", __func__, status);
			return (-1);
		}
	} while (!done);

	evbuffer_drain(evbuf, EVBUFFER_LENGTH(evbuf));
	evbuffer_add_buffer(evbuf, tmp);

	return (0);
}

/* Quick shingling */

/*
 * We want to compute hashes over blocks that can potentially change,
 * so we use shingling; see rsync or lbfs.
 */

static void
stats_shingle_data(struct stats *stats)
{
	uint16_t hash = 0;

	while (EVBUFFER_LENGTH(stats->evbuf) >= SHINGLE_MIN) {
		u_char *data = EVBUFFER_DATA(stats->evbuf);
		int i;

		/* So, we are wasting some time here, but that's alright */
		for (i = SHINGLE_MIN;
		    i < EVBUFFER_LENGTH(stats->evbuf) - 4; i++) {
			if (i >= SHINGLE_MAX)
				break;
			hash = ((~data[i] << 8 | data[i+1]) +
			    (data[i + 3] << 8 | ~data[i+2])) % 213;
			if (hash == 0)
				break;
		}

		/* If we run out of data, then we just return */
		if (hash && i < SHINGLE_MAX)
			return;

		record_add_hash(&stats->hashes, data, i);
		evbuffer_drain(stats->evbuf, i);

		stats_activate(stats);
	}
}

/* Adds a regular timeout at which stats are sent off to a monitor */

static void
stats_measure_timeout(void)
{
	struct timeval tv, now;
	uint32_t diff_ms;

	gettimeofday(&now, NULL);
	timersub(&now, &sc.tv_start, &now);
	diff_ms = (now.tv_sec * 1000) + (now.tv_usec / 1000);
	diff_ms %= (STATS_MEASUREMENT_INTERVAL * 1000);
	diff_ms = (STATS_MEASUREMENT_INTERVAL * 1000) - diff_ms;

	tv.tv_sec = diff_ms / 1000;
	tv.tv_usec = diff_ms * 1000;

	evtimer_add(&sc.ev_measure, &tv);
}


static void
stats_add_timeout(struct stats *stats)
{
	struct timeval tv;

	timerclear(&tv);
	tv.tv_sec = STATS_TIMEOUT;
	evtimer_add(&stats->ev_timeout, &tv);
}

static struct stats *
stats_find(const struct tuple *conhdr)
{
	struct stats tmp, *res;
	tmp.conhdr = *conhdr;
	res = SPLAY_FIND(statstree, &sc.all_stats, &tmp);

	if (res != NULL)
		stats_add_timeout(res);

	return (res);
}

static void
stats_activate(struct stats *stats)
{
	if (stats->isactive)
		return;
	stats->isactive = 1;
	TAILQ_INSERT_TAIL(&sc.active_stats, stats, next);
}

static void
stats_reactivate(struct stats *stats)
{
	if (stats->isactive)
		return;
	stats->isactive = 1;
	TAILQ_INSERT_HEAD(&sc.active_stats, stats, next);
}

static void
stats_deactivate(struct stats *stats)
{
	if (!stats->isactive)
		return;

	/* Once it has been deactivate, it is not new any longer */
	stats->record.state &= ~RECORD_STATE_NEW;

	stats->isactive = 0;
	TAILQ_REMOVE(&sc.active_stats, stats, next);
}

static void
stats_ready_cb(int fd, short what, void *arg)
{
	struct stats_packet *tmp;

	tmp = TAILQ_FIRST(&sc.send_queue);
	TAILQ_REMOVE(&sc.send_queue, tmp, next);
	if (what != EV_TIMEOUT) {
		syslog(LOG_DEBUG, "writing stats of length %d",
		    EVBUFFER_LENGTH(tmp->evbuf));
		if (evbuffer_write(tmp->evbuf, fd) == -1) {
			syslog(LOG_WARNING,
			    "remote stats daemon unreachable: %m");
			close(fd);
			stats_make_fd(sc.user_dst, sc.user_port);
		}
	}

	/* Free the entry */
	evbuffer_free(tmp->evbuf);
	free(tmp);

	if (TAILQ_FIRST(&sc.send_queue) != NULL) {
		struct timeval tv;
		timerclear(&tv);
		tv.tv_sec = STATS_SEND_TIMEOUT;
		event_add(&sc.ev_send, &tv);
	}
}

static void
stats_prepare_send(struct evbuffer *evbuf)
{
	struct timeval tv;
	struct stats_packet *tmp;

	assert(sc.stats_fd != -1);
	
	if ((tmp = calloc(1, sizeof(struct stats_packet))) == NULL)
		err(1, "%s: calloc", __func__);

	tmp->evbuf = evbuf;
	TAILQ_INSERT_TAIL(&sc.send_queue, tmp, next);

	timerclear(&tv);
	tv.tv_sec = STATS_SEND_TIMEOUT;
	event_add(&sc.ev_send, &tv);
}

static void
stats_package_measurement()
{
	struct evbuffer *evbuf;
	u_char digest[SHA1_DIGESTSIZE];

	/* Do not send any file data when we don't have a collector defined */
	if (sc.stats_fd == -1)
		return;
	
	if ((evbuf = evbuffer_new()) == NULL)
		err(1, "%s: evbuffer_new", __func__);

	/* Compress the measured data */
	stats_compress(sc.evbuf_measure);

	/* Sign the data - at this point, we could use compression */
	hmac_sign(&sc.hmac, digest, sizeof(digest),
	    EVBUFFER_DATA(sc.evbuf_measure),
	    EVBUFFER_LENGTH(sc.evbuf_measure));

	/* Create the signed buffer */
	evtag_marshal_string(evbuf, SIG_NAME, sc.user_name);
	evtag_marshal(evbuf, SIG_DIGEST, digest, sizeof(digest));
	evtag_marshal(evbuf, SIG_COMPRESSED_DATA,
	    EVBUFFER_DATA(sc.evbuf_measure),
	    EVBUFFER_LENGTH(sc.evbuf_measure));

	stats_prepare_send(evbuf);
}

void
measurement_marshal(struct evbuffer *evbuf, struct measurement *m)
{
	evtag_marshal_int(sc.evbuf_measure, M_COUNTER, m->counter);
	evtag_marshal_timeval(sc.evbuf_measure, M_TV_START, &m->tv_start);
	evtag_marshal_timeval(sc.evbuf_measure, M_TV_END, &m->tv_end);
}

/*
 * Packages up the measured data and sents it to a collector.
 */

static void
stats_measure_cb(int fd, short what, void *arg)
{
	struct stats *stats;
	struct statscb *statscb;
	
	/* Schedule a new timeout */
	stats_measure_timeout();

	gettimeofday(&sc.measurement.tv_end, NULL);

	while ((stats = TAILQ_FIRST(&sc.active_stats)) != NULL) {
		evbuffer_drain(sc.evbuf_measure, -1);
		sc.measurement.counter++;
		measurement_marshal(sc.evbuf_measure, &sc.measurement);
		while ((stats = TAILQ_FIRST(&sc.active_stats)) != NULL &&
		    EVBUFFER_LENGTH(sc.evbuf_measure) < STATS_MAX_SIZE) {
			struct hash *hash;
			int i;

			/* 
			 * If the object is going to be deleted and we still
			 * have some unhashed data, we are going to hash it
			 * now.
			 */
			if (stats->needelete &&
			    EVBUFFER_LENGTH(stats->evbuf) >= SHINGLE_MIN) {
				record_add_hash(&stats->hashes,
				    EVBUFFER_DATA(stats->evbuf),
				    EVBUFFER_LENGTH(stats->evbuf));
				evbuffer_drain(stats->evbuf,
				    EVBUFFER_LENGTH(stats->evbuf));
			}

			/* 
			 * Add hashes to record, but limit to a
			 * reasonable number, so that we do not create
			 * too big a stats packet.
			 */
			for (i = 0, hash = TAILQ_FIRST(&stats->hashes);
			    i < STATS_MAX_HASHES && hash != NULL;
			    i++, hash = TAILQ_FIRST(&stats->hashes)) {
				TAILQ_REMOVE(&stats->hashes, hash, next);
				TAILQ_INSERT_TAIL(&stats->record.hashes, hash,
				    next);
			}

			/*
			 * Check if we have any external consumers of
			 * our records.
			 */
			TAILQ_FOREACH(statscb, &sc.callbacks, next) {
				if ((*statscb->cb)(&stats->record,
					statscb->cb_arg) == 1)
					break;
			}
			
			/*
			 * Add to temporary buffer first, so that we can 
			 * check our size contraints.
			 */

			evbuffer_drain(sc.evbuf_tmp, -1);
			tag_marshal_record(sc.evbuf_tmp, M_RECORD,
			    &stats->record);

			/* Remove data that we have reported */
			record_remove_hashes(&stats->record.hashes);
			stats->record.bytes = 0;

			/* Toggles the new state flag */
			stats_deactivate(stats);

			/*
			 * If there are still hashes left in the stats
			 * object, we need to reactivate it, so that the
			 * next round, we get the rest.
			 */
			if (TAILQ_FIRST(&stats->hashes) != NULL)
				stats_reactivate(stats);

			/* 
			 * If the entry is no longer used, we need to remove
			 * it after we reported it's data.
			 */
			if (stats->needelete && !stats->isactive)
				stats_free(stats);

			if (EVBUFFER_LENGTH(sc.evbuf_measure) +
			    EVBUFFER_LENGTH(sc.evbuf_tmp) >= STATS_MAX_SIZE) {
				/* Package up current packet */
				stats_package_measurement();

				/*
				 * Now clear the buffer and prepare it for
				 * more stats.
				 */
				evbuffer_drain(sc.evbuf_measure, -1);
				measurement_marshal(sc.evbuf_measure,
				    &sc.measurement);
			}

			evbuffer_add_buffer(sc.evbuf_measure, sc.evbuf_tmp);
		}

		stats_package_measurement();
	}

	/* Start the next measuring period */
	sc.measurement.tv_start = sc.measurement.tv_end;
	timerclear(&sc.measurement.tv_end);
}

static void
stats_timeout_cb(int fd, short what, void *arg)
{
	struct stats *stats = arg;

	stats_free(stats);
}

struct stats *
stats_new(const struct tuple *conhdr)
{
	struct stats *stats;

	syslog(LOG_DEBUG, "Creating new stats buffer for %s",
	    honeyd_contoa(conhdr));

	assert(stats_find(conhdr) == NULL);
	if ((stats = calloc(1, sizeof(struct stats))) == NULL)
		err(1, "%s: calloc", __func__);

	TAILQ_INIT(&stats->hashes);
	stats->conhdr = *conhdr;

	record_fill(&stats->record, conhdr);

	if ((stats->evbuf = evbuffer_new()) == NULL)
		err(1, "%s: evbuffer_new", __func__);

	evtimer_set(&stats->ev_timeout, stats_timeout_cb, stats);
	stats_add_timeout(stats);

	stats->record.state = RECORD_STATE_NEW;

	SPLAY_INSERT(statstree, &sc.all_stats, stats);
	stats_activate(stats);

	return (stats);
}

void
record_add_hash(struct hashq *hashes, void *data, size_t len)
{
	struct hash *hash, *tmp;
	u_char digest[SHA1_DIGESTSIZE];
	SHA1_CTX ctx;
	int i;

	SHA1Init(&ctx);
	SHA1Update(&ctx, data, len);
	SHA1Final(digest, &ctx);

	if ((hash = calloc(1, sizeof(struct hash))) == NULL)
		err(1, "%s: calloc", __func__);

	/* We just xor the overlap together */
	for (i = 0; i < sizeof(digest); i++)
		hash->digest[i % SHINGLE_SIZE] ^= digest[i];

	/* This is really slow, but maybe it's not that bad */
	TAILQ_FOREACH(tmp, hashes, next) {
		if (memcmp(tmp->digest, hash->digest, SHINGLE_SIZE) == 0)
			break;
	}

	if (tmp == NULL)
		TAILQ_INSERT_TAIL(hashes, hash, next);
}

void
record_fill(struct record *r, const struct tuple *hdr)
{
	struct ip_hdr ip;
	char *name;

	TAILQ_INIT(&r->hashes);

	/* Fill the connection header */
	addr_pack(&r->src, ADDR_TYPE_IP, IP_ADDR_BITS,
	    &hdr->ip_src, IP_ADDR_LEN);
	addr_pack(&r->dst, ADDR_TYPE_IP, IP_ADDR_BITS,
	    &hdr->ip_dst, IP_ADDR_LEN);

	r->src_port = hdr->sport;
	r->dst_port = hdr->dport;
	gettimeofday(&r->tv_start, NULL);
	r->proto = hdr->type == SOCK_STREAM ? IP_PROTO_TCP : IP_PROTO_UDP;

        ip.ip_src = hdr->ip_src;
        name = honeyd_osfp_name(&ip);
	if (name != NULL)
		r->os_fp = strdup(name);

	/*
	 * Mark this connection as one that originated locally.  This will
	 * allow our stats measurement mechanisms to ignore it.
	 */
	if (hdr->local)
		r->flags |= REC_FLAG_LOCAL;
}

void
record_remove_hashes(struct hashq *hashes)
{
	struct hash *hash;
	
	while ((hash = TAILQ_FIRST(hashes)) != NULL) {
		TAILQ_REMOVE(hashes, hash, next);
		free(hash);
	}
}

void
record_clean(struct record *record)
{
	record_remove_hashes(&record->hashes);

	if (record->os_fp) {
		free(record->os_fp);
		record->os_fp = NULL;
	}
}

void
stats_free(struct stats *stats)
{
	SPLAY_REMOVE(statstree, &sc.all_stats, stats);
	stats_deactivate(stats);

	evtimer_del(&stats->ev_timeout);

	record_clean(&stats->record);
	record_remove_hashes(&stats->hashes);
	evbuffer_free(stats->evbuf);
	free(stats);
}

/* Functions for processing incoming network data */

static void
stats_process_data(struct stats *stats, void *data, u_int len)
{
	if (data == NULL) {
		/* This object has been terminated */
		gettimeofday(&stats->record.tv_end, NULL);
		stats->needelete = 1;
		return;
	}

	stats->record.bytes += len;

	evbuffer_add(stats->evbuf, data, len);
	stats_shingle_data(stats);
}

static void
stats_tcp_input(struct tuple *conhdr, u_char *pkt, u_int pktlen, void *arg)
{
	struct stats *stats = stats_find(conhdr);

	if (stats == NULL)
		stats = stats_new(conhdr);
	else if (stats->record.os_fp == NULL) {
		/* Update the passive fingerprint, if possible */
		char *name;
		struct ip_hdr ip;
		ip.ip_src = conhdr->ip_src;
		name = honeyd_osfp_name(&ip);
		if (name != NULL)
			stats->record.os_fp = strdup(name);
	}
		
}

static void
stats_udp_input(struct tuple *conhdr, u_char *pkt, u_int pktlen, void *arg)
{
	struct stats *stats = stats_find(conhdr);

	if (stats == NULL)
		stats = stats_new(conhdr);
}

static void
stats_tcp_data(struct tuple *conhdr, u_char *pkt, u_int pktlen, void *arg)
{
	struct stats *stats = stats_find(conhdr);
	if (stats == NULL)
		return;

	stats_process_data(stats, pkt, pktlen);
}

static void
stats_udp_data(struct tuple *conhdr, u_char *pkt, u_int pktlen, void *arg)
{
	struct stats *stats = stats_find(conhdr);
	if (stats == NULL)
		return;

	stats_process_data(stats, pkt, pktlen);
}

static void
stats_make_fd(struct addr *dst, u_short port)
{
	sc.stats_fd = make_socket(connect, SOCK_DGRAM, addr_ntoa(dst), port);
	if (sc.stats_fd == -1)
		err(1, "%s: make_socket", __func__);
	event_set(&sc.ev_send, sc.stats_fd, EV_WRITE, stats_ready_cb, NULL);
}

void
stats_register_cb(int (*cb)(const struct record *, void *), void *cb_arg)
{
	struct statscb *statscb = calloc(1, sizeof(struct statscb));
	assert(statscb != NULL);

	statscb->cb = cb;
	statscb->cb_arg = cb_arg;

	TAILQ_INSERT_TAIL(&sc.callbacks, statscb, next);
}

void
stats_init_collect(struct addr *dst, u_short port, char *name, char *password)
{
	sc.user_name = name;
	sc.user_key = password;
	sc.user_dst = dst;
	sc.user_port = port;

	stats_make_fd(dst, port);

	/* Set up message authentication code */
	hmac_init(&sc.hmac, sc.user_key);
}

void
stats_init()
{
	/* Information to establish the authentication */
	memset(&sc, 0, sizeof(sc));
	sc.stats_fd = -1;

	/* Setup hooks that we use for data processing */
	hooks_add_packet_hook(IP_PROTO_TCP, HD_INCOMING,
	    stats_tcp_input, NULL);
	hooks_add_packet_hook(IP_PROTO_UDP, HD_INCOMING,
	    stats_udp_input, NULL);

	hooks_add_packet_hook(IP_PROTO_TCP, HD_INCOMING_STREAM,
	    stats_tcp_data, NULL);
	hooks_add_packet_hook(IP_PROTO_UDP, HD_INCOMING_STREAM,
	    stats_udp_data, NULL);

	TAILQ_INIT(&sc.callbacks);
	
	TAILQ_INIT(&sc.send_queue);

	TAILQ_INIT(&sc.active_stats);
	SPLAY_INIT(&sc.all_stats);

	sc.evbuf_measure = evbuffer_new();
	sc.evbuf_tmp = evbuffer_new();

	/* Let the measurements begin */
	memset(&sc.measurement, 0, sizeof(sc.measurement));
	gettimeofday(&sc.measurement.tv_start, NULL);
	sc.tv_start = sc.measurement.tv_start;
	evtimer_set(&sc.ev_measure, stats_measure_cb, NULL);

	stats_measure_timeout();
}

void
stats_hmac_test()
{
	u_char digest[SHA1_DIGESTSIZE];
	char *test1 = "test", *test2 = "txst";

	hmac_init(&sc.hmac, "1234");
	hmac_sign(&sc.hmac, digest, sizeof(digest), test1, strlen(test1));

	if (!hmac_verify(&sc.hmac, digest, sizeof(digest),
		test1, strlen(test1)))
		errx(1, "%s: verify failed", __func__);

	if (hmac_verify(&sc.hmac, digest, sizeof(digest),
		test2, strlen(test2)))
		errx(1, "%s: verify should have failed", __func__);

	fprintf(stderr, "\t%s: OK\n", __func__);
}

void
stats_compress_test()
{
	u_char something[1024];
	struct evbuffer *buf = evbuffer_new();
	int i;

	/* Just create some stupid data */
	for (i = 0; i < sizeof(something); i++) {
		if (i == 0)
			something[i] = 1;
		something[i] = i + something[i-1];
	}

	for (i = 0; i < 3; i++) {
		evbuffer_drain(buf, EVBUFFER_LENGTH(buf));
		evbuffer_add(buf, something, sizeof(something));
		stats_compress(buf);
		fprintf(stderr, "\t\t Decompressed: %d, Compressed: %d\n",
		    sizeof(something), EVBUFFER_LENGTH(buf));

		/* Simulate packet loss */
		if (i == 1)
			continue;

		if (stats_decompress(buf) == -1)
			errx(1, "Decompress failed");
		if (EVBUFFER_LENGTH(buf) != sizeof(something))
			errx(1, "Decompressed data has bad length: %d vs %d",
			    EVBUFFER_LENGTH(buf), sizeof(something));
		if (memcmp(something, EVBUFFER_DATA(buf), sizeof(something)))
			errx(1, "Decompressed data is corrupted");
	}

	evbuffer_free(buf);
	fprintf(stderr, "\t%s: OK\n", __func__);
}

void
stats_test(void)
{
	stats_hmac_test();
	stats_compress_test();
}
