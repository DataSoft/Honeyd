/*
 * Copyright (c) 2002, 2003, 2004 Niels Provos <provos@citi.umich.edu>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_SYS_IOCCOM_H
#include <sys/ioccom.h>
#endif
#include <sys/resource.h>
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
#include <signal.h>
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#include <fcntl.h>
#include <unistd.h>
#include <getopt.h>
#include <dnet.h>

#undef timeout_pending
#undef timeout_initialized

#include <event.h>

#include "honeyd.h"
#include "tagging.h"
#include "untagging.h"
#include "stats.h"
#include "histogram.h"
#include "honeydstats.h"
#include "analyze.h"

/* Stubs to make it compile */

int pcap_datalink(void *some) {	return (-1); }
char *honeyd_osfp_name(struct ip_hdr *hdr) { return (NULL); }
void hooks_add_packet_hook(int protocol, int dir, void *callback, void *arg) {}

/* Prototypes */
int
make_socket(int (*f)(int, const struct sockaddr *, socklen_t), int type,
    char *address, uint16_t port);

static int
user_compare(struct user *a, struct user *b)
{
	return (strcmp(a->name, b->name));
}

struct usertree users;

SPLAY_PROTOTYPE(usertree, user, node, user_compare);
SPLAY_GENERATE(usertree, user, node, user_compare);

int checkpoint_fd = -1;
struct evbuffer *checkpoint_evbuf;
static struct timeval checkpoint_tv;
static int checkpoint_doreplay = 0;

void
user_new(const char *name, const char *password)
{
	struct user *user = NULL, tmp;

	tmp.name = name;
	if ((user = SPLAY_FIND(usertree, &users, &tmp)) == NULL) {
		if ((user = calloc(1, sizeof(struct user))) == NULL)
			err(1, "%s: calloc", __func__);

		if ((user->name = strdup(name)) == NULL)
			err(1, "%s: strdup", __func__);

		gettimeofday(&user->tv_when, NULL);

		SPLAY_INSERT(usertree, &users, user);

		syslog(LOG_NOTICE, "Added user '%s'", name);
	}

	hmac_init(&user->hmac, password);
}

/*
 * Reads rows of username:password entries.  We use this information
 * to authenticate and validate the reports that we receive.
 */

int
user_read_config(const char *filename)
{
	FILE *fin;
	char line[1024];
	int nrline = 0, res = -1;

	if ((fin = fopen(filename, "r")) == NULL)
		return (-1);

	while (fgets(line, sizeof(line), fin) != NULL) {
		char *user, *password, *p = line;

		nrline++;
		user = strsep(&p, ":");
		password = strsep(&p, ":\r\n");

		if (user == NULL || password == NULL) {
			syslog(LOG_WARNING,
			    "%s:%d: cannot read user and password",
			    filename, nrline);
			goto out;
		}

		user_new(user, password);
	}

	res = 0;
 out:
	fclose(fin);
	return (res);
}

/* 
 * We just got a single record - now fold it into the different
 * stats structures.
 */

int
record_process(struct user *user, struct evbuffer *evbuf)
{
	struct record *record;
	int res = -1;

	if ((record = calloc(1, sizeof(struct record))) == NULL)
		err(1, "%s: calloc", __func__);

	if (tag_unmarshal_record(evbuf, M_RECORD, record) == -1) {
		syslog(LOG_WARNING,
		    "%s: failed to unmashal record for user '%s'",
		    __func__, user->name);
		goto out;
	}

	analyze_record(record);

	res = 0;
 out:
	record_clean(record);
	free(record);
	return (res);
}

int
measurement_process(struct user *user, struct evbuffer *evbuf)
{
	uint32_t counter;
	struct timeval tv_start, tv_end, tv_diff;
	time_t tstart;
	ev_uint32_t tag;

	if (evtag_unmarshal_int(evbuf, M_COUNTER, &counter) == -1)
		return (-1);
	if (evtag_unmarshal_timeval(evbuf, M_TV_START, &tv_start) == -1)
		return (-1);

	if (evtag_unmarshal_timeval(evbuf, M_TV_END, &tv_end) == -1)
		return (-1);

	timersub(&tv_end, &tv_start, &tv_diff);
	tstart =  tv_start.tv_sec;
	if (!checkpoint_doreplay || user->nreports % 60 == 0)
		syslog(LOG_INFO,
		    "%s: %ld seconds of data at measurement period %.24s",
		    user->name, tv_diff.tv_sec, ctime(&tstart));

	/* 
	 * If we get a new time then we can update the counter,
	 * otherwise we accept only counters that are newer than
	 * our sequence number.
	 */
	if (timercmp(&user->tv_last, &tv_start, <)) {
		user->tv_last = tv_start;
		user->seqnr = counter;
	} else if (counter - user->seqnr > 0x80000000L) {
		syslog(LOG_WARNING, "%s: replayed packet: %d, expecting %d",
		    user->name, counter, user->seqnr);
		return (-1);
	}

	/* Write the data that we previously appended */
	if (checkpoint_fd != -1) {
		/* XXX - this might block */
		evbuffer_write(checkpoint_evbuf, checkpoint_fd);
	} else if (checkpoint_doreplay &&
	    timercmp(&checkpoint_tv, &tv_end, <)) {
		checkpoint_tv = tv_end;
	}

	user->nreports++;
	user->seqnr = counter;

	while (evtag_peek(evbuf, &tag) != -1) {
		if (tag != M_RECORD) {
			evtag_consume(evbuf);
			continue;
		}

		/* This is a record tag */
		record_process(user, evbuf);
	}

	return (0);
}

int
signature_process(struct evbuffer *evbuf)
{
	struct user *user = NULL, tmpuser;
	ev_uint32_t tag;
	struct evbuffer *tmp = NULL;
	char *username = NULL;
	u_char digest[SHA1_DIGESTSIZE];
	int res = -1;

	if (checkpoint_fd != -1) {
		evbuffer_drain(checkpoint_evbuf, -1);
		evbuffer_add(checkpoint_evbuf,
		    EVBUFFER_DATA(evbuf), EVBUFFER_LENGTH(evbuf));
	}

	if (evtag_unmarshal_string(evbuf, SIG_NAME, &username) == -1)
		goto out;
	if (evtag_unmarshal_fixed(evbuf, SIG_DIGEST, digest,
		sizeof(digest)) == -1)
		goto out;

	tmpuser.name = username;
	if ((user = SPLAY_FIND(usertree, &users, &tmpuser)) == NULL) {
		syslog(LOG_WARNING, "Unknown user '%s'", username);
		goto out;
	}

	if ((tmp = evbuffer_new()) == NULL)
		err(1, "%s: evbuffer_new");
	if (evtag_unmarshal(evbuf, &tag, tmp) == -1)
		goto out;

	/* Validate signature */
	if (!hmac_verify(&user->hmac, digest, sizeof(digest),
		EVBUFFER_DATA(tmp), EVBUFFER_LENGTH(tmp))) {
		syslog(LOG_WARNING, "Bad signature on data from user '%s'",
		    username);
		goto out;
	}

	switch(tag) {
	case SIG_COMPRESSED_DATA:
		if (stats_decompress(tmp) == -1) {
			syslog(LOG_WARNING,
			    "failed to decompress for user '%s'", username);
			goto out;
		}
		/* FALLTHROUGH */
	case SIG_DATA:
		measurement_process(user, tmp);
		break;
	default:
		syslog(LOG_NOTICE, "%s: unknown signature tag %d", 
		    __func__, tag);
		goto out;
	}

	res = 0;
 out:
	if (tmp != NULL)
		evbuffer_free(tmp);
	if (username != NULL)
		free(username);

	return (res);
}

/* Sleazy little code to peek into marshalled signatures */

static int
signature_length(struct evbuffer *evbuf)
{
	struct evbuffer *tmp = evbuffer_new();
	uint32_t length, tlen;

	if(evbuffer_add_buffer(tmp, evbuf) == -1)
	{
		evbuffer_free(tmp);
		return -1;
	}

	/* name */
	if (evtag_peek_length(tmp, &tlen) == -1 || EVBUFFER_LENGTH(tmp) < tlen)
	{
		evbuffer_free(tmp);
		return -1;
	}
		
	length = tlen;
	evbuffer_drain(tmp, tlen);

	/* signature */
	if (evtag_peek_length(tmp, &tlen) == -1 || EVBUFFER_LENGTH(tmp) < tlen)
	{
		evbuffer_free(tmp);
		return -1;
	}
		
	length += tlen;
	evbuffer_drain(tmp, tlen);

	/* data */
	if (evtag_peek_length(tmp, &tlen) == -1 || EVBUFFER_LENGTH(tmp) < tlen)
	{
		evbuffer_free(tmp);
		return -1;
	}
		
	length += tlen;

	evbuffer_free(tmp);
	return length;
}

void
checkpoint_replay(int fd)
{
	struct evbuffer *evbuf = evbuffer_new();
	int nread;

	fprintf(stderr, "Replaying checkpoint ...\n");
	count_set_time(&checkpoint_tv);
	checkpoint_doreplay = 1;
	analyze_set_checkpoint_doreplay(1);

	/* Read all the data and process it */
	while ((nread = evbuffer_read(evbuf, fd, 4096)) > 0) {
		int length;

		while ((length = signature_length(evbuf)) != -1 &&
		    EVBUFFER_LENGTH(evbuf) >= length) {
				signature_process(evbuf);
		}
	}

	/* Print the output at the last time we saw data from the checkpoint */
	analyze_print_report();

	checkpoint_doreplay = 0;
	analyze_set_checkpoint_doreplay(0);
	count_set_time(NULL);

	fprintf(stderr, "... checkpoint replayed\n");

	evbuffer_free(evbuf);
	close(fd);
}
