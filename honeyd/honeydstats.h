/*
 * Copyright (c) 2002, 2003, 2004 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 *
 * <LICENSEHERE>
 */
#ifndef _HONEYDSTATS_H_
#define _HONEYDSTATS_H_

struct user {
	SPLAY_ENTRY(user) node;
	const char *name;
	struct hmac_state hmac;

	struct timeval tv_when;	/* first time we heard from this user */
	int nreports;		/* how many reports we have received */

	struct timeval tv_last;
	uint32_t seqnr;		/* last sequence number */
};

SPLAY_HEAD(usertree, user);

int signature_process(struct evbuffer *evbuf);
void checkpoint_replay(int fd);
void syslog_init(int argc, char *argv[]);

int user_read_config(const char *filename);

#endif
