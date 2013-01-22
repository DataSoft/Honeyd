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
#ifndef _HONEYDSTATS_H_
#define _HONEYDSTATS_H_

#include "stats.h"

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

struct event_base *stats_libevent_base;

int signature_process(struct evbuffer *evbuf);
void checkpoint_replay(int fd);
void syslog_init(int argc, char *argv[]);

int user_read_config(const char *filename);

#endif
