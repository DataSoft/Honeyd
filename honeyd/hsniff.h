/*
 * Copyright (c) 2002, 2003, 2004 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 *
 * <LICENSEHERE>
 */
#ifndef _HSNIFF_H_
#define _HSNIFF_H_

#define HSNIFF_PIDFILE			"/var/run/hsniff.pid"
#define HSNIFF_MAX_INTERFACES		10
#define HSNIFF_CON_EXPIRE		300

struct tcp_segment {
	TAILQ_ENTRY(tcp_segment) next;
	uint32_t seq;
	size_t len;
	void *data;
};

struct tcp_track {
	struct tuple conhdr;

	uint32_t snd_una;

	TAILQ_HEAD(tcpq, tcp_segment) segments;

	struct event timeout;
};

void hsniff_tcp_timeout(int, short, void *);

void droppriv(uid_t, gid_t);

#endif /* _HSNIFF_H_ */
