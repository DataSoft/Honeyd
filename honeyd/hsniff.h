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
