/*
 * Copyright (c) 2005 Niels Provos <provos@citi.umich.edu>
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

#ifndef _PROXY_H_
#define _PROXY_H_

#define X_FORWARDED "X-Forwarded-For:"
#define CORRUPT_SPACE	20

struct proxy_ta {
	int fd;
	struct bufferevent *bev;

	int remote_fd;
	struct bufferevent *remote_bev;

	char *proxy_id;

	uint8_t wantclose:1,
		justforward:1,
		corrupt:1,
		unused:5;

	struct keyvalueq dictionary;

	struct sockaddr_storage sa;
	socklen_t salen;

	int (*empty_cb)(struct proxy_ta *);

	int dns_pending;
	int dns_canceled;
};

struct proxy_ta *proxy_ta_new(int fd, struct sockaddr *sa, socklen_t salen,
    struct sockaddr *lsa, socklen_t lsalen);
void proxy_ta_free(struct proxy_ta *ta);
void proxy_bind_socket(struct event *ev, u_short port);
void proxy_init(void);
char *proxy_pcre_group(char *line, int groupnr, int ovector[]);

#endif /* _PROXY_H_ */
