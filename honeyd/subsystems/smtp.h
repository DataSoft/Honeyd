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

#ifndef _SMTP_H_
#define _SMTP_H_

#define LOCKNAME	".lock"
#define COUNTNAME	".count"

struct smtp_ta {
	int fd;
	struct bufferevent *bev;

	char *mailer_id;
	struct keyvalueq dictionary;

	uint8_t wantclose:1,
		unused:7;

	enum {
		EXPECT_HELO,
		EXPECT_MAILFROM,
		EXPECT_RCPT,
		EXPECT_DATA
	} state;

	struct sockaddr_storage sa;	/* remote host */
	socklen_t salen;

	struct sockaddr_storage lsa;	/* local host */
	socklen_t lsalen;

	int dns_pending;
	int dns_canceled;
};

struct smtp_ta *smtp_ta_new(int fd, struct sockaddr *sa, socklen_t salen,
    struct sockaddr *lsa, socklen_t lsalen, int greeting);
void smtp_ta_free(struct smtp_ta *ta);
void smtp_bind_socket(struct event *ev, u_short port);
void smtp_store(struct smtp_ta *ta, const char *dir);
void smtp_greeting(struct smtp_ta *ta);
int smtp_set_datadir(const char *optarg);

#endif /* _SMTP_H_ */
