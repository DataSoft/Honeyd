/*
 * Copyright (c) 2005 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 *
 * <LICENSEHERE>
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

	void *dnsres_handle;	/* used to cancel a pending callback */
};

struct proxy_ta *proxy_ta_new(int fd, struct sockaddr *sa, socklen_t salen,
    struct sockaddr *lsa, socklen_t lsalen);
void proxy_ta_free(struct proxy_ta *ta);
void proxy_bind_socket(struct event *ev, u_short port);
void proxy_init(void);
char *proxy_pcre_group(char *line, int groupnr, int ovector[]);

#endif /* _PROXY_H_ */
