/*
 * Copyright (c) 2003, 2004 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 *
 * <LICENSEHERE>
 */
#ifndef _UI_H_
#define _UI_H_

struct uiclient {
	int fd;

	struct event ev_read;
	struct event ev_write;

	struct evbuffer *inbuf;
	struct evbuffer *outbuf;
};

void ui_init(void);

#define UI_FIFO		"/var/run/honeyd.sock"

#endif /* !_UI_H_ */
