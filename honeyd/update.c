/*
 * Copyright (c) 2002, 2003, 2004 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 *
 * <LICENSEHERE>
 */

#include <sys/types.h>
#include <sys/param.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/queue.h>
#include <sys/tree.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#include <sys/utsname.h>

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <syslog.h>

#include <dnet.h>
#include <event.h>

#include "update.h"

char *security_update = NULL;

static int update_ev_initialized;
static struct event update_ev;
static struct event update_connect_ev;

int make_socket(int (*f)(int, const struct sockaddr *, socklen_t), int type,
    char *address, uint16_t port);
void update_cb(int, short, void *);
void update_connect_cb(int, short, void *);

void
update_check(void)
{
	static int host_resolved;
	static struct addr host_addr;
	struct timeval tv;
	int fd;

	if (!update_ev_initialized) {
		update_ev_initialized = 1;

		evtimer_set(&update_ev, update_cb, &update_ev);
	}

	if (!host_resolved) {
		if (addr_pton("www.honeyd.org", &host_addr) == -1) {
			syslog(LOG_WARNING, "%s: failed to resolve host.",
			    __func__);
			goto reschedule;
		}

		host_resolved = 1;
	}

	fd = make_socket(connect, SOCK_STREAM, addr_ntoa(&host_addr), 80);
	if (fd == -1) {
		syslog(LOG_WARNING, "%s: failed to connect: %m", __func__);
		goto reschedule;
	}

	event_set(&update_connect_ev, fd, EV_WRITE,
	    update_connect_cb, &update_connect_ev);
	event_add(&update_connect_ev, NULL);

 reschedule:
	timerclear(&tv);
	tv.tv_sec = 24 * 60 * 60;
	evtimer_add(&update_ev, &tv);
}

static void
update_parse_information(char *data, size_t length)
{
	/* No security update for us? */
	if (!length)
		return;

	if (security_update != NULL)
		free(security_update);
	if ((security_update = malloc(length) + 1) == NULL)
		err(1, "%s: malloc");
	memcpy(security_update, data, length);
	security_update[length] = '\0';

	/* Warn the user that their version is vulnerable and needs update */
	syslog(LOG_WARNING, "SECURITY INFO: %s", security_update);
}

void
update_cb(int fd, short what, void *arg)
{
	update_check();
}

static void
update_readcb(struct bufferevent *bev, void *parameter)
{
	/* 
	 * If we did not receive the complete request and we have
	 * waited for too long already, then we drop the request.
	 */
	if (EVBUFFER_LENGTH(bev->input) > 32000) {
		syslog(LOG_NOTICE,
		    "Dropping update reply with size %d",
		    EVBUFFER_LENGTH(bev->input));
		close(bev->ev_read.ev_fd);
		bufferevent_free(bev);
		return;
	}

	/* We just need to wait now for the end of the transmission */
}

static void
update_writecb(struct bufferevent *bev, void *parameter)
{
	/* We are done writing - no wait for the response */
	bufferevent_disable(bev, EV_WRITE);
	bufferevent_enable(bev, EV_READ);
}

static void
update_errorcb(struct bufferevent *bev, short what, void *parameter)
{
	char *data = evbuffer_find(bev->input, "\r\n\r\n", 4);
	char *p, *end, *error_code;

	if (!(what & EVBUFFER_EOF) || data == NULL)
		goto error;

	end = EVBUFFER_DATA(bev->input);
	p = strsep(&end, " ");
	if (end == NULL || *end == '\0')
		goto error;

	error_code = strsep(&end, " ");
	if (error_code == NULL || end == NULL || *end == '\0')
		goto error;

	if (strcmp(error_code, "200"))
		goto error;

	evbuffer_drain(bev->input,
	    (int)(data - (int)EVBUFFER_DATA(bev->input) + 4));

	update_parse_information(EVBUFFER_DATA(bev->input),
	    EVBUFFER_LENGTH(bev->input));

	close(bev->ev_read.ev_fd);
	bufferevent_free(bev);
	return;

 error:
	/* bufferevent_free should really close the file descriptor */
	close(bev->ev_read.ev_fd);
	syslog(LOG_WARNING, "%s: failed to get security update information",
	    __func__);
	bufferevent_free(bev);
	return;
}

void
update_make_request(struct bufferevent *bev)
{
	char *request =
	    "GET /check.php?version=%s&os=%s HTTP/1.0\r\n"
	    "Host: www.honeyd.org\r\n"
	    "User-Agent: %s/%s\r\n"
	    "\r\n";
	static char buf[1024];
	static char os[64];
	struct utsname name;

	/* Find the operating system */
	if (uname(&name) == -1)
		snprintf(os, sizeof(os), "unknown");
	else
		snprintf(os, sizeof(os), "%s+%s", name.sysname, name.release);

	snprintf(buf, sizeof(buf), request, VERSION, os, PACKAGE, VERSION);
	bufferevent_write(bev, buf, strlen(buf));
}

void
update_connect_cb(int fd, short what, void *arg)
{
	struct bufferevent *bev = NULL;
	int error;
	socklen_t errsz = sizeof(error);

	/* Check if the connection completed */
	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &errsz) == -1 ||
	    error) {
		syslog(LOG_WARNING, "%s: connection failed: %m", __func__);
		close(fd);
		return;
	}

	/* We successfully connected to the host */
	bev = bufferevent_new(fd, update_readcb, update_writecb,
	    update_errorcb, NULL);
	if (bev == NULL) {
		syslog(LOG_WARNING, "%s: bufferevent_new: %m", __func__);
		close(fd);
		return;
	}

	bufferevent_settimeout(bev, 60, 60);

	update_make_request(bev);
}
