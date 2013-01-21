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

#include <sys/param.h>
#include <sys/types.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/queue.h>
#include <sys/socket.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#include <netinet/in.h>

#ifdef HAVE_TIME_H
#include <time.h>
#endif
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <ctype.h>
#include <getopt.h>
#include <err.h>

#include <pcre.h>
#include <event.h>
#include <evdns.h>
#include <dnet.h>

#include "util.h"
#include "proxy.h"
#include "proxy_messages.h"
#include "smtp.h"
#include "honeyd_overload.h"

extern int debug;

#define DFPRINTF(x, y)	do { \
	if (debug >= x) fprintf y; \
} while (0)

/* globals */

FILE *flog_proxy = NULL;	/* log the proxy transactions somewhere */
static pcre *re_connect;	/* regular expression to match connect */
static pcre *re_hostport;	/* extracts host and port */
static pcre *re_get;		/* generic get request */

/* Generic PROXY related code */

char *
proxy_logline(struct proxy_ta *ta)
{
	static char line[1024];
	char *srcipaddress = kv_find(&ta->dictionary, "$srcipaddress");
	char *cmd = kv_find(&ta->dictionary, "$command");
	char *host = kv_find(&ta->dictionary, "$host");
	char *port = kv_find(&ta->dictionary, "$port");
	char *uri = kv_find(&ta->dictionary, "$rawuri");

	if (!strcasecmp("connect", cmd)) {
		snprintf(line, sizeof(line),
		    "%d %s: CONNECT %s:%s",
		    time(NULL), srcipaddress,
		    host, port);
	} else {
		snprintf(line, sizeof(line),
		    "%d %s: GET %s:%s%s", 
		    time(NULL), srcipaddress,
		    host, port, uri);
	}

	return (line);
}

void
proxy_clear_state(struct proxy_ta *ta)
{
	/* XXX - something here */
}

/* Callbacks for PROXY handling */

char *
proxy_response(struct proxy_ta *ta, struct keyvalue data[]) {
	static char line[1024];
	struct keyvalue *cur;

	for (cur = &data[0]; cur->key != NULL; cur++) {
		if (strcmp(ta->proxy_id, cur->key) == 0)
			break;
	}

	if (cur->key == NULL)
		return (NULL);

	strlcpy(line, cur->value, sizeof(line));

	TAILQ_FOREACH(cur, &ta->dictionary, next) {
		strrpl(line, sizeof(line), cur->key, cur->value);
	}
	
	return (line);
}

int
proxy_allowed_network(const char *host)
{
	const char *error;
	int erroroffset;
	pcre *re_uri;
	int rc;
	int ovector[30];
	char *unusednets[] = {
		"^127\\.[0-9]+\\.[0-9]+\\.[0-9]+$",		/* local */
		"^10\\.[0-9]+\\.[0-9]+\\.[0-9]+$",		/* rfc-1918 */
		"^172\\.(1[6-9]|2[0-9]|3[01])\\.[0-9]+\\.[0-9]+$",
		"^192\\.168\\.[0-9]+\\.[0-9]+$",		/* rfc-1918 */
		"^2(2[4-9]|3[0-9])\\.[0-9]+\\.[0-9]+\\.[0-9]+$",/* rfc-1112 */
		"^2(4[0-9]|5[0-5])\\.[0-9]+\\.[0-9]+\\.[0-9]+$",
		"^0\\.[0-9]+\\.[0-9]+\\.[0-9]+$",
		"^255\\.[0-9]+\\.[0-9]+\\.[0-9]+$",
		NULL
	};

	char **p;

	for (p = &unusednets[0]; *p; ++p) {
		re_uri = pcre_compile(*p, PCRE_CASELESS,
		    &error, &erroroffset, NULL);
		if (re_uri == NULL) {
			/* Default to no match */
			fprintf(stderr, "%s: %s: %s at %d",
			    __func__, *p, error, erroroffset);
			return (0);
		}

		/* Match against the URI */
		rc = pcre_exec(re_uri, NULL, host, strlen(host),
		    0, 0, ovector, 30);
		pcre_free(re_uri);

		if (rc >= 0)
			return (0);
	}

	return (1);
}

/*
 * Checks if we are allowed to retrieve a URL from here.
 */

int
proxy_allowed_get(struct proxy_ta *ta, struct keyvalue data[])
{
	const char *error;
	int erroroffset;
	char *host, *uri;
	struct keyvalue *cur;
	pcre *re_uri;
	int rc;
	int ovector[30];

	host = kv_find(&ta->dictionary, "$host");
	uri = kv_find(&ta->dictionary, "$rawuri");

	for (cur = &data[0]; cur->key != NULL; cur++) {
		if (strcmp(host, cur->key) == 0)
			break;
	}

	/* Host is not allowed if we do not find it */
	if (cur->key == NULL)
		return (0);

	re_uri = pcre_compile(cur->value, PCRE_CASELESS,
	    &error, &erroroffset, NULL);
	if (re_uri == NULL) {
		/* Default to no match */
		fprintf(stderr, "%s: %s: %s at %d",
		    __func__, cur->value, error, erroroffset);
		return (0);
	}

	/* Match against the URI */
	rc = pcre_exec(re_uri, NULL, uri, strlen(uri), 0, 0, ovector, 30);

	pcre_free(re_uri);

	return (rc >= 0);
}

int
proxy_bad_connection(struct proxy_ta *ta)
{
	char *response = proxy_response(ta, badconnection);
	bufferevent_write(ta->bev, response, strlen(response));
	ta->wantclose = 1;
	return (0);
}

void
proxy_remote_readcb(struct bufferevent *bev, void *arg)
{
	struct proxy_ta *ta = arg;
	struct evbuffer *buffer = EVBUFFER_INPUT(bev);
	unsigned char *data = EVBUFFER_DATA(buffer);
	size_t len = evbuffer_get_length(buffer);

	bufferevent_write(ta->bev, data, len);
	evbuffer_drain(buffer, len);
}

void
proxy_remote_writecb(struct bufferevent *bev, void *arg)
{
}

void
proxy_remote_errorcb(struct bufferevent *bev, short what, void *arg)
{
	struct proxy_ta *ta = arg;
	struct evbuffer *buffer = EVBUFFER_OUTPUT(ta->bev);
	fprintf(stderr, "%s: called with %p, freeing\n", __func__, arg);

	/* If we still have data to write; we just wait for the flush */
	if (evbuffer_get_length(buffer)) {
		/* Shutdown this site at least - XXX: maybe call shutdown */
		bufferevent_disable(bev, EV_READ|EV_WRITE);

		ta->wantclose = 1;
	} else {
		proxy_ta_free(ta);
	}
}

char *
proxy_corrupt(char *data, size_t len)
{
	static char buffer[4096];
	int corruptions = len / CORRUPT_SPACE + 1;
	int i;

	if (len > sizeof(buffer) || len <= 1)
		return (data);

	memcpy(buffer, data, len);
	for (i = 0; i < corruptions; i++) {
		int off = rand() % (len - 1);
		buffer[off] = rand();
	}

	return (buffer);
}

void
proxy_connect_cb(int fd, short what, void *arg)
{
	char line[1024], *data;
	struct proxy_ta *ta = arg;
	int error;
	socklen_t errsz = sizeof(error);
	char *uri;

	/* Check if the connection completed */
	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &errsz) == -1 ||
	    error) {
		char *response;
		fprintf(stderr, "%s: connection failed: %s\n",
		    __func__, strerror(error));
		close(fd);

		/* Give them a connect error message */
		kv_replace(&ta->dictionary, "$reason", strerror(error));
		response = proxy_response(ta, badconnect);
		bufferevent_write(ta->bev, response, strlen(response));

		ta->wantclose = 1;
		return;
	}

	ta->remote_bev = bufferevent_new(ta->remote_fd,
	    proxy_remote_readcb, proxy_remote_writecb,
	    proxy_remote_errorcb, ta);
	if (ta->bev == NULL) {
		close(fd);
		proxy_ta_free(ta);
		return;
	}

	/* If this get is not allowed, we are going to corrupt the data */
	if (!proxy_allowed_get(ta, allowedhosts))
		ta->corrupt = 1;

	uri = kv_find(&ta->dictionary, "$rawuri");
	snprintf(line, sizeof(line), "GET %s HTTP/1.0\r\n",
	    ta->corrupt ? proxy_corrupt(uri, strlen(uri)) : uri);
	bufferevent_write(ta->remote_bev, line, strlen(line));

	/* Forward all the headers */
	while ((data = kv_find(&ta->dictionary, "data")) != NULL) {
		/* We do not propagate X-Forwarded-For headers */
		if (strncasecmp(X_FORWARDED, data, strlen(X_FORWARDED))) {
			bufferevent_write(ta->remote_bev,
			    ta->corrupt ? proxy_corrupt(data, strlen(data)) :
			    data, strlen(data)); 
			bufferevent_write(ta->remote_bev, "\r\n", 2); 
		}

		/* Do not invalidate this data until we used it */
		kv_remove(&ta->dictionary, "data");
	}
	bufferevent_write(ta->remote_bev, "\r\n", 2); 

	/* Allow the remote site to send us data */
	bufferevent_enable(ta->remote_bev, EV_READ);

	ta->justforward = 1;
}

void
proxy_connect(struct proxy_ta *ta, char *host, int port)
{
	fprintf(stderr, "Connecting to %s port %d\n", host, port);

	ta->remote_fd = -1;
	if (proxy_allowed_network(host)) {
		char *local_ip = kv_find(&ta->dictionary, "$dstipaddress");

		if (local_ip != NULL) {
			ta->remote_fd = make_bound_connect(
				SOCK_STREAM, host, port, local_ip);
		} else {
			ta->remote_fd = make_socket(
				connect, SOCK_STREAM, host, port);
		}
	}
	if (ta->remote_fd == -1) {
		char *response;
		fprintf(stderr, "%s: failed to connect: %s\n",
		    __func__, strerror(errno));
		kv_replace(&ta->dictionary, "$reason", strerror(errno));
		response = proxy_response(ta, badconnect);
		bufferevent_write(ta->bev, response, strlen(response));
		ta->wantclose = 1;
		return;
	}

	/* One handy event to get called back on this */
	event_once(ta->remote_fd, EV_WRITE, proxy_connect_cb, ta, NULL);
}

void
proxy_handle_get_cb(int result, char type, int count, int ttl,
    void *addresses, void *arg)
{
	struct proxy_ta *ta = arg;
	struct addr addr;
	struct in_addr *in_addrs = addresses;
	int port = atoi(kv_find(&ta->dictionary, "$port"));
	char *response;

	if (ta->dns_canceled) {
		proxy_ta_free(ta);
		return;
	}
	ta->dns_pending = 0;

	if (result != DNS_ERR_NONE || type != DNS_IPv4_A || count == 0) {
		response = proxy_response(ta, baddomain);
		bufferevent_write(ta->bev, response, strlen(response));
		ta->wantclose = 1;
		return;
	}

	/* Need to make a connection here */
	bufferevent_disable(ta->bev, EV_READ);

	addr_pack(&addr, ADDR_TYPE_IP, IP_ADDR_BITS, &in_addrs[0], IP_ADDR_LEN);
	proxy_connect(ta, addr_ntoa(&addr), port);
}

int
proxy_handle_get(struct proxy_ta *ta)
{
	char *host = kv_find(&ta->dictionary, "$rawhost");
	int rc;
	int ovector[30];

	kv_replace(&ta->dictionary, "$command", "GET");

	rc = pcre_exec(re_hostport, NULL, host, strlen(host), 0, 0,
	    ovector, 30);
	if (rc >= 0) {
		char *strport = proxy_pcre_group(host, 2, ovector);
		char *real_host = proxy_pcre_group(host, 1, ovector);

		kv_add(&ta->dictionary, "$host", real_host);
		kv_add(&ta->dictionary, "$port", strport);

		free(real_host);
		free(strport);
	} else {
		kv_add(&ta->dictionary, "$host", host);
		kv_add(&ta->dictionary, "$port", "80");
	}

	if (flog_proxy != NULL) {
		char *line = proxy_logline(ta);
		fprintf(flog_proxy, "%s\n", line);
		fflush(flog_proxy);
	}

	/* Try to resolve the domain name */
	evdns_resolve_ipv4(kv_find(&ta->dictionary, "$host"), 0,
	    proxy_handle_get_cb, ta);
	ta->dns_pending = 1;
	return (0);
}

void
proxy_handle_connect_cb(int result, char type, int count, int ttl,
    void *addresses, void *arg)
{
	struct proxy_ta *ta = arg;
	char *host = kv_find(&ta->dictionary, "$host");
	int port = atoi(kv_find(&ta->dictionary, "$port"));
	char *response;
	fprintf(stderr, "Connecting to %s port %d\n", host, port);

	if (ta->dns_canceled) {
		proxy_ta_free(ta);
		return;
	}
	ta->dns_pending = 0;

	if (result != DNS_ERR_NONE) {
		response = proxy_response(ta, baddomain);
		bufferevent_write(ta->bev, response, strlen(response));
		ta->wantclose = 1;
		return;
	}

	if (port != 25 || !proxy_allowed_network(host)) {
		response = proxy_response(ta, badport);
		bufferevent_write(ta->bev, response, strlen(response));
		ta->wantclose = 1;
	} else {
		struct smtp_ta *smtp_ta = NULL;
		int fd = dup(ta->fd);

		if (fd != -1)
			smtp_ta = smtp_ta_new(fd,
			    (struct sockaddr *)&ta->sa, ta->salen, 
			    NULL, 0, 0);
		if (smtp_ta != NULL) {
			response = proxy_response(ta, goodport);
			bufferevent_write(smtp_ta->bev,
			    response, strlen(response));
			smtp_greeting(smtp_ta);

			proxy_ta_free(ta);
		} else {
			kv_add(&ta->dictionary, "$host", host);
			response = proxy_response(ta, badport);
			bufferevent_write(ta->bev, response, strlen(response));
			ta->wantclose = 1;
		}
	}
}

int
proxy_handle_connect(struct proxy_ta *ta)
{
	char *host = kv_find(&ta->dictionary, "$rawhost");
	int rc;
	int ovector[30];

	kv_replace(&ta->dictionary, "$command", "CONNECT");

	rc = pcre_exec(re_hostport, NULL, host, strlen(host), 0, 0,
	    ovector, 30);
	if (rc >= 0) {
		char *strport = proxy_pcre_group(host, 2, ovector);
		char *real_host = proxy_pcre_group(host, 1, ovector);

		kv_add(&ta->dictionary, "$host", real_host);
		kv_add(&ta->dictionary, "$port", strport);

		free(real_host);
		free(strport);
	} else {
		kv_add(&ta->dictionary, "$host", host);
		kv_add(&ta->dictionary, "$port", "80");
	}

	if (flog_proxy != NULL) {
		char *line = proxy_logline(ta);
		fprintf(flog_proxy, "%s\n", line);
		fflush(flog_proxy);
	}

	/* Try to resolve the domain name */
	evdns_resolve_ipv4(kv_find(&ta->dictionary, "$host"), 0,
	    proxy_handle_connect_cb, ta);
	ta->dns_pending = 1;
	return (0);
}

char *
proxy_pcre_group(char *line, int groupnr, int ovector[])
{
	int start = ovector[2*groupnr];
	int end = ovector[2*groupnr + 1];
	char *group = malloc(end - start + 1);
	if (group == NULL)
	{
		syslog(LOG_ERR, "%s: gettimeofday", __func__);
		exit(EXIT_FAILURE);
	}
		//err(1, "%s: malloc", __func__);
	memcpy(group, line + start, end - start);
	group[end-start] = '\0';

	return (group);
}

int
proxy_handle(struct proxy_ta *ta, char *line)
{
	int rc;
	int ovector[30];

	/* Execute regular expressions to match the command */

	rc = pcre_exec(re_connect, NULL, line, strlen(line), 0, 0,
	    ovector, 30);
	if (rc >= 0) {
		char *host = proxy_pcre_group(line, 1, ovector);
		kv_replace(&ta->dictionary, "$rawhost", host);
		free(host);

		ta->empty_cb = proxy_handle_connect;
		return (0);
	}

	rc = pcre_exec(re_get, NULL, line, strlen(line), 0, 0, ovector, 30);
	if (rc >= 0) {
		char *host = proxy_pcre_group(line, 1, ovector);
		char *uri = proxy_pcre_group(line, 2, ovector);
		kv_replace(&ta->dictionary, "$rawhost", host);
		kv_replace(&ta->dictionary, "$rawuri", uri);
		free(host);
		free(uri);

		ta->empty_cb = proxy_handle_get;
		return (0);
	}

	return proxy_bad_connection(ta);
}

char *
proxy_readline(struct bufferevent *bev)
{
	struct evbuffer *buffer = EVBUFFER_INPUT(bev);
	char *data = EVBUFFER_DATA(buffer);
	size_t len = evbuffer_get_length(buffer);
	char *line;
	int i;

	for (i = 0; i < len; i++) {
		if (data[i] == '\r' || data[i] == '\n')
			break;
	}
	
	if (i == len)
		return (NULL);

	if ((line = malloc(i + 1)) == NULL) {
		fprintf(stderr, "%s: out of memory\n", __func__);
		evbuffer_drain(buffer, i);
		return (NULL);
	}

	memcpy(line, data, i);
	line[i] = '\0';

	if ( i < len - 1 ) {
		char fch = data[i], sch = data[i+1];

		/* Drain one more character if needed */
		if ( (sch == '\r' || sch == '\n') && sch != fch )
			i += 1;
	}

	evbuffer_drain(buffer, i + 1);

	return (line);
}

void
proxy_readcb(struct bufferevent *bev, void *arg)
{
	struct proxy_ta *ta = arg;
	char *line;

	if (ta->justforward) {
		struct evbuffer *input = EVBUFFER_INPUT(bev);
		char *data = EVBUFFER_DATA(input);
		size_t len = evbuffer_get_length(input);
		if (ta->corrupt) {
			bufferevent_write(ta->remote_bev,
			    proxy_corrupt(data, len), len);
		} else {
			bufferevent_write(ta->remote_bev, data, len);
		}
		evbuffer_drain(input, len);
		return;
	}

	while ((line = proxy_readline(bev)) != NULL) {
		int res = 0;
		/* If we are ready to close on the bugger, just eat it */
		if (ta->wantclose) {
			free(line);
			continue;
		}
		if (ta->empty_cb) {
			/* eat the input until we get a return */
			if (strlen(line)) {
				kv_add(&ta->dictionary, "data", line);
				free(line);
				continue;
			} else {
				res = (*ta->empty_cb)(ta);
				ta->empty_cb = NULL;
			}
		} else {
			res = proxy_handle(ta, line);
		}
		free(line);

		/* Destroy the state machine on error */
		if (res == -1) {
			proxy_ta_free(ta);
			return;
		}
	}
}

void
proxy_writecb(struct bufferevent *bev, void *arg)
{
	struct proxy_ta *ta = arg;
	
	if (ta->wantclose)
		proxy_ta_free(ta);
}

void
proxy_errorcb(struct bufferevent *bev, short what, void *arg)
{
	fprintf(stderr, "%s: called with %p, freeing\n", __func__, arg);

	proxy_ta_free(arg);
}

/* Tear down a connection */
void
proxy_ta_free(struct proxy_ta *ta)
{
	struct keyvalue *entry;

	if (ta->dns_pending && !ta->dns_canceled) {
		/* if we have a pending dns lookup, tell it to cancel */
		ta->dns_canceled = 1;
		return;
	}

	while ((entry = TAILQ_FIRST(&ta->dictionary)) != NULL) {
		TAILQ_REMOVE(&ta->dictionary, entry, next);
		free(entry->key);
		free(entry->value);
		free(entry);
	}

	bufferevent_free(ta->bev);
	close(ta->fd);

	if (ta->remote_bev) {
		bufferevent_free(ta->remote_bev);
		close(ta->remote_fd);
	}

	free(ta);
	
}

/* Create a new PROXY transaction */

struct proxy_ta *
proxy_ta_new(int fd, struct sockaddr *sa, socklen_t salen,
    struct sockaddr *lsa, socklen_t lsalen)
{
	struct proxy_ta *ta = calloc(1, sizeof(struct proxy_ta));
	char *srcipname, *srcportname;
	char *dstipname, *dstportname;

	if (ta == NULL)
		goto error;

	ta->proxy_id = "junkbuster";

	TAILQ_INIT(&ta->dictionary);

	memcpy(&ta->sa, sa, salen);
	ta->salen = salen;

	ta->fd = fd;
	ta->bev = bufferevent_new(fd,
	    proxy_readcb, proxy_writecb, proxy_errorcb, ta);
	if (ta->bev == NULL)
		goto error;

	/* Create our tiny dictionary */
	if (lsa != NULL) {
		name_from_addr(lsa, lsalen, &dstipname, &dstportname);
		kv_add(&ta->dictionary, "$dstipaddress", dstipname);
	}

	name_from_addr(sa, salen, &srcipname, &srcportname);
	kv_add(&ta->dictionary, "$srcipaddress", srcipname);

	bufferevent_enable(ta->bev, EV_READ);

	fprintf(stderr, "%s: new proxy instance to %s complete.\n",
	    __func__, srcipname);

	return (ta);

 error:
	if (ta != NULL)
		free(ta);
	fprintf(stderr, "%s: out of memory\n", __func__);
	close(fd);

	return (NULL);
}

static void
accept_socket(int fd, short what, void *arg)
{
	struct sockaddr_storage ss, lss;
	socklen_t addrlen = sizeof(ss), laddrlen = sizeof(lss);
	int nfd, res;

	if ((nfd = accept(fd, (struct sockaddr *)&ss, &addrlen)) == -1) {
		fprintf(stderr, "%s: bad accept\n", __func__);
		return;
	}

	/* Test our special subsystem magic */
	res = fcntl(fd, F_XXX_GETSOCK, &lss, &laddrlen);

	if (res != -1) {
		/*
		 * We are running under honeyd and could figure out
		 * who we are.  That's great.
		 */
		proxy_ta_new(nfd, (struct sockaddr *)&ss, addrlen,
		    (struct sockaddr *)&lss, laddrlen);
	} else {
		proxy_ta_new(nfd, (struct sockaddr *)&ss, addrlen,
		    NULL, 0);
	}
}

void
proxy_bind_socket(struct event *ev, u_short port)
{
	int fd;

	if ((fd = make_socket(bind, SOCK_STREAM, "0.0.0.0", port)) == -1)
	{
		syslog(LOG_ERR, "%s: cannot bind socket: %d", __func__, port);
		exit(EXIT_FAILURE);
	}
		//err(1, "%s: cannot bind socket: %d", __func__, port);

	if (listen(fd, 10) == -1)
	{
		syslog(LOG_ERR, "%s: listen failed: %d", __func__, port);
		exit(EXIT_FAILURE);
	}
		//err(1, "%s: listen failed: %d", __func__, port);

	/* Schedule the socket for accepting */
	event_set(ev, fd, EV_READ | EV_PERSIST, accept_socket, NULL);
	event_add(ev, NULL);

	fprintf(stderr, 
	    "Bound to port %d\n"
	    "Awaiting connections ... \n",
	    port);
}

void
proxy_init(void)
{
	const char *error;
	int erroroffset;
	const char *exp_connect = "^connect\\s+(.*)\\s+http";
	const char *exp_hostport = "^(.*):([0-9]+)$";
	const char *exp_get = "^GET\\s+http://([^/ ]*)(/?[^ ]*)\\s+HTTP";

	/* Compile regular expressions for command parsing */
	re_connect = pcre_compile(exp_connect, PCRE_CASELESS,
	    &error, &erroroffset, NULL);
	if (re_connect == NULL)
	{
		syslog(LOG_ERR, "%s: %s at %d", __func__, error, erroroffset);
		exit(EXIT_FAILURE);
	}
		//err(1, "%s: %s at %d", __func__, error, erroroffset);

	re_hostport = pcre_compile(exp_hostport, PCRE_CASELESS,
	    &error, &erroroffset, NULL);
	if (re_connect == NULL)
	{
		syslog(LOG_ERR, "%s: %s at %d", __func__, error, erroroffset);
		exit(EXIT_FAILURE);
	}
		//err(1, "%s: %s at %d", __func__, error, erroroffset);

	re_get = pcre_compile(exp_get, PCRE_CASELESS,
	    &error, &erroroffset, NULL);
	if (re_connect == NULL)
	{
		syslog(LOG_ERR, "%s: %s at %d", __func__, error, erroroffset);
		exit(EXIT_FAILURE);
	}
		//err(1, "%s: %s at %d", __func__, error, erroroffset);
}
