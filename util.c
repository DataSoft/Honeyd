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

/*
 * Copyright (c) 1999, 2000 Dug Song <dugsong@monkey.org>
 * All rights reserved, all wrongs reversed.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
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

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <assert.h>
#include <syslog.h>

#include <pcap.h>
#include <dnet.h>
#include <event.h>

#include "honeyd.h"
#include "util.h"

int trace_on;		/* determines if we trace file descriptor calls */

int
pcap_dloff(pcap_t *pd)
{
	int offset = -1;
	
	switch (pcap_datalink(pd)) {
	case DLT_EN10MB:
		offset = 14;
		break;
	case DLT_IEEE802:
		offset = 22;
		break;
	case DLT_FDDI:
		offset = 21;
		break;
#ifdef DLT_PPP
        case DLT_PPP:
                offset = 24;
                break;
#endif
#ifdef DLT_LINUX_SLL
        case DLT_LINUX_SLL:
                offset = 16;
                break;
#endif
#ifdef DLT_LOOP
	case DLT_LOOP:
#endif
	case DLT_NULL:
		offset = 4;
		break;
	default:
		warnx("unsupported datalink type");
		break;
	}
	return (offset);
}

char *
strrpl(char *str, size_t size, char *match, char *value)
{
	char *p, *e;
	int len, rlen;

	p = str;
	e = p + strlen(p);
	len = strlen(match);

	/* Try to match against the variable */
	while ((p = strchr(p, match[0])) != NULL) {
		if (!strncmp(p, match, len) && !isalnum(p[len]))
			break;
		/* This could be optimized but we don't really care */
		p += 1;

		if (p >= e)
			return (NULL);
		    
	}

	if (p == NULL)
		return (NULL);

	rlen = strlen(value);

	if (strlen(str) - len + rlen > size)
		return (NULL);

	memmove(p + rlen, p + len, strlen(p + len) + 1);
	memcpy(p, value, rlen);

	return (p);
}

/*
 * Checks if <addr> is contained in the network specified by <net>
 */

int
addr_contained(struct addr *net, struct addr *addr)
{
	struct addr tmp;

	tmp = *net;
	tmp.addr_bits = IP_ADDR_BITS;
	if (addr_cmp(&tmp, addr) > 0)
		return (0);

	addr_bcast(net, &tmp);
	tmp.addr_bits = IP_ADDR_BITS;
	if (addr_cmp(&tmp, addr) < 0)
		return (0);

	return (1);
}

char *
strnsep(char **line, char *delim)
{
	char *ret, *p;

	if (line == NULL)
		return (NULL);

	ret = *line;
	if (ret == NULL)
		return (NULL);

	p = strpbrk(ret, delim);
	if (p == NULL) {
		*line = NULL;
		return (ret);
	}

	*line = p + strspn(p, delim);
	*p = '\0';

	return (ret);
}

#ifndef HAVE_FGETLN
char *
fgetln(FILE *stream, size_t *len)
{
	static char buf[1024];

	if (fgets(buf, sizeof(buf), stream) == NULL)
		return (NULL);
	
	*len = strlen(buf);

	return (buf);
}
#endif

/* Either connect or bind */

int
make_socket_ai(int (*f)(int, const struct sockaddr *, socklen_t), int type,
    struct addrinfo *ai)
{
        struct linger linger;
        int fd, on = 1;

        /* Create listen socket */
        fd = socket(AF_INET, type, 0);
        if (fd == -1) {
                warn("socket");
                return (-1);
        }

        if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
                warn("fcntl(O_NONBLOCK)");
                goto out;
        }

        if (fcntl(fd, F_SETFD, 1) == -1) {
                warn("fcntl(F_SETFD)");
                goto out;
        }

	if (type == SOCK_STREAM) {
		setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE,
		    (void *)&on, sizeof(on));
		setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
		    (void *) &on, sizeof(on));
#ifdef SO_REUSEPORT
		setsockopt(fd, SOL_SOCKET, SO_REUSEPORT,
		    (void *) &on, sizeof(on));
#endif
		linger.l_onoff = 1;
		linger.l_linger = 5;
		setsockopt(fd, SOL_SOCKET, SO_LINGER, &linger, sizeof(linger));
	}

        if ((f)(fd, ai->ai_addr, ai->ai_addrlen) == -1) {
		if (errno != EINPROGRESS) {
			warn("%s", __func__);
			goto out;
		}
        }

	return (fd);

 out:
	close(fd);
	return (-1);
}

/*
 * Connect to an address:port from a specified local IP address.
 */

int
make_bound_connect(int type, char *address, uint16_t port, char *local_address)
{
        struct addrinfo ai, *aitop, *local_aitop;
        char strport[NI_MAXSERV];
	int fd;
	
        memset(&ai, 0, sizeof (ai));
        ai.ai_family = AF_INET;
        ai.ai_socktype = type;
        snprintf(strport, sizeof (strport), "%d", port);
        if (getaddrinfo(address, strport, &ai, &aitop) != 0) {
                warn("getaddrinfo");
                return (-1);
        }
        
        memset(&ai, 0, sizeof (ai));
        ai.ai_family = AF_INET;
        ai.ai_socktype = type;
        strlcpy(strport, "0", sizeof(strport));
        if (getaddrinfo(local_address, strport, &ai, &local_aitop) != 0) {
                warn("getaddrinfo");
		freeaddrinfo(aitop);
                return (-1);
        }

	fd = make_socket_ai(bind, type, local_aitop);

	if (fd != -1 ) {
		if (connect(fd, aitop->ai_addr, aitop->ai_addrlen) == -1) {
			if (errno != EINPROGRESS) {
				warn("%s", __func__);
				close(fd);
				fd = -1;
			}
		}
        }

	freeaddrinfo(aitop);
	freeaddrinfo(local_aitop);

	return (fd);
}

int
make_socket(int (*f)(int, const struct sockaddr *, socklen_t), int type,
    char *address, uint16_t port)
{
        struct addrinfo ai, *aitop;
        char strport[NI_MAXSERV];
	int fd;
	
        memset(&ai, 0, sizeof (ai));
        ai.ai_family = AF_INET;
        ai.ai_socktype = type;
        ai.ai_flags = f != connect ? AI_PASSIVE : 0;
        snprintf(strport, sizeof (strport), "%d", port);
        if (getaddrinfo(address, strport, &ai, &aitop) != 0) {
                warn("getaddrinfo");
                return (-1);
        }
        
	fd = make_socket_ai(f, type, aitop);

	freeaddrinfo(aitop);

	return (fd);
}

#define DIFF(a,b) do { \
	if ((a) < (b)) return -1; \
	else if ((a) > (b)) return 1; \
} while (0)

int
conhdr_compare(struct tuple *a, struct tuple *b)
{
	DIFF(a->ip_src, b->ip_src);
	DIFF(a->ip_dst, b->ip_dst);
	DIFF(a->sport, b->sport);
	DIFF(a->dport, b->dport);

	return (0);
}

char *
honeyd_contoa(const struct tuple *hdr)
{
	static char buf[128];
	char asrc[24], adst[24];
	struct addr src, dst;
	u_short sport, dport;
	
	addr_pack(&src, ADDR_TYPE_IP, IP_ADDR_BITS, &hdr->ip_src, IP_ADDR_LEN);
	addr_pack(&dst, ADDR_TYPE_IP, IP_ADDR_BITS, &hdr->ip_dst, IP_ADDR_LEN);

	/* For a local connection switch the address around */
	if (hdr->local) {
		struct addr tmp;

		tmp = src;
		src = dst;
		dst = tmp;

		sport = hdr->dport;
		dport = hdr->sport;
	} else {
		sport = hdr->sport;
		dport = hdr->dport;
	}

	addr_ntop(&src, asrc, sizeof(asrc));
	addr_ntop(&dst, adst, sizeof(adst));

	snprintf(buf, sizeof(buf), "(%s:%d - %s:%d)",
	    asrc, sport, adst, dport);

	return (buf);
}

/* Some stupid keyvalue stuff */

void
kv_add(struct keyvalueq *head, char *key, char *value)
{
	struct keyvalue *entry = malloc(sizeof(struct keyvalue));

	if (entry == NULL)
	{
		syslog(LOG_ERR, "%s: malloc, failed to allocate keyvalue entry", __func__);
		exit(EXIT_FAILURE);
	}
		//err(1, "%s: malloc", __func__);

	entry->key = strdup(key);
	entry->value = strdup(value);

	if (entry->key == NULL || entry->value == NULL)
	{
		syslog(LOG_ERR, "%s: strdup", __func__);
		exit(EXIT_FAILURE);
	}
		//err(1, "%s: strdup", __func__);

	TAILQ_INSERT_TAIL(head, entry, next);
}

char *
kv_find(struct keyvalueq *head, char *key)
{
	struct keyvalue *entry;

	TAILQ_FOREACH(entry, head, next) {
		if (strcmp(key, entry->key) == 0)
			return (entry->value);
	}
	return (NULL);
}

int
kv_remove(struct keyvalueq *head, char *key)
{
	struct keyvalue *entry;

	TAILQ_FOREACH(entry, head, next) {
		if (strcmp(key, entry->key) == 0)
			break;
	}

	if (entry == NULL)
		return (0);

	TAILQ_REMOVE(head, entry, next);
	free(entry->value);
	free(entry->key);
	free(entry);

	return (1);
}

void
kv_replace(struct keyvalueq *head, char *key, char *value)
{
	struct keyvalue *entry;

	TAILQ_FOREACH(entry, head, next) {
		if (strcmp(key, entry->key) == 0)
		    break;
	}

	if (entry == NULL) {
		entry = malloc(sizeof(struct keyvalue));
		if (entry == NULL)
		{
			syslog(LOG_ERR, "%s: malloc, failed to allocate entry", __func__);
			exit(EXIT_FAILURE);
		}
			//err(1, "%s: malloc", __func__);
	} else {
		free(entry->key);
		free(entry->value);
		TAILQ_REMOVE(head, entry, next);
	}

	entry->key = strdup(key);
	entry->value = strdup(value);

	if (entry->key == NULL || entry->value == NULL)
	{
		syslog(LOG_ERR, "%s: strdup", __func__);
		exit(EXIT_FAILURE);
	}
		//err(1, "%s: strdup", __func__);

	TAILQ_INSERT_TAIL(head, entry, next);
}

void
name_from_addr(struct sockaddr *sa, socklen_t salen,
    char **phost, char **pport)
{
	static char ntop[NI_MAXHOST];
	static char strport[NI_MAXSERV];

	if (getnameinfo(sa, salen,
		ntop, sizeof(ntop), strport, sizeof(strport),
		NI_NUMERICHOST|NI_NUMERICSERV) != 0)
	{
		syslog(LOG_ERR, "%s: getnameinfo failed", __func__);
	    exit(EXIT_FAILURE);
	}
		//err(1, "%s: getnameinfo failed", __func__);

	*phost = ntop;
	*pport = strport;
}

/* File descriptor sharing */

static int *fds_refs;
static int fds_refsize;

static int
fdshare_init(int fd)
{
	int n = fds_refsize;
	int *tmp;
	
	if (!n) 
		n = 32;

	while (n <= fd)
		n <<= 1;

	tmp = realloc(fds_refs, n * sizeof(int));
	if (tmp == NULL)
		return (-1);

	/* Initialize everything to a 0 refcount */
	memset(tmp + fds_refsize, 0, (n - fds_refsize) * sizeof(int));

	fds_refs = tmp;
	fds_refsize = n;

	return (0);
}

int
fdshare_dup(int fd)
{
	int res;

	assert(fd >= 0);

	if (fds_refs == NULL || fd >= fds_refsize) {
		res = fdshare_init(fd);
		if (res == -1)
			return (-1);
	}

	++fds_refs[fd];

	return (fd);
}

/* Check if the ref counter is not zero; if it is close the fd */

int
fdshare_close(int fd)
{
	assert(fds_refs != NULL);
	assert(fd >= 0 && fd < fds_refsize);

	if (--fds_refs[fd])
		return (0);

	TRACE_RESET(fd, close(fd));

	return (0);
}

/* Quick tool for debugging */

int
fdshare_inspect(int fd)
{
	if (fds_refs == NULL || fd < 0 || fd >= fds_refsize)
		return (-1);

	return (fds_refs[fd]);
}

/* Tracing facility */

struct trace {
	TAILQ_ENTRY(trace) next;
	char *line;
	int closed;
};

static TAILQ_HEAD(traceq, trace) **trace_refs;
static int trace_refsize;

static int
trace_init(int fd)
{
	int n = trace_refsize, i;
	struct traceq **tmp;
	
	if (!n) 
		n = 32;

	while (n <= fd)
		n <<= 1;

	tmp = (struct traceq **)realloc(trace_refs, n * sizeof(struct traceq));
	if (tmp == NULL)
		return (-1);

	/* Initialize all queues */
	for (i = trace_refsize; i < n; ++i) {
		struct traceq *head = malloc(sizeof(struct traceq *));
		if (head == NULL)
		{
			syslog(LOG_ERR, "%s: malloc", __func__);
			exit(EXIT_FAILURE);
		}
			//err(1, "%s: malloc", __func__);
		TAILQ_INIT(head);
		tmp[i] = head;
	}

	trace_refs = tmp;
	trace_refsize = n;

	return (0);
}

static void
trace_free(int fd)
{
	struct traceq *head = trace_refs[fd];
	struct trace *tmp;

	while ((tmp = TAILQ_FIRST(head)) != NULL) {
		TAILQ_REMOVE(head, tmp, next);
		free(tmp->line);
		free(tmp);
	}
}

int
trace_enter(int fd, char *line, int closed)
{
	struct trace *tmp;
	int res;

	assert(fd >= 0);

	if (trace_refs == NULL || fd >= trace_refsize) {
		res = trace_init(fd);
		if (res == -1)
			goto error;
	}

	if ((tmp = TAILQ_LAST(trace_refs[fd], traceq)) != NULL) {
		if (tmp->closed)
			trace_free(fd);
	}

	if ((tmp = malloc(sizeof(struct trace))) == NULL)
		goto error;

	tmp->line = line;
	tmp->closed = closed;
	TAILQ_INSERT_TAIL(trace_refs[fd], tmp, next);

	return (0);

 error:
	free(line);
	return (-1);
}

#define TRACE_UNKNOWN	"<unknown>\n"

int
trace_inspect(int fd, struct evbuffer *buffer)
{
	struct trace *tmp;
	if (trace_refs == NULL || fd < 0 || fd >= trace_refsize) {
		evbuffer_add(buffer, TRACE_UNKNOWN, strlen(TRACE_UNKNOWN) + 1);
		return (-1);
	}

	TAILQ_FOREACH(tmp, trace_refs[fd], next) {
		evbuffer_add_printf(buffer, "%s\n", tmp->line);
	}
	evbuffer_add(buffer, "\0", 1);
	
	return (0);
}

void
trace_onoff(int on) {
	trace_on = on;
	if (!on) {
		int i;
		for (i = 0; i < trace_refsize; ++i)
			trace_free(i);
	}
}
