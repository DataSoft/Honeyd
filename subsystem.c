/*
 * Copyright (c) 2003, 2004 Niels Provos <provos@citi.umich.edu>
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

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#include <sys/tree.h>
#include <sys/queue.h>

#include <unistd.h>
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <dnet.h>
#include <assert.h>

#undef timeout_pending
#undef timeout_initialized

#include <event.h>

#include "honeyd.h"
#include "template.h"
#include "subsystem.h"
#include "util.h"
#include "fdpass.h"

ssize_t atomicio(ssize_t (*)(), int, void *, size_t);


int
templ_container_compare(struct template_container *a,
    struct template_container *b)
{
	return (strcmp(a->tmpl->name, b->tmpl->name));
}

/* Store referencing templates in tree */
SPLAY_GENERATE(subtmpltree, template_container, node, templ_container_compare);

void subsystem_read(int, short, void *);
void subsystem_write(int, short, void *);

struct callback subsystem_cb = {
	subsystem_read, subsystem_write, NULL, NULL
};

/* Determine if the socket information is valid */

#define SOCKET_REMOTE		0
#define SOCKET_LOCAL		1
#define SOCKET_MAYBELOCAL	2

int
subsystem_socket(struct subsystem_command *cmd, int local,
    char *ip, size_t iplen, u_short *port, int *proto)
{
	struct sockaddr_in *si;
	struct addr src;
	socklen_t len;

	si = (struct sockaddr_in *)(local ? &cmd->sockaddr : &cmd->rsockaddr);
	len = local ? cmd->len : cmd->rlen;

	/* Only IPv4 TCP or UDP is allowed.  No raw sockets or such */
	if (si->sin_family != AF_INET || cmd->domain != AF_INET ||
	    !(cmd->type == SOCK_DGRAM || cmd->type == SOCK_STREAM) ||
	    len != sizeof(struct sockaddr_in)) {
		if (local == SOCKET_LOCAL)
			return (-1);
		memset(&cmd->sockaddr, 0, sizeof(cmd->sockaddr));
	}

	addr_pack(&src, ADDR_TYPE_IP, IP_ADDR_BITS, &si->sin_addr.s_addr,
	    IP_ADDR_LEN);
	addr_ntop(&src, ip, iplen);

	*port = ntohs(si->sin_port);
	*proto = cmd->type == SOCK_DGRAM ? IP_PROTO_UDP : IP_PROTO_TCP;

	return (0);
}

struct template *
subsystem_template_find(struct subsystem *sub, char *name)
{
	struct template tmp;
	struct template_container cont, *find;

	tmp.name = name;
	cont.tmpl = &tmp;

	find = SPLAY_FIND(subtmpltree, &sub->root, &cont);
	
	return (find != NULL ? find->tmpl : NULL);
}

void
subsystem_insert_template(struct subsystem *sub, struct template *tmpl)
{
	struct template_container *cont;
	struct addr addr;
	int isipaddr = addr_aton(tmpl->name, &addr) != -1;

	if ((cont = calloc(1, sizeof(struct template_container))) == NULL)
	{
		syslog(LOG_ERR, "%s: calloc",__func__);
		exit(EXIT_FAILURE);
	}
	cont->tmpl = template_ref(tmpl);

	TAILQ_INSERT_TAIL(&sub->templates, cont, next);
	if (isipaddr)
		SPLAY_INSERT(subtmpltree, &sub->root, cont);
}

void
subsystem_restart(int fd, short what, void *arg)
{
	struct subsystem *sub = arg;
	struct template_container *cont = TAILQ_FIRST(&sub->templates);
	struct template *tmpl = cont->tmpl;
	template_subsystem_free_ports(sub);
	cmd_free(&sub->cmd);
	syslog(LOG_INFO, "Restarting subsystem \"%s\"", sub->cmdstring);
	template_subsystem_start(tmpl, sub);
}

void
subsystem_cleanup(struct subsystem *sub)
{
	syslog(LOG_INFO, "Subsystem \"%s\" died", sub->cmdstring);

	if (sub->flags & SUBSYSTEM_RESTART) {
		struct timeval tmp;
		gettimeofday(&tmp, NULL);
		timersub(&tmp, &sub->tv_restart, &tmp);

		/*
		 * Restart the subsystem immediately if we did not restart
		 * it recently.  Otherwise, delay the restart.
		 */
		if (tmp.tv_sec >= SUBSYSTEM_RESTART_INTERVAL) {
			subsystem_restart(-1, EV_TIMEOUT, sub);
		} else {
			struct timeval tv;
			
			timerclear(&tv);
			tv.tv_sec = 2 * SUBSYSTEM_RESTART_INTERVAL;
			event_base_once(libevent_base, -1, EV_TIMEOUT, subsystem_restart, sub, &tv);
		}
		return;
	}

	/* XXX - do proper cleanup here */
	template_subsystem_free(sub);
}

void
subsystem_readyport(struct port *port, struct subsystem *sub,
    struct template *tmpl)
{
	assert(port->sub == NULL);
	assert(port->subtmpl == NULL);
	port->sub = sub;
	port->subtmpl = tmpl;
	port->sub_fd = -1;

	TAILQ_INSERT_TAIL(&sub->ports, port, next);
}

/*
 * Tries to find an unallocated port in all of the templates that
 * are being shared or just in the single template if no sharing
 * is going on.
 */

int
subsystem_findport(struct subsystem *sub, char *name, int proto)
{
	struct template_container *cont;
	struct template *tmpl;
	struct port *sub_port = NULL;
	u_short port;
	int done = 0;

	while (!done) {
		struct action action;
		memset(&action, 0, sizeof(action));
		action.status = PORT_RESERVED;

		/* 
		 * Try to find the right template or default to the root,
		 * if we need to deal with multiple templates at the same
		 * time.
		 */
		cont = SPLAY_ROOT(&sub->root);
		tmpl = cont->tmpl;
		if (!strcmp(name, "0.0.0.0")) {
			tmpl = subsystem_template_find(sub, name);
			if (tmpl == NULL) {
				cont = SPLAY_ROOT(&sub->root);
				tmpl = cont->tmpl;
			}
		}

		sub_port = port_random(tmpl, proto, &action, 1024, 49151);
		if (sub_port == NULL)
			return (0);

		port = sub_port->number;
		port_free(tmpl, sub_port);

		/* Fast path for single template */
		if (!strcmp(name, "0.0.0.0")) {
			break;
		}

		/* Assume that we succeed */
		done = 1;

		/* Now test this port number for all templates */
		SPLAY_FOREACH(cont, subtmpltree, &sub->root) {
			tmpl = cont->tmpl;
			sub_port = port_insert(tmpl, proto, port, &action);
			if (sub_port == NULL) {
				/* This port is in use already */
				done = 0;
				break;
			}

			/* Free the port and continue with the next template */
			port_free(tmpl, sub_port);
		}
	}

	syslog(LOG_DEBUG, "Subsytem \"%s\" binds %s to port %d",
	    sub->cmdstring, name, port);

	return (port);
}

int
subsystem_bind(int fd, struct template *tmpl, struct subsystem *sub,
    int proto, u_short port)
{
	struct port *sub_port;
	struct action action;

	/* Setup port type */
	memset(&action, 0, sizeof(action));
	action.status = PORT_RESERVED;

	sub_port = port_insert(tmpl, proto, port, &action);
	if (sub_port == NULL)
		return (-1);

	/* Set up necessary port information */
	subsystem_readyport(sub_port, sub, tmpl);

	syslog(LOG_DEBUG, "Subsytem \"%s\" binds %s:%d",
	    sub->cmdstring, tmpl->name, port);

	return (0);
}

int
subsystem_listen(struct port *sub_port, char *ip, int nfd)
{
	syslog(LOG_DEBUG, "Listen: %s:%d -> fd %d", 
	    ip, sub_port->number, nfd);

	/* We use this fd to notify the other side */
	TRACE(nfd, sub_port->sub_fd = fdshare_dup(nfd));
	if (sub_port->sub_fd == -1)
		return (-1);
	sub_port->sub_islisten = 1;
			
	/* Enable this port */
	sub_port->action.status = PORT_SUBSYSTEM;

	return (0);
}

int
subsystem_cmd_listen(int fd,
    struct subsystem *sub, struct subsystem_command *cmd)
{
	struct template_container *cont;
	struct template *tmpl;
	struct port *sub_port = NULL;
	char asrc[24];
	u_short port;
	int proto;
	int nfd;
	int res = -1;

	/* Check address family */
	if (subsystem_socket(cmd, SOCKET_LOCAL, asrc, sizeof(asrc),
		&port, &proto) == -1) {
		syslog(LOG_WARNING, "%s: listen bad socket", __func__);
		return (-1);
	}

	if (strcmp(asrc, "0.0.0.0") != 0) {
		tmpl = subsystem_template_find(sub, asrc);
	} else {
		cont = SPLAY_ROOT(&sub->root);
		tmpl = cont->tmpl;
	}
	if (tmpl != NULL)
		sub_port = port_find(tmpl, proto, port);
	if (sub_port == NULL) {
		syslog(LOG_WARNING, "%s: proto %d port %d not bound",
		    __func__, proto, port);
		return (-1);
	}

	res = 0;
	TRACE(fd, atomicio(write, fd, &res, 1));
	res = -1;

	/* Repeat until we get a result */
	while ((nfd = receive_fd(fd, NULL, NULL)) == -1) {
		if (errno != EAGAIN)
			break;
	}

	if (nfd == -1) {
		syslog(LOG_WARNING, "%s: no file descriptor",__func__);
		return (-1);
	}

	TRACE(nfd, res = fdshare_dup(nfd));
	if (res == -1) {
		syslog(LOG_WARNING, "%s: out of memory", __func__);
		TRACE_RESET(nfd, close(nfd));
		return (-1);
	}

	if (strcmp(asrc, "0.0.0.0") != 0) {
		TRACE(nfd, subsystem_listen(sub_port, asrc, nfd));
	} else {
		/* 
		 * Subsystem sharing means that we need to
		 * listen to all templates
		 */
		int success = 0;
		SPLAY_FOREACH(cont, subtmpltree, &sub->root) {
			tmpl = cont->tmpl;
			sub_port = port_find(tmpl, proto, port);
			if (sub_port == NULL)
			{
				syslog(LOG_ERR, "%s: no proto %d port %d", __func__, proto, port);
				exit(EXIT_FAILURE);
			}
			if (sub_port->sub == NULL) {
				syslog(LOG_DEBUG,
				    "Subsystem %s fails to listen on %s:%d",
				    sub->cmdstring, tmpl->name, port);
			} else {
				int ok;
				TRACE(nfd, ok = subsystem_listen(sub_port,
					  asrc, nfd));
				if (ok != -1)
					success = 1;
			}
		}
		if (!success)
			res = -1;
	}

	/* Close this file descriptor */
	TRACE(nfd, fdshare_close(nfd));
		
	return (res);
}

void
subsystem_read(int fd, short what, void *arg)
{
	struct subsystem *sub = arg;
	struct subsystem_command cmd;
	struct sockaddr_in *si = (struct sockaddr_in *)&cmd.sockaddr;
	char asrc[24], adst[24];
	u_short port, local_port;
	int proto, n;
	char res = -1;

	TRACE(fd, n = atomicio(read, fd, &cmd, sizeof(cmd)));
	if (n != sizeof(cmd)) {
		subsystem_cleanup(sub);
		return;
	}

	switch (cmd.command) {
	case SUB_BIND: {
		struct template_container *cont;
		struct template *tmpl;
	
		/* Check address family */
		if (subsystem_socket(&cmd, SOCKET_LOCAL, asrc, sizeof(asrc),
			&port, &proto) == -1)
			goto out;

		if (port == 0) {
			/* Try to find a port that is free everywhere */
			port = subsystem_findport(sub, asrc, proto);
			if (port == 0)
				goto out;
		}

		/* See if it tries to bind an address that we know */
		if (si->sin_addr.s_addr == IP_ADDR_ANY) {
			int ret;
			res = -1;
			/* Bind to all associated templates */
			SPLAY_FOREACH(cont, subtmpltree, &sub->root) {
				tmpl = cont->tmpl;
				TRACE(fd, ret = subsystem_bind(fd, tmpl,
					  sub,proto,port));
				/* One success is good enough for us */
				if (ret != -1) {
					res = 0;
				} else {
					syslog(LOG_DEBUG,
					    "Subsystem %s fails to bind to "
					    "port %d on %s",
					    sub->cmdstring, port, tmpl->name);
				}
			}
		} else {
			/* See if we can find a good template */
			tmpl = subsystem_template_find(sub, asrc);
			if (tmpl == NULL) {
				cont = SPLAY_ROOT(&sub->root);
				tmpl = cont->tmpl;
				syslog(LOG_WARNING,
				    "Subsystem %s on %s attempts "
				    "illegal bind %s:%d",
				    sub->cmdstring, tmpl->name, asrc, port);
				goto out;
			}

			TRACE(fd,
			    res = subsystem_bind(fd, tmpl, sub, proto, port));
		}

		/* Confirm success or failure of this phase */
		TRACE(fd, atomicio(write, fd, &res, 1));
			
		/* On success, we also communicate the port back */
		if (res != -1) {
			TRACE(fd, atomicio(write, fd, &port, sizeof(port)));
		}
		goto reschedule;
	}

	case SUB_LISTEN:
		TRACE(fd, res = subsystem_cmd_listen(fd, sub, &cmd));
		break;

	case SUB_CLOSE: {
		struct template_container *cont;
		struct template *tmpl = NULL;
		struct port *sub_port;

		/* Check address family */
		if (subsystem_socket(&cmd, SOCKET_LOCAL, asrc, sizeof(asrc),
			&port, &proto) == -1)
			goto out;

		syslog(LOG_DEBUG, "Close: %s:%d", asrc, port);
		if (strcmp(asrc, "0.0.0.0") != 0) {
			tmpl = subsystem_template_find(sub, asrc);
			if (tmpl == NULL)
				goto out;
			sub_port = port_find(tmpl, proto, port);
			if (sub_port == NULL || sub_port->sub != sub)
				goto out;
			
			port_free(tmpl, sub_port);
		} else {
			SPLAY_FOREACH(cont, subtmpltree, &sub->root) {
				tmpl = cont->tmpl;
				/* XXX - only bound port */
				sub_port = port_find(tmpl, proto, port);
				if (sub_port == NULL || sub_port->sub != sub)
					continue;
				
				port_free(tmpl, sub_port);
			}
		}
		break;
	}

	case SUB_CONNECT: {
		struct template_container *cont;
		struct template *tmpl;
		struct port *sub_port;
		struct action action;
		struct addr src, dst;
		struct ip_hdr ip;

		/* Check remote address family */
		if (subsystem_socket(&cmd, SOCKET_MAYBELOCAL,
			asrc, sizeof(asrc), &local_port, &proto) == -1)
			goto out;
		if (subsystem_socket(&cmd, SOCKET_REMOTE, adst, sizeof(adst),
			&port, &proto) == -1)
			goto out;
		
		/* Find appropriate template */
		if (strcmp(asrc, "0.0.0.0") != 0) {
			tmpl = subsystem_template_find(sub, asrc);
			if (tmpl == NULL)
			{
				syslog(LOG_ERR, "%s: source address %s not found", __func__, asrc);
				exit(EXIT_FAILURE);
			}
		} else {
			cont = SPLAY_ROOT(&sub->root);
			tmpl = cont->tmpl;
		}

		syslog(LOG_DEBUG, "Connect: %s %s:%d -> %s:%d",
		    proto == IP_PROTO_UDP ? "udp" : "tcp",
		    tmpl->name, local_port, adst, port);

		if (addr_aton(tmpl->name, &src) == -1)
			goto out;
		if (addr_aton(adst, &dst) == -1)
			goto out;

		memset(&action, 0, sizeof(action));
		action.status = PORT_RESERVED;

		if (local_port == 0) {
			sub_port = port_random(tmpl, proto, &action,
			    1024, 49151);
			if (sub_port != NULL)
				subsystem_readyport(sub_port, sub, tmpl);
		} else {
			/*
			 * If the port is bound already, then we need to use
			 * that port number.
			 */
			sub_port = port_find(tmpl, proto, local_port);
		}
		if (sub_port == NULL)
			goto out;
		
		/* Verify that we have the correct binding */
		assert(sub_port->sub == sub);

		syslog(LOG_DEBUG, "Connect: allocated port %d",
		    sub_port->number);

		/* The remote side is the source */
		ip.ip_src = dst.addr_ip;
		ip.ip_dst = src.addr_ip;

		/* Try to setup a TCP connection */
		if (proto == IP_PROTO_TCP) {
			struct tcp_con *con;
			struct tcp_hdr tcp;
			int nfd;

			tcp.th_sport = htons(port);
			tcp.th_dport = htons(sub_port->number);

			if ((con = tcp_new(NULL, &ip, &tcp, INITIATED_BY_SUBSYSTEM)) == NULL)
				goto out;
			con->tmpl = template_ref(tmpl);

			/* Cross notify */
			con->port = sub_port;
			sub_port->sub_conport = &con->port;

			/* Confirm success of this phase */
			res = 0;
			TRACE(fd, atomicio(write, fd, &res, 1));
			
			/* Now get the control fd */
			while ((nfd = receive_fd(fd, NULL, NULL)) == -1) {
				if (errno != EAGAIN) {
					tcp_free(con);
					goto out;
				}
			}
			TRACE(nfd, sub_port->sub_fd = fdshare_dup(nfd));

			/* Confirm success again */
			res = 0;
			TRACE(nfd, atomicio(write, nfd, &res, 1));
			
			/* Send out the SYN packet */
			con->state = TCP_STATE_SYN_SENT;
			tcp_send(con, TH_SYN, NULL, 0);
			con->snd_una++;

			con->retrans_time = 1;
			generic_timeout(con->retrans_timeout, con->retrans_time);
			goto reschedule;
		} else if (proto == IP_PROTO_UDP) {
			struct udp_con *con;
			struct udp_hdr udp;
			int nfd;

			/* The remote side is the source */
			udp.uh_sport = htons(port);
			udp.uh_dport = htons(sub_port->number);

			if ((con = udp_new(&ip, &udp, INITIATED_BY_SUBSYSTEM)) == NULL)
				goto out;
			con->tmpl = template_ref(tmpl);
			
			/* Cross notify */
			con->port = sub_port;
			sub_port->sub_conport = &con->port;

			/* Confirm success of this phase */
			res = 0;
			TRACE(fd, atomicio(write, fd, &res, 1));

			/* Now get the control fd */
			while ((nfd = receive_fd(fd, NULL, NULL)) == -1) {
				if (errno != EAGAIN) {
					udp_free(con);
					goto out;
				}
			}
			TRACE(nfd, sub_port->sub_fd = fdshare_dup(nfd));

			/* Confirm success again */
			res = 0;
			TRACE(nfd, atomicio(write, nfd, &res, 1));
                       
			/* Connect our system to the subsystem */
			cmd_subsystem_localconnect(&con->conhdr, &con->cmd,
			    sub_port, con);
			goto reschedule;
		}
	}
	default:
		break;
	}

 out:
	TRACE(fd, atomicio(write, fd, &res, 1));
 reschedule:
	/* Reschedule read */
	TRACE(event_get_fd(sub->cmd.pread), event_add(sub->cmd.pread, NULL));
}

void
subsystem_write(int fd, short what, void *arg)
{
	/* Nothing */
}

void
subsystem_print(struct evbuffer *buffer, struct subsystem *sub)
{
	time_t restart_secs = sub->tv_restart.tv_sec;

	evbuffer_add_printf(buffer, "subsystem %s:\n", sub->cmdstring);
	evbuffer_add_printf(buffer, "  pid: %d %s%s\n",
	    sub->cmd.pid,
	    sub->flags & SUBSYSTEM_SHARED ? "shared " : "",
	    sub->flags & SUBSYSTEM_RESTART ? "restart " : "");
	evbuffer_add_printf(buffer, "  running since: %s",
	    ctime(&restart_secs));
	    
}
