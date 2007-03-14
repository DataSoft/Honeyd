/*
 * Copyright (c) 2002, 2003, 2004 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 *
 * <LICENSEHERE>
 */

#include <sys/types.h>
#include <sys/param.h>

#include "config.h"

#include <sys/stat.h>
#include <sys/tree.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/resource.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dnet.h>

#undef timeout_pending
#undef timeout_initialized

#include <event.h>

#include "honeyd.h"
#include "tcp.h"
#include "log.h"
#include "hooks.h"
#include "util.h"

struct callback cb_tcp = {
	cmd_tcp_read, cmd_tcp_write, cmd_tcp_eread, cmd_tcp_connect_cb
};

void
tcp_increase_buf(u_char **pbuf, u_int *psize, u_int maxsize)
{
	u_int size = *psize;
	u_char *p;

	if (size >= maxsize)
		return;
	size *= 2;
	if (size >= maxsize)
		size = maxsize;

	p = realloc(*pbuf, size);
	if (p == NULL)
		return;

	*psize = size;
	*pbuf = p;
}

void
tcp_drain_payload(struct tcp_con *con, u_int len)
{
	if (len == 0 || con->payload == NULL)
		return;

	if (len >= con->plen) {
		con->plen = 0;
		con->poff = 0;
		goto out;
	}

	memmove(con->payload, con->payload + len, con->plen - len);
	con->plen -= len;
	con->poff -= len;
 out:
	cmd_trigger_read(&con->cmd, con->psize - con->plen);
}

int
tcp_add_readbuf(struct tcp_con *con, u_char *dat, u_int datlen)
{
	int space;

	hooks_dispatch(IP_PROTO_TCP, HD_INCOMING_STREAM, &con->conhdr,
	    dat, datlen);

	if (con->cmd_pfd == -1)
		return (datlen);

	space = con->rsize - con->rlen;
	if (space < datlen) {
		tcp_increase_buf(&con->readbuf, &con->rsize, TCP_MAX_SIZE);
		space = con->rsize - con->rlen;
		if (space < datlen)
			datlen = space;
	}

	memcpy(con->readbuf + con->rlen, dat, datlen);
	con->rlen += datlen;

	cmd_trigger_write(&con->cmd, con->rlen);

	return (datlen);
}

void
cmd_tcp_eread(int fd, short which, void *arg)
{
	extern FILE *honeyd_servicefp;
	struct tcp_con *con = arg;
	char line[1024];
	int nread;
	struct command *cmd = &con->cmd;

	TRACE(fd, nread = read(fd, line, sizeof(line)));

	if (nread <= 0) {
		if (cmd->fdwantclose) {
			/* Stdin is already closed */
			cmd_free(&con->cmd);
			
			tcp_sendfin(con);
		} else {
			/* Now stdin will takes us down */
			cmd->fdwantclose = 1;
		}
		return;
	}

	if (nread == sizeof(line))
		nread--;
	line[nread] = '\0';
	
	honeyd_log_service(honeyd_servicefp, IP_PROTO_TCP, &con->conhdr, line);

	TRACE(cmd->peread.ev_fd, event_add(&cmd->peread, NULL));
}

void
cmd_tcp_read(int fd, short which, void *arg)
{
	struct tcp_con *con = arg;
	int len, space;
	struct command *cmd = &con->cmd;
	
	space = con->psize - con->plen;
	if (space <= 0)
		return;

	TRACE(fd, len = read(fd, con->payload + con->plen, space));
	if (len == -1) {
		if (errno == EINTR || errno == EAGAIN)
			goto again;
		cmd_free(&con->cmd);
		tcp_sendfin(con);
		return;
	} else if (len == 0) {
		if (cmd->perrfd != -1 && !cmd->fdwantclose) {
			cmd->fdwantclose = 1;
			return;
		}
		cmd_free(&con->cmd);

		tcp_sendfin(con);
		return;
	}

	con->plen += len;
	if (con->plen == con->psize)
		tcp_increase_buf(&con->payload, &con->psize, TCP_MAX_SIZE);

	/* XXX - Trigger write */
	tcp_senddata(con, TH_ACK);

 again:
	cmd_trigger_read(&con->cmd, con->psize - con->plen);
}

void
cmd_tcp_write(int fd, short which, void *arg)
{
	struct tcp_con *con = arg;
	int len;
	
	TRACE(fd, len = write(fd, con->readbuf, con->rlen));
	
	if (len == -1) {
		if (errno == EINTR || errno == EAGAIN)
			goto again;
		cmd_free(&con->cmd);
		return;
	} else if (len == 0) {
		cmd_free(&con->cmd);
		return;
	}

	memmove(con->readbuf, con->readbuf + len, con->rlen - len);
	con->rlen -= len;

	/* Shut down the connection if we received a FIN and sent all data */
	if (con->rlen == 0 && con->cmd.fdgotfin)
		TRACE(con->cmd_pfd, shutdown(con->cmd_pfd, SHUT_WR));

 again:
	cmd_trigger_write(&con->cmd, con->rlen);
}

void
cmd_tcp_connect_cb(int fd, short which, void *arg)
{
	struct tcp_con *con = arg;
        int error = 0;
        socklen_t errsz = sizeof(error);

	/* Everything is ready */
	cmd_ready_fd(&con->cmd, &cb_tcp, con);

	if (which == EV_TIMEOUT)
		goto out;

        /* Check if the connection completed */
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &errsz) == -1) {
                warn("%s: getsockopt for %d", __FUNCTION__, fd);
                goto out;
        }

        if (error) {
                warnx("%s: getsockopt: %s", __FUNCTION__, strerror(error));
		goto out;
	}

	cmd_trigger_read(&con->cmd, con->psize - con->plen);
	cmd_trigger_write(&con->cmd, con->rlen);
	return;

 out:	
	/* Connection failed, bring this down gracefully */
	cmd_free(&con->cmd);
	tcp_sendfin(con);
}
