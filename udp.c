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
#include "udp.h"
#include "log.h"
#include "hooks.h"
#include "util.h"

struct callback cb_udp = {
	cmd_udp_read, cmd_udp_write, cmd_udp_eread, cmd_udp_connect_cb
};

void
cmd_udp_eread(int fd, short which, void *arg)
{
	extern FILE *honeyd_servicefp;
	struct udp_con *con = arg;
	char line[1024];
	int nread;
	struct command *cmd = &con->cmd;

	TRACE(fd, nread = read(fd, line, sizeof(line)));

	if (nread <= 0) {
		udp_free(con);
		return;
	}

	if (nread == sizeof(line))
		nread--;
	line[nread] = '\0';
	
	honeyd_log_service(honeyd_servicefp, IP_PROTO_UDP, &con->conhdr, line);

	event_add(cmd->peread, NULL);
}

void
udp_add_readbuf(struct udp_con *con, u_char *dat, u_int datlen)
{
	struct conbuffer *buf;

	hooks_dispatch(IP_PROTO_UDP, HD_INCOMING_STREAM, &con->conhdr,
	    dat, datlen);

	if (con->cmd_pfd == -1)
		return;

	if (con->nincoming >= MAX_UDP_BUFFERS)
		return;

	buf = malloc(sizeof(struct conbuffer));
	if (buf == NULL)
		return;
	buf->buf = malloc(datlen);
	if (buf->buf == NULL) {
		free(buf);
		return;
	}

	memcpy(buf->buf, dat, datlen);
	buf->len = datlen;

	TAILQ_INSERT_TAIL(&con->incoming, buf, next);
	con->nincoming++;

	cmd_trigger_write(&con->cmd, 1);
}

void
cmd_udp_read(int fd, short which, void *arg)
{
	struct udp_con *con = arg;
	u_char buf[2048];
	ssize_t len;

	TRACE(fd, len = read(fd, buf, sizeof(buf)));
	if (len == -1) {
		if (errno == EINTR || errno == EAGAIN)
			goto again;
	}
	if (len <= 0) {
		udp_free(con);
		return;
	}

	udp_send(con, buf, len);

 again:
	cmd_trigger_read(&con->cmd, 1);
}

void
cmd_udp_write(int fd, short which, void *arg)
{
	struct udp_con *con = arg;
	struct conbuffer *buf;
	ssize_t len;
	
	buf = TAILQ_FIRST(&con->incoming);
	if (buf == NULL)
		return;
	TRACE(fd, len = write(fd, buf->buf, buf->len));
	if (len == -1) {
		if (errno == EINTR || errno == EAGAIN)
			goto again;
		cmd_free(&con->cmd);
		return;
	} else if (len == 0) {
		cmd_free(&con->cmd);
		return;
	}

	TAILQ_REMOVE(&con->incoming, buf, next);
	con->nincoming--;

	free(buf->buf);
	free(buf);

 again:
	cmd_trigger_write(&con->cmd, TAILQ_FIRST(&con->incoming) != NULL);
}

void
cmd_udp_connect_cb(int fd, short which, void *arg)
{
	struct udp_con *con = arg;

	/* Everything is ready */
	cmd_ready_fd(&con->cmd, &cb_udp, con);

	cmd_trigger_read(&con->cmd, 1);
	cmd_trigger_write(&con->cmd, TAILQ_FIRST(&con->incoming) != NULL);
	return;
}
