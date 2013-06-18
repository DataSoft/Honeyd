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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

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
#include <syslog.h>
#include <grp.h>
#include <pcap.h>

#undef timeout_pending
#undef timeout_initialized

#include <event.h>

#include "honeyd.h"
#include "template.h"
#include "personality.h"
#include "subsystem.h"
#include "tcp.h"
#include "udp.h"
#include "fdpass.h"
#include "osfp.h"
#include "pyextend.h"
#include "honeyd_overload.h"
#include "util.h"

#include "interface.h"

ssize_t atomicio(ssize_t (*)(), int, void *, size_t);

extern struct callback cb_tcp;
extern struct callback cb_udp;

void
cmd_trigger_read(struct command *cmd, int size)
{
 	if (cmd->pfd == -1 || !cmd->fdconnected)
		return;
	if (size)
		TRACE(event_get_fd(cmd->pread), event_add(cmd->pread, NULL));
}

void
cmd_trigger_write(struct command *cmd, int size)
{
 	if (cmd->pfd == -1 || !cmd->fdconnected)
		return;
	if (size)
		TRACE(event_get_fd(cmd->pwrite), event_add(cmd->pwrite, NULL));
}

void
cmd_free(struct command *cmd)
{
	TRACE(event_get_fd(cmd->pread), event_del(cmd->pread));
	TRACE(event_get_fd(cmd->pwrite), event_del(cmd->pwrite));
	TRACE_RESET(cmd->pfd, close(cmd->pfd));
	cmd->pfd = -1;
	cmd->pid = -1;

	if (cmd->perrfd != -1) {
		TRACE(event_get_fd(cmd->peread), event_del(cmd->peread));
		TRACE_RESET(cmd->perrfd, close(cmd->perrfd));
		cmd->perrfd = -1;
	}

#ifdef HAVE_PYTHON
	if (cmd->state != NULL)
		pyextend_connection_end(cmd->state);
#endif
}

void
cmd_ready_fd(struct command *cmd, struct callback *cb, void *con)
{
	TRACE(cmd->pfd,
		cmd->pread = event_new(libevent_base, cmd->pfd, EV_READ, cb->cb_read, con));
	TRACE(cmd->pfd,
		cmd->pwrite = event_new(libevent_base, cmd->pfd, EV_WRITE, cb->cb_write, con));
	cmd->fdconnected = 1;

	if (cmd->perrfd != -1) {
		TRACE(cmd->perrfd,
			cmd->peread = event_new(libevent_base, cmd->perrfd, EV_READ, cb->cb_eread, con));
	}
}

struct addrinfo *
cmd_proxy_getinfo(char *address, int type, short port)
{
	struct addrinfo ai, *aitop;
        char strport[NI_MAXSERV];

        memset(&ai, 0, sizeof (ai));
        ai.ai_family = AF_INET;
        ai.ai_socktype = type;
        ai.ai_flags = 0;
        snprintf(strport, sizeof (strport), "%d", port);
        if (getaddrinfo(address, strport, &ai, &aitop) != 0) {
                warn("getaddrinfo: %s:%d", address, port);
                return (NULL);
        }

	return (aitop);
}

int
cmd_proxy_connect(struct tuple *hdr, struct command *cmd, struct addrinfo *ai,
    void *con)
{
	char ntop[NI_MAXHOST], strport[NI_MAXSERV];
	char *host = ntop, *port = strport;
	struct callback *cb;
	struct timeval tv = {10, 0};
        int fd;
        
	if (hdr->type == SOCK_STREAM)
		cb = &cb_tcp;
	else
		cb = &cb_udp;

        fd = socket(AF_INET, hdr->type, 0);
        if (fd == -1) {
                warn("socket");
                return (-1);
        }

        if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1)
                warn("fcntl(O_NONBLOCK)");

        if (fcntl(fd, F_SETFD, 1) == -1)
                warn("fcntl(F_SETFD)");

	TRACE(fd, cmd->pfd = fd);
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) {
		(*cb->cb_connect)(fd, EV_WRITE, con);
		return (0);
	}

	if (errno != EINPROGRESS) {
		warn("connect");
		cmd->pfd = -1;
		TRACE_RESET(fd, close(fd));
		return (-1);
	}

	TRACE(fd,
		cmd->pwrite = event_new(libevent_base, fd, EV_WRITE, cb->cb_connect, con));
	TRACE(event_get_fd(cmd->pwrite), event_add(cmd->pwrite, &tv));

	if (getnameinfo(ai->ai_addr, ai->ai_addrlen,
		ntop, sizeof(ntop), strport, sizeof(strport),
		NI_NUMERICHOST|NI_NUMERICSERV) != 0) {

		host = "<hosterror>";
		port = "<porterror>";
	}
	syslog(LOG_INFO, "Connection established: %s -> proxy to %s:%s",
	    honeyd_contoa(hdr), host, port);

	return (0);
}

void
cmd_environment(struct template *tmpl, struct tuple *hdr)
{
	char line[256];
	struct addr addr;
	struct ip_hdr ip;
	char *os_name;

	if (tmpl->person != NULL) {
		snprintf(line, sizeof(line), "%s", tmpl->person->name);
		setenv("HONEYD_PERSONALITY", line, 1);
	}

	if (hdr == NULL)
		return;
	     
	/* Determine the remote operating system */
	ip.ip_src = hdr->ip_src;
	os_name = honeyd_osfp_name(&ip);
	if (os_name != NULL) {
		setenv("HONEYD_REMOTE_OS", os_name, 1);
	}

	addr_pack(&addr, ADDR_TYPE_IP, IP_ADDR_BITS, &hdr->ip_src,IP_ADDR_LEN);
	snprintf(line, sizeof(line), "%s", addr_ntoa(&addr));
	setenv("HONEYD_IP_SRC", line, 1);

	addr_pack(&addr, ADDR_TYPE_IP, IP_ADDR_BITS, &hdr->ip_dst,IP_ADDR_LEN);
	snprintf(line, sizeof(line), "%s", addr_ntoa(&addr));
	setenv("HONEYD_IP_DST", line, 1);

	if (hdr->iface != NULL) {
		snprintf(line, sizeof(line), "%s", hdr->iface->if_ent.intf_name);
		setenv("HONEYD_INTERFACE", line, 1);
	}

	snprintf(line, sizeof(line), "%s", tmpl->name);
	setenv("HONEYD_TEMPLATE_NAME", line, 1);

	snprintf(line, sizeof(line), "%d", hdr->sport);
	setenv("HONEYD_SRC_PORT", line, 1);

	snprintf(line, sizeof(line), "%d", hdr->dport);
	setenv("HONEYD_DST_PORT", line, 1);
}

#define SETERROR(x) do { \
	snprintf x; \
	strlcat(error, errline, sizeof(error)); \
} while (0)

/* Drop the privileges and verify that they got dropped */

void
cmd_droppriv(uid_t uid, gid_t gid)
{
	static char error[1024];
	static char errline[256];

	error[0] = '\0';

	/* Lower privileges */
#ifdef HAVE_SETGROUPS
	if (setgroups(1, &gid) == -1)
		SETERROR((errline, sizeof(errline),
			     "%s: setgroups(%d) failed\n", __func__, gid));
#endif
#ifdef HAVE_SETREGID
	if (setregid(gid, gid) == -1)
		SETERROR((errline, sizeof(errline),
			     "%s: setregid(%d) failed\n", __func__, gid));
#endif
	if (setegid(gid) == -1)
		SETERROR((errline, sizeof(errline),
			     "%s: setegid(%d) failed\n", __func__, gid));
	if (setgid(gid) == -1)
		SETERROR((errline, sizeof(errline), 
			     "%s: setgid(%d) failed\n", __func__, gid));
#ifdef HAVE_SETREUID
	if (setreuid(uid, uid) == -1)
		SETERROR((errline, sizeof(errline),
			     "%s: setreuid(%d) failed\n", __func__, uid));
#endif
#ifdef __OpenBSD__
	if (seteuid(uid) == -1)
		SETERROR((errline, sizeof(errline),
			     "%s: seteuid(%d) failed\n", __func__, gid));
#endif
	if (setuid(uid) == -1)
		SETERROR((errline, sizeof(errline),
			     "%s: setuid(%d) failed\n", __func__, gid));

	if (getgid() != gid || getegid() != gid) {
		SETERROR((errline, sizeof(errline),
			     "%s: could not set gid to %d", __func__, gid));
		goto error;
	}

	if (getuid() != uid || geteuid() != uid) {
		SETERROR((errline, sizeof(errline),
			     "%s: could not set uid to %d", __func__, uid));
		goto error;
	}

	/* Make really sure that we dropped them */
	if (uid != 0 && (setuid(0) != -1 || seteuid(0) != -1)) {
		SETERROR((errline, sizeof(errline),
			     "%s: did not successfully drop privilege",
			     __func__));
		goto error;
	}
	if (gid != 0 && (setgid(0) != -1 || setegid(0) != -1)) {
		SETERROR((errline, sizeof(errline),
			     "%s: did not successfully drop privilege",
			     __func__));
		goto error;
	}

	return;
 error:
 syslog(LOG_ERR,"%s: terminated",__func__);
 exit(EXIT_FAILURE);
}

int
cmd_setpriv(struct template *tmpl)
{
	extern uid_t honeyd_uid;
	extern gid_t honeyd_gid;
	uid_t uid = honeyd_uid;
	gid_t gid = honeyd_gid;
	int nofiles = 30;
	struct rlimit rl;

	/* Set our own priority low */
	setpriority(PRIO_PROCESS, 0, 10);

	if (tmpl->uid)
		uid = tmpl->uid;
	if (tmpl->gid)
		gid = tmpl->gid;
	if (tmpl->max_nofiles)
		nofiles = tmpl->max_nofiles;

	cmd_droppriv(uid, gid);

	/* Raising file descriptor limits */
	rl.rlim_cur = rl.rlim_max = nofiles;
	if (setrlimit(RLIMIT_NOFILE, &rl) == -1)
	{
		syslog(LOG_ERR, "setrlimit: %d, failed to set resource limit", nofiles);
		exit(EXIT_FAILURE);
	}

	return (0);
}

int
cmd_fork(struct tuple *hdr, struct command *cmd, struct template *tmpl,
    char *execcmd, char **argv, void *con)
{
	extern int honeyd_nchildren;
	int pair[2], perr[2];
	struct callback *cb;
	sigset_t sigmask;

	if (socketpair(AF_UNIX, hdr->type, 0, pair) == -1)
		return (-1);
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, perr) == -1) {
		TRACE_RESET(pair[0], close(pair[0]));
		TRACE_RESET(pair[1], close(pair[1]));
		return (-1);
	}

	/* Block SIGCHLD */
	sigemptyset(&sigmask);
	sigaddset(&sigmask, SIGCHLD);
	if (sigprocmask(SIG_BLOCK, &sigmask, NULL) == -1) {
		warn("sigprocmask");
		goto fork_err;
	}

	cmd->pid = fork();
	if (cmd->pid == -1) {
		warn("fork");
		goto unmask_err;
	}

	if (cmd->pid == 0) {
		/* Child privileges */
		cmd_setpriv(tmpl);

		/* Child */
		TRACE_RESET(pair[0], close(pair[0]));
		if (dup2(pair[1], fileno(stdout)) == -1)
		{
			syslog(LOG_ERR, "%s: dup2 failed to copy descriptor",__func__);
			exit(EXIT_FAILURE);
		}
		if (dup2(pair[1], fileno(stdin)) == -1)
		{
			syslog(LOG_ERR, "%s: dup2", __func__);
			exit(EXIT_FAILURE);
		}
		TRACE_RESET(pair[0], close(perr[0]));
		if (dup2(perr[1], fileno(stderr)) == -1)
		{
			syslog(LOG_ERR, "%s: dup2", __func__);
			exit(EXIT_FAILURE);
		}

		TRACE_RESET(pair[1], close(pair[1]));
		TRACE_RESET(perr[1], close(perr[1]));

		cmd_environment(tmpl, hdr);

		if (execvp(execcmd, argv) == -1)
		{
			syslog(LOG_ERR, "%s: execv(%s): %s", __func__, execcmd, strerror(errno));
			exit(EXIT_FAILURE);
		}

		/* NOT REACHED */
	}

	TRACE_RESET(pair[1], close(pair[1]));
	TRACE(pair[0], cmd->pfd = pair[0]);
	if (fcntl(cmd->pfd, F_SETFD, 1) == -1)
		warn("fcntl(F_SETFD)");
	if (fcntl(cmd->pfd, F_SETFL, O_NONBLOCK) == -1)
		warn("fcntl(F_SETFL)");

	TRACE_RESET(perr[1], close(perr[1]));
	cmd->perrfd = perr[0];
	if (fcntl(cmd->perrfd, F_SETFD, 1) == -1)
		warn("fcntl(F_SETFD)");
	if (fcntl(cmd->perrfd, F_SETFL, O_NONBLOCK) == -1)
		warn("fcntl(F_SETFL)");

	if (hdr->type == SOCK_STREAM)
		cb = &cb_tcp;
	else
		cb = &cb_udp;

	cmd_ready_fd(cmd, cb, con);

	TRACE(event_get_fd(cmd->pread), event_add(cmd->pread, NULL));
	TRACE(event_get_fd(cmd->peread), event_add(cmd->peread, NULL));

	honeyd_nchildren++;

	/* Install old signal handler */
	if (sigprocmask(SIG_UNBLOCK, &sigmask, NULL) == -1) {
		warn("sigprocmask");
		goto fork_err;
	}
	return (0);

	/* Error cleanup */
 unmask_err:
	/* Install old signal handler */
	if (sigprocmask(SIG_UNBLOCK, &sigmask, NULL) == -1)
		warn("sigprocmask");

 fork_err:
	TRACE_RESET(perr[0], close(perr[0]));
	TRACE_RESET(perr[1], close(perr[1]));
	TRACE_RESET(pair[0], close(pair[0]));
	TRACE_RESET(pair[1], close(pair[1]));
	cmd->pfd = -1;

	return (-1);
}

int
cmd_python(struct tuple *hdr, struct command *cmd, void *con)
{
	int pair[2];
	struct callback *cb;

	if (socketpair(AF_UNIX, hdr->type, 0, pair) == -1)
		return (-1);

	TRACE(pair[0], cmd->pfd = pair[0]);
	if (fcntl(cmd->pfd, F_SETFD, 1) == -1)
		warn("fcntl(F_SETFD)");
	if (fcntl(cmd->pfd, F_SETFL, O_NONBLOCK) == -1)
		warn("fcntl(F_SETFL)");

	/* Python descriptors should not go across exec */
	if (fcntl(pair[1], F_SETFD, 1) == -1)
		warn("fcntl(F_SETFD)");
	if (fcntl(pair[1], F_SETFL, O_NONBLOCK) == -1)
		warn("fcntl(F_SETFL)");

	if (hdr->type == SOCK_STREAM)
		cb = &cb_tcp;
	else
		cb = &cb_udp;

	cmd_ready_fd(cmd, cb, con);

	TRACE(event_get_fd(cmd->pread), event_add(cmd->pread, NULL));

	return (pair[1]);
}

int
cmd_subsystem(struct template *tmpl, struct subsystem *sub,
    char *execcmd, char **argv)
{
	extern int honeyd_nchildren;
	struct command *cmd = &sub->cmd;
	extern struct callback subsystem_cb;
	int pair[2];
	sigset_t sigmask;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1)
		return (-1);

	/* Block SIGCHLD */
	sigemptyset(&sigmask);
	sigaddset(&sigmask, SIGCHLD);
	if (sigprocmask(SIG_BLOCK, &sigmask, NULL) == -1) {
		warn("sigprocmask");
		goto fork_err;
	}

	cmd->pid = fork();
	if (cmd->pid == -1) {
		warn("fork");
		goto unmask_err;
	}

	if (cmd->pid == 0) {
		char magic_buf[12];
		int magic_fd;
		/* Set privileges */
		cmd_setpriv(tmpl);

		/* Child */
		TRACE_RESET(pair[0], close(pair[0]));
		/* Set the communication fd */
		if ((magic_fd = dup(pair[1])) == -1)
		{
			syslog(LOG_ERR, "%s: dup(%d): no magic failed to duplicate the pair", __func__, pair[1]);
			exit(EXIT_FAILURE);
		}
		snprintf(magic_buf, sizeof(magic_buf), "%d", magic_fd);
		setenv(SUBSYSTEM_MAGICFD, magic_buf, 1);
		if (dup2(fileno(stderr), fileno(stdout)) == -1)
		{
			syslog(LOG_ERR, "%s: dup2", __func__);
			exit(EXIT_FAILURE);
		}
		if (dup2(fileno(stderr), fileno(stdin)) == -1)
		{
			syslog(LOG_ERR, "%s: dup2", __func__);
			exit(EXIT_FAILURE);
		}

		TRACE_RESET(pair[1], close(pair[1]));

		cmd_environment(tmpl, NULL);

		/* Setup the wrapper library */
		if (setenv("LD_PRELOAD", PATH_HONEYDLIB"/libhoneyd.so", 1) == -1)
		{
			syslog(LOG_ERR, "%s: setenv", __func__);
			exit(EXIT_FAILURE);
		}

		if (execv(execcmd, argv) == -1)
		{
			syslog(LOG_ERR, "%s: execv(%s)", __func__, execcmd);
			exit(EXIT_FAILURE);
		}

		/* NOT REACHED */
	}

	TRACE_RESET(pair[1], close(pair[1]));
	TRACE(pair[0], cmd->pfd = pair[0]);
	if (fcntl(cmd->pfd, F_SETFD, 1) == -1)
		warn("fcntl(F_SETFD)");

	cmd->perrfd = -1;
	cmd_ready_fd(cmd, &subsystem_cb, sub);

	TRACE(event_get_fd(cmd->pread), event_add(cmd->pread, NULL));

	honeyd_nchildren++;

	/* Install old signal handler */
	if (sigprocmask(SIG_UNBLOCK, &sigmask, NULL) == -1) {
		warn("sigprocmask");
		goto fork_err;
	}
	return (0);

	/* Error cleanup */
 unmask_err:
	/* Install old signal handler */
	if (sigprocmask(SIG_UNBLOCK, &sigmask, NULL) == -1)
		warn("sigprocmask");

 fork_err:
	TRACE_RESET(pair[0], close(pair[0]));
	TRACE_RESET(pair[1], close(pair[1]));
	cmd->pfd = -1;

	return (-1);
}

static void
cmd_subsystem_connect_cb(int fd, short what, void *arg)
{
	struct port_encapsulate *tmp = arg;
	struct port *port = tmp->port;

	TAILQ_REMOVE(&port->pending, tmp, next);

	if (what != EV_WRITE) {
		/* We encountered some error with this */
		if (tmp->hdr->type == SOCK_STREAM)
			tcp_connectfail(tmp->con);
		goto out;
	}

	cmd_subsystem_connect(tmp->hdr, tmp->cmd, port, tmp->con);

 out:
	port_encapsulation_free(tmp);
}

int
cmd_subsystem_schedule_connect(struct tuple *hdr, struct command *cmd,
    struct port *port, void *con)
{
	struct port_encapsulate *tmp = calloc(1, sizeof(*tmp));
	struct subsystem *sub = port->sub;

	if (tmp == NULL)
		return (-1);

	tmp->hdr = hdr;
	tmp->cmd = cmd;
	tmp->port = port;
	tmp->con = con;

	/* Tell the connection that it has a pending connection */
	tmp->hdr->pending = tmp;

	TAILQ_INSERT_TAIL(&port->pending, tmp, next);

	TRACE(port->sub_fd,
		event_new(libevent_base, port->sub_fd, EV_WRITE, cmd_subsystem_connect_cb, tmp));
	TRACE(event_get_fd(tmp->ev),
		event_add(tmp->ev, NULL));

	syslog(LOG_DEBUG,
	    "Scheduling connection establishment: %s -> subsystem \"%s\"",
	    honeyd_contoa(hdr), sub->cmdstring);

	return (0);
}

int
cmd_subsystem_connect(struct tuple *hdr, struct command *cmd,
    struct port *port, void *con)
{
	struct callback *cb;
	struct subsystem *sub = port->sub;
	struct bundle bundle;
	struct addr src, dst;
	int pair[2];
        
	if (hdr->type == SOCK_STREAM)
		cb = &cb_tcp;
	else
		cb = &cb_udp;

        if (socketpair(AF_LOCAL, hdr->type, 0, pair) == -1) {
                warn("%s: socketpair: %s", __func__, sub->cmdstring);
                return (-1);
        }

        if (fcntl(pair[0], F_SETFL, O_NONBLOCK) == -1)
                warn("fcntl(O_NONBLOCK)");

        if (fcntl(pair[0], F_SETFD, 1) == -1)
                warn("fcntl(F_SETFD)");

	TRACE(pair[0], cmd->pfd = pair[0]);

	/* Prepare sockaddr for both src and destination */
	addr_pack(&src, ADDR_TYPE_IP, IP_ADDR_BITS, &hdr->ip_src,IP_ADDR_LEN);
	addr_ntos(&src, (struct sockaddr *)&bundle.src);
	bundle.src.sin_port = htons(hdr->sport);
	addr_pack(&dst, ADDR_TYPE_IP, IP_ADDR_BITS, &hdr->ip_dst,IP_ADDR_LEN);
	addr_ntos(&dst, (struct sockaddr *)&bundle.dst);
	bundle.dst.sin_port = htons(hdr->dport);

	if (send_fd(port->sub_fd, pair[1], &bundle, sizeof(bundle)) == -1) {
		TRACE_RESET(pair[0], close(pair[0]));
		TRACE_RESET(pair[1], close(pair[1]));
		cmd->pfd = -1;
		return (-1);
	}

	/* After transfering the file descriptor, we may close it */
	TRACE_RESET(pair[1], close(pair[1]));

	/* We are connected now */
	(*cb->cb_connect)(pair[0], EV_WRITE, con);

	syslog(LOG_INFO, "Connection established: %s -> subsystem \"%s\"",
	    honeyd_contoa(hdr), sub->cmdstring);

	return (0);
}

/*
 * Called when the 3-way handshake for a connection initiated by a
 * subsystem completed successfully.
 */

int
cmd_subsystem_localconnect(struct tuple *hdr, struct command *cmd,
    struct port *port, void *con)
{
	struct callback *cb;
	struct subsystem *sub = port->sub;
	struct sockaddr_in si;
	struct addr src;
	int fd;
        
	if (hdr->type == SOCK_STREAM)
		cb = &cb_tcp;
	else
		cb = &cb_udp;

	/*
	 * If we do not have a control file descriptor for this connection,
	 * then get it now.  The control file descriptor will give us the
	 * fd that is used for the real communication.
	 */
	if (port->sub_fd == -1) {
		char res;

		while ((fd = receive_fd(sub->cmd.pfd, NULL, NULL)) == -1) {
			if (errno != EAGAIN) {
				warnx("%s: receive_fd", __func__);
			}
		}

		/* Confirm success of failure */
		res = fd == -1 ? -1 : 0;
		TRACE(sub->cmd.pfd,
		    atomicio(write, sub->cmd.pfd, &res, 1));
		if (fd == -1)
			return (-1);

		TRACE(fd, port->sub_fd = fdshare_dup(fd));
	}

	/* Get another fd on this special thingy */
	while ((fd = receive_fd(port->sub_fd, NULL, NULL)) == -1) {
		if (errno != EAGAIN) {
			TRACE(port->sub_fd, fdshare_close(port->sub_fd));
			warnx("%s: receive_fd", __func__);
			return (-1);
		}
	}

        if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1)
                warn("%s: fcntl(O_NONBLOCK)", __func__);

        if (fcntl(fd, F_SETFD, 1) == -1)
                warn("%s: fcntl(F_SETFD)", __func__);

	TRACE(fd, cmd->pfd = fd);

	/* Prepare sockaddr */
	addr_pack(&src, ADDR_TYPE_IP, IP_ADDR_BITS, &hdr->ip_dst, IP_ADDR_LEN);
	addr_ntos(&src, (struct sockaddr *)&si);
	si.sin_port = htons(hdr->dport);

	/* Write the bound socket address to the other side */
	if (atomicio(write, port->sub_fd, &si, sizeof(si)) != sizeof(si)) {
		TRACE(port->sub_fd, fdshare_close(port->sub_fd));
		port->sub_fd = -1;
		TRACE_RESET(cmd->pfd, close(cmd->pfd));
		cmd->pfd = -1;
		return (-1);
	}

	/* Now we may close the special thingy */
	TRACE(port->sub_fd, fdshare_close(port->sub_fd));
	port->sub_fd = -1;

	/* We are connected now */
	(*cb->cb_connect)(fd, EV_WRITE, con);

	syslog(LOG_INFO, "Connection established: subsystem \"%s\" -> %s",
	    sub->cmdstring, honeyd_contoa(hdr));

	return (0);
}
