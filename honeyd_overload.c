/*
 * Copyright (c) 2003 Niels Provos <provos@citi.umich.edu>
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
 * Copyright (c) 2002 Marius Aamodt Eriksen <marius@monkey.org>
 * All rights reserved.
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
 * 3. The names of the copyright holders may not be used to endorse or
 *    promote products derived from this software without specific
 *    prior written permission.

 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/types.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/socket.h>
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/un.h>

#include <netinet/in.h>

#include <err.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <limits.h>
#include <math.h>
#include <time.h>
#include <syslog.h>
#include <pwd.h>
#include <dnet.h>
#include <stdarg.h>

#undef timeout_pending
#undef timeout_initialized

#include <event.h>

#include "honeyd.h"
#include "template.h"
#include "subsystem.h"
#include "fdpass.h"
#include "honeyd_overload.h"

#undef DEBUG
#ifdef DEBUG
#define DPRINTF(x) fprintf x
#else
#define DPRINTF(X)
#endif

#define SETCMD(x,z,y) do { \
	(x)->domain = (y)->domain; \
	(x)->type = (y)->type; \
	(x)->protocol = (y)->protocol; \
	(x)->command = (z); \
	(x)->len = (y)->salen; \
	memcpy(&(x)->sockaddr, &(y)->sa, (y)->salen); \
} while (0)

/*
 * Used to protect a file descriptor if it is used directly to communicate
 * with.  In the long run, we will have to make new socket pairs for
 * communication because otherwise we get messed up with multiple processes
 * using the same file descriptor and then interfere.
 */

#define PROTECT(x) do { \
	(x)->flags |= FD_INTERNAL_USE; \
} while (0)

#define UNPROTECT(x) do { \
	(x)->flags &= ~FD_INTERNAL_USE; \
} while (0)

/* Variables figure out where we are */

#define DECLARE(name, ret, args) static ret (*libc_##name) args

DECLARE(socket, int, (int, int, int));
DECLARE(bind, int, (int, const struct sockaddr *, socklen_t));
DECLARE(listen, int, (int, int));
DECLARE(close, int, (int));
DECLARE(connect, int, (int, const struct sockaddr *, socklen_t));
DECLARE(setsockopt, int, (int, int, int, const void *, socklen_t));
DECLARE(getsockname, int, (int, struct sockaddr *, socklen_t *));

DECLARE(recv, ssize_t, (int, void *, size_t, int));
DECLARE(recvfrom, ssize_t, (int, void *, size_t, int, struct sockaddr *,
	    socklen_t *));

DECLARE(sendto, ssize_t, (int, const void *, size_t, int,
	    const struct sockaddr *, socklen_t));
DECLARE(sendmsg, ssize_t, (int s, const struct msghdr *msg, int flags));
DECLARE(recvmsg, ssize_t, (int s, struct msghdr *msg, int flags));

DECLARE(select, int, (int, fd_set *, fd_set *, fd_set *, struct timeval *));
DECLARE(poll, int, (struct pollfd *, int, int));

DECLARE(accept, int, (int, struct sockaddr *, socklen_t *));
DECLARE(dup, int, (int));
DECLARE(dup2, int, (int, int));
DECLARE(fcntl, int, (int, int, ...));
#if defined(HAVE_KQUEUE) && 0
DECLARE(kqueue,int, (void));
#endif

ssize_t atomicio(ssize_t (*)(), int, void *, size_t);

#ifdef DL_NEED_UNDERSCORE
#define UNDERSCORE "_"
#else
#define UNDERSCORE ""
#endif /* DL_NEED_UNDERSCORE */

#define GETADDR(x) do {							     \
	if ((libc_##x = dlsym(dh, UNDERSCORE #x)) == NULL)		     \
	{ \
	syslog(LOG_ERR, "[honeyd_overload] Failed to get " #x "() address");\
	exit(EXIT_FAILURE);\
	}\
} while (0);
//errx(1, "[honeyd_overload] Failed to get " #x "() address");
#define FD_UNBOUND	0x01
#define FD_BOUND	0x02
#define FD_CONNECTED	0x04
#define FD_CONNECTING	0x08

#define FD_INTERNAL_USE	0x80
#define FD_GETSOCKNAME	0x40	/* supports only getsockname */

struct fd {
	TAILQ_ENTRY(fd) next;

	int this_fd;
	int their_fd;

	int flags;

	int domain;
	int type;
	int protocol;

	struct sockaddr_storage sa;	/* address we bound to */
	socklen_t salen;

	struct sockaddr_storage rsa;	/* remote address */
	socklen_t rsalen;

	struct sockaddr_storage lsa;	/* address we are representing */
	socklen_t lsalen;
};

/* Prototypes */

static void free_fd(struct fd *nfd);

#define INIT do { \
	if (!initalized) \
		honeyd_init(); \
} while (0)

static TAILQ_HEAD(fdqueue, fd) fds;
static int initalized;
static int magic_fd;

static void
honeyd_init(void)
{
	void *dh;

	magic_fd = atoi(getenv(SUBSYSTEM_MAGICFD));
	if (magic_fd <= 0)
	{
		syslog(LOG_ERR, "[honeyd_overload] cannot find magic fd");
		exit(EXIT_FAILURE);
	}
	//errx(1, "[honeyd_overload] cannot find magic fd");

#ifdef NODLOPEN
	dh = (void *) -1L;
#else
 	if ((dh = dlopen(DLOPENLIBC, RTLD_LAZY)) == NULL)
 	errx(1, "[honeyd_overload] Failed to open libc");
#endif /* DLOPEN */

	GETADDR(socket);
	GETADDR(setsockopt);
	GETADDR(getsockname);
	GETADDR(bind);
	GETADDR(listen);
	GETADDR(close);
	GETADDR(connect);

#ifndef __FreeBSD__
	GETADDR(recv);
#endif /* !__FreeBSD__ */
	GETADDR(recvfrom);

	GETADDR(sendto);
	GETADDR(sendmsg);
	GETADDR(recvmsg);

	GETADDR(select);
	GETADDR(poll);

	GETADDR(dup);
	GETADDR(dup2);
	GETADDR(fcntl);

	GETADDR(accept);

#if defined(HAVE_KQUEUE) && 0
	GETADDR(kqueue);
#endif

	/* Do the rest here */
	TAILQ_INIT(&fds);

	initalized = 1;
}

static struct fd *
new_fd(int fd)
{
	struct fd *nfd;

	if ((nfd = calloc(1, sizeof(struct fd))) == NULL)
		return (NULL);

	nfd->this_fd = fd;

	TAILQ_INSERT_TAIL(&fds, nfd, next);

	DPRINTF((stderr, "%s: newfd %d\n", __func__, nfd->this_fd));

	return (nfd);
}

static struct fd *
newsock_fd(int domain, int type, int protocol)
{
	struct fd *nfd;
	int pair[2];

	if (socketpair(AF_LOCAL, type, 0, pair) == -1) {
		warn("%s: socketpair", __func__);
		return (NULL);
	}

	if ((nfd = new_fd(pair[0])) == NULL) {
		(*libc_close)(pair[0]);
		(*libc_close)(pair[1]);
		return (NULL);
	}

	if (protocol == 0) {
		switch (type) {
		case SOCK_STREAM:
			protocol = IPPROTO_TCP;
			break;
		case SOCK_DGRAM:
			protocol = IPPROTO_UDP;
			break;
		}
	}

	nfd->domain = domain;
	nfd->type = type;
	nfd->protocol = protocol;

	nfd->flags |= FD_UNBOUND;

	/* We might send this fd over */
	nfd->their_fd = pair[1];
	DPRINTF((stderr, "%s: theirfd %d\n", __func__, pair[1]));

	return (nfd);
}

static struct fd *
clone_fd(struct fd *ofd, int fd)
{
	struct fd *nfd;

	if ((nfd = new_fd(fd)) == NULL)
		return (NULL);

	nfd->domain = ofd->domain;
	nfd->type = ofd->type;
	nfd->protocol = ofd->protocol;

	nfd->flags = ofd->flags;

	nfd->their_fd = (*libc_dup)(ofd->their_fd);
	if (nfd->their_fd == -1) {
		free_fd(nfd);
		return (NULL);
	}

	nfd->sa = ofd->sa;
	nfd->salen = ofd->salen;
	nfd->rsa = ofd->rsa;
	nfd->rsalen = ofd->rsalen;

	return (nfd);
}

static int
send_cmd(struct subsystem_command *cmd)
{
	char res;

	if (atomicio(write, magic_fd, cmd,
		sizeof(struct subsystem_command)) !=
	    sizeof(struct subsystem_command)) {
		DPRINTF((stderr, "%s: write failed\n", __func__));
		errno = EBADF;
		return (-1);
	}

	if (atomicio(read, magic_fd, &res, 1) != 1) {
		DPRINTF((stderr, "%s: read failed\n", __func__));
		errno = EBADF;
		return (-1);
	}

	return (res);
}

static void
free_fd(struct fd *nfd)
{
	(*libc_close)(nfd->this_fd);
	(*libc_close)(nfd->their_fd);

	TAILQ_REMOVE(&fds, nfd,  next);

	free(nfd);
}

/* Finds an FD as long as the flag_filter does not match */

static struct fd *
find_fd(int fd, int flag_filter)
{
	struct fd *nfd;

	/* Never return internal fds */
	flag_filter |= FD_INTERNAL_USE;
	
	TAILQ_FOREACH(nfd, &fds, next)
	    if (nfd->this_fd == fd) {
		    /* Do not return the file object if it is protected */
		    if (nfd->flags & flag_filter)
			    return (NULL);
		    return (nfd);
	    }

	return (NULL);
}

int
socket(int domain, int type, int protocol)
{
	struct fd *nfd;

	INIT;

#ifdef AF_INET6
	if (domain == AF_INET6) {
		errno = EPROTONOSUPPORT;
		return (-1);
	}
#endif
	if (type == SOCK_RAW) {
		errno = EACCES;
		return (-1);
	}

	/* If its not an internet socket, allow it */
	if (domain != AF_INET)
		return ((*libc_socket)(domain, type, protocol));

	DPRINTF((stderr, "%s: Attempting to create socket: %d %d %d\n",
	    __func__, domain, type, protocol));

	nfd = newsock_fd(domain, type, protocol);
	if (nfd == NULL) {
		errno = ENOBUFS;
		return (-1);
	}

	return (nfd->this_fd);
}

int
listen(int s, int backlog)
{
	struct fd *nfd;
	struct subsystem_command cmd;
	int res;

	INIT;

	DPRINTF((stderr, "%s: called on %d\n", __func__, s));
	if ((nfd = find_fd(s, FD_GETSOCKNAME)) == NULL)
		return ((*libc_listen)(s, backlog));

	if (!(nfd->flags & FD_BOUND)) {
		errno = EOPNOTSUPP;
		return (-1);
	}

	SETCMD(&cmd, SUB_LISTEN, nfd);
	if (send_cmd(&cmd) == -1) {
		errno = EBADF;
		return (-1);
	}

	/* Now send them the fd */
	send_fd(magic_fd, nfd->their_fd, NULL, 0);
	if (atomicio(read, magic_fd, &res, 1) != 1) {
		errno = EBADF;
		return (-1);
	}

	(*libc_close)(nfd->their_fd);
	nfd->their_fd = -1;

	return (0);
}

/*
 * Protocol:
 * 1. send bind command
 * 2. read the allocated port number
 */

int
bind(int s, const struct sockaddr *name, socklen_t namelen)
{
	struct fd *nfd;
	struct subsystem_command cmd;
	u_short port;

	INIT;

	DPRINTF((stderr, "%s: called: fd %d familiy %d\n",
		    __func__, s, name->sa_family));

	if ((nfd = find_fd(s, FD_GETSOCKNAME)) == NULL)
		return ((*libc_bind)(s, name, namelen));

	if (namelen >= sizeof(struct sockaddr_storage)) {
		errno = EINVAL;
		return (-1);
	}

	nfd->salen = namelen;
	memcpy(&nfd->sa, name, namelen);

	SETCMD(&cmd, SUB_BIND, nfd);

	if (send_cmd(&cmd) == -1) {
		errno = EADDRINUSE;
		return (-1);
	}

	if (atomicio(read, magic_fd, &port, sizeof(port))
	    != sizeof(port)) {
		errno = EBADF;
		return (-1);
	} else {
		/* Record local port information */
		struct sockaddr *sa = (struct sockaddr *)(&nfd->sa);
		switch (sa->sa_family) {
		case AF_INET: {
			struct sockaddr_in *sin = (struct sockaddr_in *)sa;
			sin->sin_port = htons(port);
			break;
		}
#ifdef AF_INET6
		case AF_INET6: {
			struct sockaddr_in6 *sin = (struct sockaddr_in6 *)sa;
			sin->sin6_port = htons(port);
			break;
		}
#endif
		default:
			DPRINTF((stderr,
				    "%s: bad socket family on %d: %d\n",
				    __func__, s, sa->sa_family));
			break;
		}
	}

	nfd->flags &= ~FD_UNBOUND;
	nfd->flags = FD_BOUND;

	DPRINTF((stderr, "%s: socket %d bound at port %d\n",
		    __func__, s, port));

	return (0);
}

int
close(int fd)
{
	struct fd *nfd;
	struct subsystem_command cmd;

	INIT;

	/* Don't close the magic file descriptor that points back to us */
	if (fd == magic_fd) {
		errno = EBADF;
		return (-1);
	}

	if ((nfd = find_fd(fd, 0)) == NULL)
		return ((*libc_close)(fd));

	DPRINTF((stderr, "%s: with %d, flags %x\n", __func__,
	    nfd->this_fd, nfd->flags));


	/* XXX - need to tell honeyd about close in other cases */
	if (nfd->flags & FD_BOUND) {
		SETCMD(&cmd, SUB_CLOSE, nfd);
		send_cmd(&cmd);
	}

	free_fd(nfd);

	return (0);
}

int
connect(int s, const struct sockaddr *name, socklen_t namelen)
{
	struct subsystem_command cmd;
	struct sockaddr_in si;
	struct fd *nfd;
	int pair[2];
	char res;

	INIT;

	DPRINTF((stderr, "%s: called: %d: %p %d\n",
		    __func__, s, name, namelen));

	if ((nfd = find_fd(s, FD_GETSOCKNAME)) == NULL)
		return ((*libc_connect)(s, name, namelen));

	/* Report an error if the socket is connected already */
	if (nfd->flags & FD_CONNECTING) {
		DPRINTF((stderr, "%s: %d is connecting already", __func__, s));
		errno = EINPROGRESS;
		return (-1);
	}

	/* Report an error if the socket is connected already */
	if (nfd->flags & FD_CONNECTED) {
		DPRINTF((stderr, "%s: %d already connected", __func__, s));
		errno = EISCONN;
		return (-1);
	}

	if (namelen > sizeof(struct sockaddr_storage)) {
		errno = EINVAL;
		return (-1);
	}

	/* Get another socketpair */
	if (socketpair(AF_LOCAL, SOCK_STREAM, 0, pair) == -1) {
		DPRINTF((stderr, "%s: socketpair failed", __func__));
		errno = ETIMEDOUT; /* XXX */
		return (-1);
	}

	SETCMD(&cmd, SUB_CONNECT, nfd);
	cmd.rlen = namelen;
	memcpy(&cmd.rsockaddr, name, namelen);
	/* Copy local address, too */
	cmd.len = nfd->salen;
	memcpy(&cmd.sockaddr, &nfd->sa, nfd->salen);
	if (send_cmd(&cmd) == -1) {
		(*libc_close)(pair[0]);
		(*libc_close)(pair[1]);
		errno = ENETUNREACH;
		return (-1);
	}

	/* Send special communication fd */
	send_fd(magic_fd, pair[1], NULL, 0);
	(*libc_close)(pair[1]);

	if (atomicio(read, pair[0], &res, sizeof(res)) != sizeof(res)){
		(*libc_close)(pair[0]);
		(*libc_close)(pair[1]);
		DPRINTF((stderr, "%s: failure to send fd\n", __func__));
		errno = EBADF;
		return (-1);
	}

	/* Now send them the fd */
	send_fd(pair[0], nfd->their_fd, NULL, 0);

	nfd->flags |= FD_CONNECTING;

#if 0
	/* This is the point where we need to check non-blocking IO */
	flags = (*libc_fcntl)(nfd->this_fd, F_GETFL, NULL);
	if (flags != -1 && (flags & O_NONBLOCK)) {
		fcntl(pair[0], F_SETFL, O_NONBLOCK);
	}
#endif

	if (atomicio(read, pair[0], &si, sizeof(si)) != sizeof(si)) {
		DPRINTF((stderr, "%s: did not receive sockaddr\n", __func__));
		errno = ECONNREFUSED;
		return (-1);
	}

 	/* Now we can close the special communication fds */
	(*libc_close)(pair[0]);
	(*libc_close)(pair[1]);

	(*libc_close)(nfd->their_fd);
	nfd->their_fd = -1;

	nfd->salen = sizeof(si);
	memcpy(&nfd->sa, &si, nfd->salen);

	nfd->rsalen = namelen;
	memcpy(&nfd->rsa, name, namelen);

	nfd->flags &= ~FD_CONNECTING;
	nfd->flags |= FD_CONNECTED;

	DPRINTF((stderr, "%s: socket %d is connected\n", __func__, s));

	return (0);
}

int
select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
    struct timeval *timeout)
{
	INIT;

	return ((*libc_select)(nfds, readfds, writefds, exceptfds, timeout));
}

#if 0
int
poll(struct pollfd *fds, int nfds, int timeout)
{
	INIT;

	return ((*libc_poll)(fds, nfds, timeout));
}
#endif /* 0 */


#ifndef __FreeBSD__ 
ssize_t
recv(int sock, void *buf, size_t len, int flags)
{
	ssize_t ret;

	INIT;

	ret = (*libc_recv)(sock, buf, len, flags);

	DPRINTF((stderr, "%s: called on %d -> %d\n", __func__, sock, ret));

	return (ret);
}
#endif /* !__FreeBSD__ */

ssize_t
recvfrom(int sock, void *buf, size_t len, int flags, struct sockaddr *from,
    socklen_t *fromlen)
{
	ssize_t ret;
	struct fd *nfd;
	socklen_t flen = fromlen != NULL ? *fromlen : 0;

	INIT;

	DPRINTF((stderr, "%s: called on %d, %p,%d\n",
		    __func__, sock, from, len));

	ret = (*libc_recvfrom)(sock, buf, len, flags, from, fromlen);

	DPRINTF((stderr, "%s: read %d\n", __func__, ret));

	if (from != NULL && (nfd = find_fd(sock, FD_GETSOCKNAME)) != NULL) {
		if (flen < nfd->rsalen)
			goto out;
		memcpy(from, &nfd->rsa, nfd->rsalen);
		*fromlen = nfd->rsalen;
		DPRINTF((stderr, "%s: filled in %d\n", __func__, nfd->rsalen));
	}
 out:
	return (ret);
}

ssize_t
sendto(int sock, const void *buf, size_t len, int flags,
    const struct sockaddr *to, socklen_t tolen)
{
	struct fd *nfd;
	ssize_t ret;

	INIT;

	nfd = find_fd(sock, FD_GETSOCKNAME);

	if (nfd == NULL)
		return ((*libc_sendto)(sock, buf, len, flags, to, tolen));

	/*
	 * UDP sockets can be sendto when they are not yet connected.
	 * However, Honeyd requires UDP sockets to be connected.  This can
	 * cause problems when an application uses one UDP socket to talk
	 * to multiple hosts.
	 */
	if (!(nfd->flags & FD_CONNECTED) && nfd->protocol == IPPROTO_UDP) {
		DPRINTF((stderr, "%s : false connect is needed !\n",__func__));
		connect(sock,to,tolen);
	}

	ret = (*libc_sendto)(sock, buf, len, flags, NULL, 0);

	DPRINTF((stderr, "%s: called: %d: len %d: sa %p,%d -> %d (%s)\n",
		    __func__, len,
		    sock, to, tolen,
		    ret, ret != -1 ? "no error" : strerror(errno)));

	return (ret);
}

int
getsockname(int sock, struct sockaddr *to, socklen_t *tolen)
{
	struct fd *nfd;
	struct sockaddr *src;
	socklen_t srclen;
	

	INIT;

	nfd = find_fd(sock, 0);
	if (nfd == NULL)
		return ((*libc_getsockname)(sock, to, tolen));

	DPRINTF((stderr, "%s: called: %d: %p,%d\n", __func__,
		    sock, to, *tolen));

	/*
	 * Get the real local address if possible, otherwise return
	 * the address we bound to.
	 */
	if (nfd->lsalen) {
		src = (struct sockaddr *)&nfd->lsa;
		srclen = nfd->lsalen;
	} else {
		src = (struct sockaddr *)&nfd->sa;
		srclen = nfd->salen;
	}
	
	if (*tolen < srclen)
		srclen = *tolen;
	else
		*tolen = srclen;
	memcpy(to, src, srclen);

	return (0);
}

ssize_t
recvmsg(int sock, struct msghdr *msg, int flags)
{
	struct fd *nfd;
	ssize_t ret = -1;
	size_t len, off;
	int i;
	void *data;

	INIT;

	nfd = find_fd(sock, FD_GETSOCKNAME);

	if (nfd == NULL)
		return ((*libc_recvmsg)(sock, msg, flags));

	errno = EINVAL;
	DPRINTF((stderr, "%s: called: %d: %p, %d\n", __func__, sock,
		    msg, flags));

	/* We do not currently support these flags */
	if ( flags & (MSG_OOB|MSG_PEEK) ) {
		errno = EINVAL;
		return (-1);
	}

	/* We would like to know how much data we can read. */
	len = 0;
	for ( i = 0; i < msg->msg_iovlen; i++ ) {
		len += msg->msg_iov[i].iov_len;
	}
	if ((data = malloc(len)) == NULL) {
		errno = ENOBUFS;
		return (-1);
	}

	/* Now we have successfully converted the call into a recvmsg call */
	ret = recvfrom(sock, data, len, flags,
	    msg->msg_name, &msg->msg_namelen);

	if (ret == -1)
		goto out;

	/* Copy the data back into the provided memory buffers */
	for ( i = 0, off = 0; i < msg->msg_iovlen && off < ret; i++ ) {
		ssize_t avail = msg->msg_iov[i].iov_len;
		if (avail > ret - off)
			avail = ret - off;
		memcpy(msg->msg_iov[i].iov_base, data + off, avail);
		off += avail;
	}

 out:
	free(data);

	return (ret);
}

ssize_t
sendmsg(int sock, const struct msghdr *msg, int flags)
{
	struct fd *nfd;
	ssize_t ret = -1;
	size_t len, off;
	int i;
	void *data;

	INIT;

	nfd = find_fd(sock, FD_GETSOCKNAME);

	if (nfd == NULL)
		return ((*libc_sendmsg)(sock, msg, flags));

	errno = EINVAL;
	DPRINTF((stderr, "%s: called: %d: %p, %d\n", __func__, sock,
		    msg, flags));

	/* We do not currently support these flags */
	if ( flags & (MSG_OOB|MSG_DONTROUTE) ) {
		errno = EINVAL;
		return (-1);
	}

	/* We just gather the data and then send it as bulk */
	len = 0;
	for ( i = 0; i < msg->msg_iovlen; i++ ) {
		len += msg->msg_iov[i].iov_len;
	}
	if ((data = malloc(len)) == NULL) {
		errno = ENOBUFS;
		return (-1);
	}

	/* Copy all the data into our single buffer */
	for ( i = 0, off = 0; i < msg->msg_iovlen; i++ ) {
		memcpy(data + off,
		    msg->msg_iov[i].iov_base,
		    msg->msg_iov[i].iov_len);
		off += msg->msg_iov[i].iov_len;
	}

	/* Now we have successfully converted the call into a sendmsg call */
	ret = sendto(sock, data, len, 0, msg->msg_name, msg->msg_namelen);

	free(data);

	return (ret);
}

int
setsockopt(int sock, int level, int optname, const void *optval,
    socklen_t option)
{
	INIT;

	/* blocking, etc. */
	return ((*libc_setsockopt)(sock, level, optname, optval, option));
}

int
fcntl(int fd, int cmd, ...)
{
	struct fd *nfd;
	int argument, i;
	int req_special = 0;
	int ret = -1;
	va_list ap;

	va_start(ap, cmd);

	INIT;

	/* Some fcntl commands require our special attention */
	if (cmd == F_DUPFD || cmd == F_SETFD || cmd == F_XXX_GETSOCK)
		req_special = 1;

	if (!req_special || (nfd = find_fd(fd, FD_GETSOCKNAME)) == NULL) {
		struct flock *flock;

		switch (cmd) {
		case F_GETLK:
		case F_SETLK:
		case F_SETLKW:
			flock = va_arg(ap, struct flock *);
			return (*libc_fcntl)(fd, cmd, flock);
		default:
			argument = va_arg(ap, int);
			return (*libc_fcntl)(fd, cmd, argument);
		}

	}

	/*
	 * A special hook for a subsystem to get the local address
	 * information for a connected socket.
	 */
	if (cmd == F_XXX_GETSOCK) {
		struct sockaddr *sa = va_arg(ap, struct sockaddr *);
		socklen_t *psalen = va_arg(ap, socklen_t *);
		va_end(ap);

		DPRINTF((stderr, "%s: called: %d XXX_GETSOCK\n",
			    __func__, fd));

		if (nfd->lsalen == 0) {
			errno = EBADF;
			return (-1);
		}
		
		if (*psalen < nfd->lsalen) {
			errno = EINVAL;
			return (-1);
		}

		*psalen = nfd->lsalen;
		memcpy(sa, &nfd->lsa, nfd->lsalen);

		return (0);
	}

	/* Get the fd argument from fcntl */
	argument = va_arg(ap, int);

	va_end(ap);

	switch (cmd) {
	case F_DUPFD: {
		DPRINTF((stderr, "%s: called: %d dup > %d\n",
			    __func__, fd, argument));

		/* 
		 * Try to find an unused descriptor that is higher
		 * than the desired.  XXX: Remove hard coded limit;
		 */
		for ( i = argument; i < 4096; i++ ) {
			/* fcntl will fail on unallocated file descriptor */
			if ((*libc_fcntl)(i, F_GETFD) == -1)
				break;
		}

		/* Out of file descriptors */
		if ( i == 4096 ) {
			errno = EMFILE;
			return (-1);
		}

		/* Duplicate the file descriptor as desired */
		return (dup2(fd, i));
	}
	case F_SETFD: {
		DPRINTF((stderr, "%s: called: %d setfd: %d\n",
			    __func__, fd, argument));
		ret = (*libc_fcntl)(fd, F_SETFD, argument);
		if (ret != -1 && nfd->their_fd != -1)
			ret = (*libc_fcntl)(nfd->their_fd, F_SETFD, argument);
		break;
	}
	default:
		DPRINTF((stderr, "%s: unknown fcntl command: %d\n",
			    __func__, cmd));
	}

	return ret;
}

int
dup(int oldfd)
{
	struct fd *nfd;
	int newfd;

	INIT;

	DPRINTF((stderr, "%s: called: %d\n", __func__, oldfd));

	/* Prevent overwriting of our control fd */

	newfd = (*libc_dup)(oldfd);

	/* Special magic needs to go here */
	if (newfd == -1)
		return (-1);

	nfd = find_fd(oldfd, 0);
	if (nfd != NULL && clone_fd(nfd, newfd) == NULL) {
		(*libc_close)(newfd);
		errno = EMFILE;
		return (-1);
	}

	return (newfd);
}

int
dup2(int oldfd, int newfd)
{
	struct fd *nfd;
	int ret;

	INIT;

	DPRINTF((stderr, "%s: called: %d -> %d\n", __func__, oldfd, newfd));

	/* Prevent overwriting of our control fd */
	if (newfd == magic_fd) {
		errno = EBADF;
		return (-1);
	}


	ret = (*libc_dup2)(oldfd, newfd);

	/* Special magic needs to go here */
	if (newfd == -1)
		return (-1);

	nfd = find_fd(oldfd, 0);
	if (nfd != NULL && clone_fd(nfd, newfd) == NULL) {
		(*libc_close)(newfd);
		errno = EMFILE;
		return (-1);
	}

	return (ret);
}

int
accept(int sock, struct sockaddr *addr, socklen_t *addrlen)
{
	struct fd *nfd;
	struct bundle bundle;
	socklen_t salen;
	int fd;

	INIT;

	nfd = find_fd(sock, FD_GETSOCKNAME);

	DPRINTF((stderr, "%s: called: %d -> %p\n", __func__, sock, nfd));

	if (nfd == NULL)
		return (*libc_accept)(sock, addr, addrlen);

	/* Get a connection from Honeyd */
	salen = sizeof(bundle);
	/* Do not intercept calls on this */
	PROTECT(nfd);
	fd = receive_fd(sock, &bundle, &salen);
	UNPROTECT(nfd);
	if (fd == -1) {
		DPRINTF((stderr, "%s: failed\n", __func__));
		return (-1);
	}

	/* XXX - something good happened! */
	DPRINTF((stderr, "%s: got %d (salen %d)\n", __func__, fd, salen));

	if (addr != NULL) {
		*addrlen = sizeof(bundle.src);
		memcpy(addr, &bundle.src, sizeof(bundle.src));
	}

	/* create a new mapping fd for the accepted connection */
	nfd = new_fd(fd);
	nfd->flags |= FD_GETSOCKNAME;

	/* Store for later */
	nfd->rsalen = sizeof(bundle.src);
	memcpy(&nfd->rsa, &bundle.src, nfd->rsalen);

	nfd->lsalen = sizeof(bundle.dst);
	memcpy(&nfd->lsa, &bundle.dst, nfd->lsalen);

	return (fd);
}

#if 0

/* We DO NOT support kqueue */

int
kqueue(void)
{
	errno = EOPNOTSUPP;
	return (-1);
}

#endif
