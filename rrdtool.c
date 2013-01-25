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

#include <sys/socket.h>
#include <sys/queue.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <assert.h>
#include <syslog.h>

#include <event.h>
#include <dnet.h>

#include "rrdtool.h"

extern rand_t *honeyd_rand;


static void rrdtool_restart(int, short, void *);
static void rrdtool_write_command(struct rrdtool_drv *, char *);

/*
 * Very simple RRDTOOL driver
 */

void
rrdtool_evb_readcb(struct bufferevent *bev, void *parameter)
{
	struct rrdtool_drv *req = parameter;

	char *start, *end;
	struct evbuffer_ptr offset;

	start = (char*)evbuffer_pullup(bev->input, -1);

	offset = evbuffer_search(bev->input, "OK ", 3, NULL);
	if(offset.pos == -1)
		return;
	
	end = start + offset.pos;

	/* Find the end of the line */
	if(strchr(end, '\n') == NULL)
		return;

	/* Communicate everything before the OK to the call back */
	*end = '\0';

	rrdtool_command_done(req, start);
	
	/* 
	 * We drain all the input because we do not currently interleave
	 * commands.
	 */
	evbuffer_drain(bev->input, -1);

	return;
}

void
rrdtool_evb_writecb(struct bufferevent *bev, void *parameter)
{
	/* We wrote all of the command - now read the response */
	bufferevent_enable(bev, EV_READ);
}

/*
 * We start this timeout if we spam the rrdtool too fast.
 */

static void
rrdtool_restart(int fd, short what, void *arg)
{
	struct rrdtool_drv *drv = arg;
	struct timeval tv;

	/* Terminate the bugger */
	if (drv->fd != -1) {
		close(drv->fd);
		drv->fd = -1;
	}
	if (drv->pid != 0) {
		kill(drv->pid, SIGTERM);
		drv->pid = 0;
	}

	/* If we respawn too quickly, we need to wait a little whilte */
	gettimeofday(&tv, NULL);
	timersub(&tv, &drv->tv_started, &tv);
	if (tv.tv_sec < 5) {
		syslog(LOG_NOTICE, "Respawing rrdtool too quickly");
		tv.tv_sec = 5;
		tv.tv_usec = 0;
		evtimer_add(drv->ev_timeout, &tv);
		return;
	}

	/* Bad hack - we need to disable all events */
	bufferevent_disable(drv->evb, EV_READ|EV_WRITE);

	if (rrdtool_fork(drv) == -1) {
		syslog(LOG_WARNING, "Terminating rrdtool driver.");
		rrdtool_free(drv);
	} else {
		struct rrdtool_command *cmd = TAILQ_FIRST(&drv->commands);

		/* This is yet another bad hack */
		drv->evb->ev_read.ev_fd = drv->fd;
		drv->evb->ev_write.ev_fd = drv->fd;
		bufferevent_enable(drv->evb, EV_WRITE);

		/* Restart the last command */
		if (cmd != NULL)
			rrdtool_write_command(drv, cmd->command);
	}
}

void
rrdtool_evb_errcb(struct bufferevent *bev, short what, void *parameter)
{
	struct rrdtool_drv *drv = parameter;

	syslog(LOG_NOTICE, "rrdtool returning errors - restarting.");
	rrdtool_restart(-1, EV_TIMEOUT, drv);
}

/*
 * Creates a new rrdtool process
 */

struct rrdtool_drv *
rrdtool_init(const char *path_rrdtool)
{
	struct rrdtool_drv *rrd;

	if ((rrd = calloc(1, sizeof(struct rrdtool_drv))) == NULL) {
		warn("%s: calloc", __func__);
		goto error;
	}

	/* Remember the path so that we can respawn */
	rrd->bin_path = path_rrdtool;

	if (rrdtool_fork(rrd) == -1) {
		goto error;
	}

	rrdtool_libevent_base = event_base_new();

	if((rrd->evb = bufferevent_socket_new(rrdtool_libevent_base, rrd->fd, BEV_OPT_CLOSE_ON_FREE)) == NULL)
		goto error;

	bufferevent_setcb(rrd->evb, rrdtool_evb_readcb, rrdtool_evb_writecb, rrdtool_evb_errcb, rrd);

	TAILQ_INIT(&rrd->commands);

	bufferevent_disable(rrd->evb, EV_READ);
	bufferevent_enable(rrd->evb, EV_WRITE);

	rrd->ev_timeout = evtimer_new(rrdtool_libevent_base, rrdtool_restart, rrd);

	return rrd;

 error:
	if (rrd != NULL) {
		if (rrd->fd != -1)
			close(rrd->fd);
		free(rrd);
	}

	return (NULL);
}

/*
 * Frees a rrdtool driver structure
 */

void
rrdtool_free(struct rrdtool_drv *drv)
{
	event_del(drv->ev_timeout);

	bufferevent_free(drv->evb);

	if (drv->fd != -1) {
		close(drv->fd);
		drv->fd = -1;
	}
	if (drv->pid != 0) {
		kill(drv->pid, SIGTERM);
		drv->pid = 0;
	}

	free(drv);
}

void
rrdtool_db_free(struct rrdtool_db *db)
{
	int i;

	for (i = 0; i < db->ndatasrcs; i++)
		free(db->datasrcs[i]);

	free(db);
}


/* Write a single command to rrdtool */

static void
rrdtool_write_command(struct rrdtool_drv *drv, char *command)
{
	bufferevent_write(drv->evb, command, strlen(command));
	if (command[strlen(command) - 1] != '\n')
		bufferevent_write(drv->evb, "\n", 1);
}

void
rrdtool_command_done(struct rrdtool_drv *drv, char *result)
{
	struct rrdtool_command *cmd = TAILQ_FIRST(&drv->commands);

	assert(cmd != NULL);
	
	TAILQ_REMOVE(&drv->commands, cmd, next);

	if (cmd->cb != NULL)
		(*cmd->cb)(result, cmd->cb_arg);

	free(cmd->command);
	free(cmd);

	bufferevent_disable(drv->evb, EV_READ);

	if ((cmd = TAILQ_FIRST(&drv->commands)) != NULL) {
		rrdtool_write_command(drv, cmd->command);
	}
}

void
rrdtool_command(struct rrdtool_drv *drv, char *command,
    void (*cb)(char *, void *), void *cb_arg)
{
	struct rrdtool_command *cmd;

	if ((cmd = calloc(1, sizeof(struct rrdtool_command))) == NULL)
	{
		syslog(LOG_ERR, "%s: calloc", __func__);
		exit(EXIT_FAILURE);
	}
	
	if ((cmd->command = strdup(command)) == NULL)
	{
		syslog(LOG_ERR, "%s: strdup", __func__);
		exit(EXIT_FAILURE);
	}

	cmd->cb = cb;
	cmd->cb_arg = cb_arg;

	if (TAILQ_FIRST(&drv->commands) == NULL)
		rrdtool_write_command(drv, command);

	TAILQ_INSERT_TAIL(&drv->commands, cmd, next);
}

/*
 * Create a new data base.
 */

struct rrdtool_db *
rrdtool_db_start(struct rrdtool_drv *drv, char *filename, int stepsize)
{
	struct rrdtool_db *db;

	if ((db = calloc(1, sizeof(struct rrdtool_db))) == NULL)
	{
		syslog(LOG_ERR, "%s: calloc", __func__);
		exit(EXIT_FAILURE);
	}

	db->drv = drv;

	strlcpy(db->rrd_file, filename, sizeof(db->rrd_file));

	snprintf(db->create_command, sizeof(db->create_command),
	    "create %s --step %d", filename, stepsize);

	return (db);
}

int
rrdtool_db_datasource(struct rrdtool_db *db, char *name, char *type,
    int heartbeat)
{
	char line[1024];

	if (db->ndatasrcs >= MAX_RRD_DATASRCS) {
		warnx("%s: too many data sources", __func__);
		return (-1);
	}

	if (strcasecmp(type, "COUNTER") && strcasecmp(type, "GAUGE")) {
		warnx("%s: bad data source type: %s", __func__, type);
		return (-1);
	}

	snprintf(line, sizeof(line), "DS:%s:%s:%d:U:U",
	    name, type, heartbeat);
	if ((db->datasrcs[db->ndatasrcs++] = strdup(line)) == NULL)
	{
		syslog(LOG_ERR, "%s: strdup",__func__);
		exit(EXIT_FAILURE);
	}

	strlcat(db->create_command, " ", sizeof(db->create_command));
	if ( strlcat(db->create_command, line, sizeof(db->create_command)) >=
	    sizeof(db->create_command)) {
		warnx("%s: command too long", __func__);
		return (-1);
	}

	return (0);
}

static void
rrdtool_db_commit_cb(char *result, void *arg)
{
	struct rrdtool_db *db = arg;

	if (strlen(result) && strncasecmp(result, "ERROR", 5) == 0) {
		result[strlen(result) - 1] = '\0';
		syslog(LOG_NOTICE, "rrdtool create of %s: %s",
		    db->rrd_file, result);
	}
}

int
rrdtool_db_commit(struct rrdtool_db *db)
{
	if (strlcat(db->create_command, " "
		"RRA:AVERAGE:0.5:1:600 "
		"RRA:AVERAGE:0.5:6:700 "
		"RRA:AVERAGE:0.5:24:775 "
		"RRA:AVERAGE:0.5:288:797 "
		"RRA:MAX:0.5:1:600 "
		"RRA:MAX:0.5:6:700 "
		"RRA:MAX:0.5:24:775 "
		"RRA:MAX:0.5:288:797", sizeof(db->create_command)) >=
	    sizeof(db->create_command)) {
		warnx("%s: command too long", __func__);
		return (-1);
	}

	/* Don't clobber the database if we do not have to */
	if (access(db->rrd_file, W_OK) == -1) {
		rrdtool_command(db->drv, db->create_command,
		    rrdtool_db_commit_cb, db);
	}

	return (0);
}

/*
 * Takes a line of descriptions and updates the database.
 */

int
rrdtool_db_update(struct rrdtool_db *db, struct timeval *tv, char *update)
{
	char line[1024];
	struct timeval tv_now;

	if (tv == NULL) {
		gettimeofday(&tv_now, NULL);
		tv = &tv_now;
	}

	snprintf(line, sizeof(line), "update %s %ld:%s",
	    db->rrd_file, tv->tv_sec, update);

	rrdtool_command(db->drv, line, NULL, NULL);

	return (0);
}

/*
 * Create a graph for the specified location
 */

void
rrdtool_graph(struct rrdtool_db *db, char *filename,
    struct timeval *tv_start, struct timeval *tv_end,
    char *spec)
{
	char line[1024];
	struct timeval tv;

	gettimeofday(&tv, NULL);
	if (tv_start == NULL)
		tv_start = &tv;
	else if (tv_start->tv_sec < 0) {
		/* Negative start time is subtracted from current time */
		timeradd(tv_start, &tv, tv_start);
	}
	if (tv_end == NULL)
		tv_end = &tv;
	    
	snprintf(line, sizeof(line), "graph %s --start %ld --end %ld %s",
	    filename, tv_start->tv_sec, tv_end->tv_sec, spec);

	rrdtool_command(db->drv, line, NULL, NULL);
}

int
rrdtool_fork(struct rrdtool_drv *drv)
{
	const char *argv[3];
	int pair[2];
	sigset_t sigmask;

	argv[0] = drv->bin_path;
	argv[1] = "-";
	argv[2] = NULL;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1)
		return (-1);

	/* Block SIGCHLD */
	sigemptyset(&sigmask);
	sigaddset(&sigmask, SIGCHLD);
	if (sigprocmask(SIG_BLOCK, &sigmask, NULL) == -1) {
		warn("sigprocmask");
		goto fork_err;
	}

	/*
	 * Record the time that we tried to fork, so that we can see
	 * if we get too many errors.
	 */
	gettimeofday(&drv->tv_started, NULL);

	drv->pid = fork();
	if (drv->pid == -1) {
		warn("fork");
		goto unmask_err;
	}

	if (drv->pid == 0) {
		/* Child */
		close(pair[0]);
		if (dup2(pair[1], fileno(stdout)) == -1)
		{
			syslog(LOG_ERR, "%s: dup2", __func__);
			exit(EXIT_FAILURE);
		}
		if (dup2(pair[1], fileno(stdin)) == -1)
		{
			syslog(LOG_ERR, "%s: dup2", __func__);
			exit(EXIT_FAILURE);
		}

		close(pair[1]);

		if (execvp(drv->bin_path, (char * const*)argv) == -1)
		{
			syslog(LOG_ERR, "%s: execv(%s)", __func__, drv->bin_path);
			exit(EXIT_FAILURE);
		}

		/* NOT REACHED */
	}

	close(pair[1]);
	drv->fd = pair[0];
	if (fcntl(drv->fd, F_SETFD, 1) == -1)
		warn("fcntl(F_SETFD)");
	if (fcntl(drv->fd, F_SETFL, O_NONBLOCK) == -1)
		warn("fcntl(F_SETFL)");

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
	close(pair[0]);
	close(pair[1]);
	drv->fd = -1;

	return (-1);
}

/*
 * -----------
 * Unittesting 
 * -----------
 */

void
rrdtool_test_done(char *something, void *arg)
{
	struct timeval tv;

	timerclear(&tv);
	tv.tv_sec = 1;
	event_base_loopexit(rrdtool_libevent_base, &tv);
}

void
rrdtool_test(void)
{
	extern char *honeyd_rrdtool_path;
	struct rrdtool_drv *drv;
	struct rrdtool_db *db;
 	struct timeval tv, tv_now;
	char line[1024];
	int i, in = 0, out = 0;

	drv = rrdtool_init(honeyd_rrdtool_path);
	assert(drv != NULL);

	db = rrdtool_db_start(drv, "/tmp/myrouter.rrd", 300);
	assert(db != NULL);

	rrdtool_db_datasource(db, "input", "COUNTER", 600);
	rrdtool_db_datasource(db, "output", "COUNTER", 600);

	rrdtool_db_commit(db);

	gettimeofday(&tv, NULL);
	tv_now = tv;
	for (i = 0; i < 500; i++) {
		tv.tv_sec += 60;

		in += (i*5) % 500;
		out += i % 400 + rand_uint16(honeyd_rand) % 1000;

		snprintf(line, sizeof(line), "%u:%u", in, out);
		rrdtool_db_update(db, &tv, line);
	}

	unlink("/tmp/honeyd_myrouter.gif");
	snprintf(line, sizeof(line),
	    "graph /tmp/honeyd_myrouter.gif --start %ld --end %ld "
	    "--height 300 --width 600 "
	    "DEF:inoctets=/tmp/myrouter.rrd:input:AVERAGE "
	    "DEF:outoctets=/tmp/myrouter.rrd:output:AVERAGE "
	    "CDEF:mout=outoctets,-1,* "
	    "AREA:inoctets#00FF00:\"In traffic\" "
	    "AREA:mout#0000FF:\"Out traffic\"",
	    tv_now.tv_sec, tv.tv_sec);
	rrdtool_command(drv, line, rrdtool_test_done, NULL);

	event_base_dispatch(rrdtool_libevent_base);

	if (access("/tmp/honeyd_myrouter.gif", R_OK) == -1)
	{
		syslog(LOG_ERR, "%s: graph creation failed", __func__);
		exit(EXIT_FAILURE);
	}

	rrdtool_free(drv);
	fprintf(stderr, "\t%s: OK\n", __func__);
}

