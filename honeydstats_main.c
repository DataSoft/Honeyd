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

#include <sys/param.h>
#include <sys/types.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_SYS_IOCCOM_H
#include <sys/ioccom.h>
#endif
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/tree.h>
#include <sys/wait.h>
#include <sys/queue.h>

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <signal.h>
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#include <fcntl.h>
#include <unistd.h>
#include <getopt.h>
#include <dnet.h>

#undef timeout_pending
#undef timeout_initialized

#include <event.h>

#include "honeyd.h"
#include "tagging.h"
#include "untagging.h"
#include "stats.h"
#include "histogram.h"
#include "honeydstats.h"
#include "analyze.h"
#include "keycount.h"

/* Prototypes */
int
make_socket(int (*f)(int, const struct sockaddr *, socklen_t), int type,
    char *address, uint16_t port);

extern int checkpoint_fd;
extern struct evbuffer *checkpoint_evbuf;
extern struct usertree users;

static int fd_recv;
static struct evbuffer *evbuf_recv;
static char *checkpoint_filename = NULL;
static char *config_filename = "honeydstats.config";

static void
read_cb(int fd, short what, void *unused)
{
	static u_char buf[4096];
	struct addr src;
	struct sockaddr_storage from;
	socklen_t fromsz = sizeof(from);
	int nread;

	/* Reschedule the event */
	struct event *ev_recv = event_new(stats_libevent_base, fd_recv, EV_READ, read_cb, NULL);
	event_add(ev_recv, NULL);

	nread = recvfrom(fd, buf, sizeof(buf), MSG_WAITALL,
	    (struct sockaddr *)&from, &fromsz);
	if (nread == -1) {
		warn("%s: recvfrom", __func__);
		return;
	}

	addr_ston((struct sockaddr *)&from, &src);

	syslog(LOG_INFO, "Received report from %s: %d",
	    addr_ntoa(&src), nread);

	evbuffer_drain(evbuf_recv, evbuffer_get_length(evbuf_recv));
	evbuffer_add(evbuf_recv, buf, nread);

	signature_process(evbuf_recv);
}

struct _unittest {
	char *name;
	void (*cb)(void);
} unittests[] = {
	{ "histogram", histogram_test },
	{ "stats", stats_test },
	{ "analyze", analyze_test },
	{ NULL, NULL}
};

void
unittest(void)
{
	struct _unittest *ut;
	fprintf(stderr, "Running unittests ...\n");
	for (ut = unittests; ut->name != NULL; ut++) {
		fprintf(stderr, " ---- %s TEST ---- \n", ut->name);
		(*ut->cb)();
		fprintf(stderr, " ---- %s OK ---- \n", ut->name);
	}
	fprintf(stderr, "All unitests are OK\n");
	exit(0);
}

void
usage(void)
{
	fprintf(stderr,
	    "Usage: honeydstats [OPTIONS]\n\n"
	    "where options include:\n"
	    "  --os_report <filename>      Report os versions to this file.\n"
	    "  --port_report <filename>    Report port distribution to file.\n"
	    "  --spammer_report <filename> Report spammer IPs to this file.\n"
	    "  --country_report <filename> Report country codes to this file.\n"
	    "  -V, --version               Print program version and exit.\n"
	    "  -h, --help                  Print this message and exit.\n"
	    "  -l <address>                Address to bind listen socket to.\n"
	    "  -p <port>                   Port number to bind to.\n"
	    "  -f <config>                 Name of configuration file.\n"
	    "  -c <checkpoint>             Name of checkpointing file.\n"
	    );

	    
	exit(1);
}

void
setup_socket(char *address, int port)
{
	if ((evbuf_recv = evbuffer_new()) == NULL){
		syslog(LOG_ERR, "%s: evbuffer_new", __func__);
		exit(EXIT_FAILURE);
	}

	if ((fd_recv = make_socket(bind, SOCK_DGRAM, address, port)) == -1){
		syslog(LOG_ERR, "%s: make_socket", __func__);
		exit(EXIT_FAILURE);
	}

	syslog(LOG_NOTICE, "Listening on %s:%d", address, port);

	struct event *ev_recv = event_new(stats_libevent_base, fd_recv, EV_READ, read_cb, NULL);
	event_add(ev_recv, NULL);
}

void
honeydstats_signal(int fd, short what, void *arg)
{
	syslog(LOG_NOTICE, "exiting on signal %d", fd);
	exit(EXIT_SUCCESS);
}

void
honeydstats_sighup(int fd, short what, void *arg)
{
	syslog(LOG_NOTICE,
	    "rereading configuration/rotating files on signal %d", fd);

	if (config_filename != NULL)
		user_read_config(config_filename);

	if (checkpoint_fd != -1) {
		close(checkpoint_fd);
		checkpoint_fd = open(checkpoint_filename,
		    O_CREAT|O_WRONLY|O_APPEND, S_IRUSR|S_IWUSR|S_IRGRP);
	}
}

int
main(int argc, char *argv[])
{
	static int show_version = 0;
	static int show_usage = 0;
	static int report_os = 0;
	static int report_port = 0;
	static int report_spammer = 0;
	static int report_country = 0;
	static struct option stats_long_opts[] = {
		{"version",     0, &show_version, 1},
		{"help",        0, &show_usage, 1},
		{"os_report",   required_argument, &report_os, 1},
		{"port_report",   required_argument, &report_port, 1},
		{"spammer_report", required_argument, &report_spammer, 1},
		{"country_report", required_argument, &report_country, 1},
		{0, 0, 0, 0}
	};
	char *replay_filename = NULL;
	char *address = "0.0.0.0";
	char **orig_argv;
	int orig_argc;
	int debug = 0;
	int want_unittest = 0;
	u_short port = 9000;
	int c;

	orig_argc = argc;
	orig_argv = argv;

	fprintf(stderr,
	    "HoneydStats Collector V%s Copyright (c) 2004 Niels Provos\n",
	    VERSION);

	while ((c = getopt_long(argc, argv, "TVdc:r:l:p:f:h?",
				stats_long_opts, NULL)) != -1) {
		switch (c) {
		case 'V':
			show_version = 1;
			break;
		case 'T':
			debug = 1;
			want_unittest = 1;
			break;
		case 'd':
			debug = 1;
			break;
		case 'f':
			config_filename = optarg;
			break;
		case 'c':
			checkpoint_filename = optarg;
			break;
		case 'r':
			replay_filename = optarg;
			break;
		case 'l':
			address = optarg;
			break;
		case 'p':
			if ((port = atoi(optarg)) == 0) {
				syslog(LOG_ERR, "Bad port number: %s\n",optarg);
				fprintf(stderr, "Bad port number: %s\n",
				    optarg);
				usage();
			}
			break;
		case 0:
			/* long option handled */
			if (report_os) {
				extern char *os_report_file;
				os_report_file = optarg;
				report_os = 0;
			}

			if (report_port) {
				extern char *port_report_file;
				port_report_file = optarg;
				report_port = 0;
			}

			if (report_spammer) {
				extern char *spammer_report_file;
				spammer_report_file = optarg;
				report_spammer = 0;
			}
			if (report_country) {
				extern char *country_report_file;
				country_report_file = optarg;
				report_country = 0;
			}
			break;
		default:
			usage();
			break;
		}
	}

	if (show_version)
		exit(0);

	if (show_usage) {
		usage();
		/* not reached */
	}

	SPLAY_INIT(&users);

	if (user_read_config(config_filename) == -1) {
		if (!want_unittest)
			errx(1, "config file '%s' not found", config_filename);
		else
			warnx("config file '%s' not found", config_filename);
	}

	syslog_init(orig_argc, orig_argv);

	/* Start the stats daemon in the background if necessary */
	if (!debug) {
		setlogmask(LOG_UPTO(LOG_INFO));
		
		fprintf(stderr, "Starting as background process\n");
		if (daemon(1, 0) < 0)
		{
			syslog(LOG_ERR, "daemon");
			exit(EXIT_FAILURE);
		}
			//err(1, "daemon");
	}

	stats_libevent_base = event_base_new();

	count_init();

	analyze_init();
	timeseries_init();

	if (want_unittest)
		unittest();

	if (replay_filename != NULL) {
		char *p;
		int fd;

		while ((p = strsep(&replay_filename, ",")) != NULL) {
			if ((fd = open(p, O_RDONLY, 0)) == -1)
			{
				syslog(LOG_ERR, "%s: open(%s)", __func__,p);
				exit(EXIT_FAILURE);
			}
			checkpoint_replay(fd);
		}
	}

	if (checkpoint_filename != NULL) {
		int fd;

		/*
		 * First check if we can use the file name to replay
		 * log information.
		 */

		fd = open(checkpoint_filename, O_RDONLY, 0);
		if (fd != -1)
			checkpoint_replay(fd);

		/*
		 * Open file descriptor into which we log information for
		 * replay.
		 */
		checkpoint_fd = open(checkpoint_filename,
		    O_CREAT|O_WRONLY|O_APPEND, S_IRUSR|S_IWUSR|S_IRGRP);
		checkpoint_evbuf = evbuffer_new();
	}

	setup_socket(address, port);

	struct event *sigterm_ev, *sigint_ev, *sighup_ev;

	sigterm_ev = evsignal_new(stats_libevent_base, SIGTERM, honeydstats_signal, NULL);
	sigint_ev = evsignal_new(stats_libevent_base, SIGINT, honeydstats_signal, NULL);
	sighup_ev = evsignal_new(stats_libevent_base, SIGHUP, honeydstats_sighup, NULL);

	event_add(sigterm_ev, NULL);
	event_add(sigint_ev, NULL);
	event_add(sighup_ev, NULL);

	event_base_dispatch(stats_libevent_base);

	syslog(LOG_ERR, "Kqueue does not recognize bpf filedescriptor.");

	return (0);
}

void
syslog_init(int argc, char *argv[])
{
	int options, i;
	char buf[MAXPATHLEN];

#ifdef LOG_PERROR
	options = LOG_PERROR|LOG_PID|LOG_CONS;
#else
	options = LOG_PID|LOG_CONS;
#endif
	openlog("honeydstats", options, LOG_DAEMON);	

	/* Create a string containing all the command line
	 * arguments and pass it to syslog:
	 */

	buf[0] = '\0';
	for (i = 1; i < argc; i++) {
		if (i > 1 && strlcat(buf, " ", sizeof(buf)) >= sizeof(buf))
			break;
		if (strlcat(buf, argv[i], sizeof(buf)) >= sizeof(buf))
			break;
	}

	syslog(LOG_NOTICE, "started with %s", buf);
}
