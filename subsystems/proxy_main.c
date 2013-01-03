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
#include <sys/stat.h>
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
#include <syslog.h>

#include <event.h>
#include <evdns.h>

#include "util.h"
#include "proxy.h"
#include "smtp.h"

/* globals */

extern FILE *flog_proxy;	/* log the proxy transactions somewhere */
extern FILE *flog_email;	/* log SMTP transactions somewhere */
extern const char *log_datadir;	/* log the email transactions somewhere */

int debug;

static void
usage(char *progname)
{
	fprintf(stderr, "%s [-p port] [-l logfile] [-L mail_logfile]\n"
	    "\t -p port    - specifies port to bind to\n"
	    "\t -l logfile - logs PROXY transaction to specified file\n"
	    "\t -L mail_logfile - logs SMTP transactions to specified file\n",
	    progname);
	exit(EXIT_SUCCESS);
}

int
main(int argc, char **argv)
{
	struct event bind_ev;
	char *progname = argv[0];
	char *logfile = NULL;
	char *mail_logfile = NULL;
	int ch;
	char *ports = NULL;
	u_short port = 2525;

	while ((ch = getopt(argc, argv, "ve:p:L:l:d:")) != -1) {
		switch (ch) {
		case 'e':
			fprintf(stderr, "Redirecting stderr to %s\n", optarg);
			if (freopen(optarg, "a", stderr) == NULL)
			{
				syslog(LOG_ERR, "%s: failed to reopen stderr", __func__);
				exit(EXIT_FAILURE);
			}
				//err(1, "%s: failed to reopen stderr",
				  //  __func__);
			setvbuf(stderr, NULL, _IOLBF, 0);
			break;
		case 'v':
			debug++;
			break;
		case 'p':
			ports = optarg;
			break;
		case 'l':
			logfile = optarg;
			break;
		case 'L':
			mail_logfile = optarg;
			break;
		case 'd': {
			if (smtp_set_datadir(optarg) == -1)
			{
				syslog(LOG_ERR, "Bad directory specification: %s", log_datadir);
				exit(EXIT_FAILURE);
			}
				//errx(1, "Bad directory specification: %s",
				  //  log_datadir);
			break;
		}
		default:
			usage(progname);
		}
	}

	if (logfile != NULL) {
		flog_proxy = fopen(logfile, "a");
		if (flog_proxy == NULL)
		{
			syslog(LOG_ERR, "%s: fopen(%s)", __func__,logfile);
			exit(EXIT_FAILURE);
		}
			//err(1, "%s: fopen(%s)", __func__, logfile);
		fprintf(stderr, "Logging to %s\n", logfile);
	}

	if (mail_logfile != NULL) {
		flog_email = fopen(mail_logfile, "a");
		if (flog_email == NULL)
		{
			syslog(LOG_ERR, "%s: fopen(%s)", __func__,mail_logfile);
			exit(EXIT_FAILURE);
		}
			//err(1, "%s: fopen(%s)", __func__, mail_logfile);
		fprintf(stderr, "Logging SMTP to %s\n", mail_logfile);
	}

	proxy_init();

	event_init();

	evdns_init();

	if (ports == NULL) {
		/* Just a single port to connect to */
		proxy_bind_socket(&bind_ev, port);
	} else {
		/* We might have multiple ports */
		char *p;
		struct event *event;

		while ((p = strsep(&ports, ",")) != NULL) {
			port = atoi(p);
			if (port == 0)
			{
				syslog(LOG_ERR, "Bad port number: %s", p);
				exit(EXIT_FAILURE);
			}
				//errx(1, "Bad port number: %s", p);
			event = malloc(sizeof(struct event));
			if (event == NULL)
			{
				syslog(LOG_ERR, "%s: malloc", __func__);
				exit(EXIT_FAILURE);
			}
				//err(1, "%s: malloc", __func__);
			proxy_bind_socket(event, port);
		}
	}
	
	event_dispatch();

	exit(0);
}
