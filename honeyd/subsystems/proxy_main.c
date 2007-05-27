/*
 * Copyright (c) 2005 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 *
 * <LICENSEHERE>
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
	exit(1);
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
				err(1, "%s: failed to reopen stderr", 
				    __func__);
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
				errx(1, "Bad directory specification: %s", 
				    log_datadir);
			break;
		}
		default:
			usage(progname);
		}
	}

	if (logfile != NULL) {
		flog_proxy = fopen(logfile, "a");
		if (flog_proxy == NULL)
			err(1, "%s: fopen(%s)", __func__, logfile);
		fprintf(stderr, "Logging to %s\n", logfile);
	}

	if (mail_logfile != NULL) {
		flog_email = fopen(mail_logfile, "a");
		if (flog_email == NULL)
			err(1, "%s: fopen(%s)", __func__, mail_logfile);
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
				errx(1, "Bad port number: %s", p);
			event = malloc(sizeof(struct event));
			if (event == NULL)
				err(1, "%s: malloc", __func__);
			proxy_bind_socket(event, port);
		}
	}
	
	event_dispatch();

	exit(0);
}
